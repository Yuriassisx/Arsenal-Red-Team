"""
core/http_client.py
===================

Cliente HTTP assíncrono (httpx) com:
  - controle de concorrência (semáforo)
  - rate limiting (req/s)
  - retries com backoff
  - medição de tempo de resposta (para detecção time-based)
  - suporte a proxy (Burp/mitmproxy), TLS relaxado, headers/cookies default
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .target import PreparedRequest

# pool de User-Agents para rotação no modo stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Mobile Safari/537.36",
]


# ---- descrições p/ o verbose detalhado (propósito e encoder) ----
_PURPOSE = {
    "lfi": "LFI/path-traversal", "sqli": "SQL-injection", "cmdi": "OS-command-injection",
    "ssrf": "SSRF", "xss": "XSS-refletido", "ssti": "template-injection(SSTI)",
    "open_redirect": "open-redirect", "crlf": "CRLF/header-injection",
    "nosqli": "NoSQL-injection", "ldap": "LDAP-injection", "xpath": "XPath-injection",
    "deserial": "desserialização", "host_header": "host-header-injection",
    "xxe": "XXE", "mass_assignment": "mass-assignment", "cache_poison": "cache-poisoning",
    "idor": "IDOR", "jwt": "JWT", "waf": "sonda-WAF",
}


def purpose_of(module: str) -> str:
    return _PURPOSE.get(module, module or "?")


_ENC = {
    "raw": "sem encode", "url": "percent-encode", "url_all": "percent em TODO byte",
    "url_double": "duplo percent", "url_triple": "triplo percent",
    "url_plus": "espaço→+", "url_hex_mixed": "hex caixa mista (%2f/%2F)",
    "url_all_lower": "percent minúsculo", "double_url_all": "duplo percent total",
    "triple_url_all": "triplo percent total", "unicode_iis": "%uXXXX (IIS)",
    "utf8_overlong": "UTF-8 overlong 2B", "utf8_overlong3": "UTF-8 overlong 3B",
    "fullwidth": "fullwidth Unicode", "best_fit": "best-fit homoglyph",
    "unicode_escape": "\\uXXXX", "case_upper": "MAIÚSCULAS", "case_lower": "minúsculas",
    "case_swap": "troca de caixa", "case_random": "caixa aleatória",
    "backslash": "barra invertida", "double_slash": "barra dupla",
    "mixed_slash": "barra mista", "slash_variants": "variações de barra",
    "dot_variants": "variações de ponto", "null_multi": "null byte (6 formas)",
    "ifs": "${IFS}/espaço alt", "space_variants": "espaços alternativos",
    "cmd_quote": "quote quebrando keyword", "cmd_glob": "globbing (/???/c?t)",
    "sql_comment_between": "comentário /**/ entre chars",
    "sql_comment_ws": "comentário como espaço", "sql_inline_case": "caixa inline SQL",
    "html_dec": "HTML decimal", "html_hex": "HTML hex", "html_entities": "HTML entities",
    "poly_percent": "polimórfico percent", "poly_case": "polimórfico caixa",
    "poly_ws": "polimórfico espaço", "poly_sql_noise": "ruído SQL polimórfico",
    "poly_mix": "polimórfico misto",
}


def encoder_desc(label: str) -> str:
    """Descreve o encoder (ou encadeamento 'a+b') em linguagem humana."""
    if not label or label == "raw":
        return "sem encode"
    parts = label.split("|")[0].split("+")   # ignora sufixo de modo (|hpp)
    return " + ".join(_ENC.get(p, p) for p in parts)


@dataclass
class Response:
    status: int
    headers: dict
    text: str
    elapsed: float          # segundos
    url: str
    error: Optional[str] = None
    length: int = 0
    truncated: bool = False  # corpo cortado no teto de tamanho (max_response_bytes)

    @property
    def ok(self) -> bool:
        return self.error is None


class HttpClient:
    def __init__(
        self,
        concurrency: int = 20,
        rate: float = 0.0,            # req/s (0 = ilimitado)
        timeout: float = 15.0,
        retries: int = 2,
        proxy: Optional[str] = None,
        verify_tls: bool = False,
        follow_redirects: bool = False,
        default_headers: Optional[dict] = None,
        user_agent: str = "ParamHunter/1.0 (+security-testing)",
        stealth: bool = False,
        jitter: float = 0.0,
        max_response_bytes: int = 2_000_000,   # teto do corpo lido (0 = ilimitado)
        http2: bool = False,
        retry_after_cap: float = 60.0,         # teto p/ respeitar Retry-After (s)
        verbose: int = 0,                      # 0=off, 1=req+status, 2=+corpo/tempo/payload
        logfn=None,                            # callable(str) p/ imprimir no verbose
    ):
        self.verbose = verbose
        self._logfn = logfn
        self.max_response_bytes = max(0, max_response_bytes)
        self.sem = asyncio.Semaphore(concurrency)
        self.rate = rate
        self._min_interval = (1.0 / rate) if rate > 0 else 0.0
        self._base_interval = self._min_interval
        self._last = 0.0
        self._pause_until = 0.0                # pausa global honrando Retry-After
        self._retry_after_cap = max(0.0, retry_after_cap)
        self._lock = asyncio.Lock()
        self.stealth = stealth
        self.jitter = jitter
        self._max_interval = 8.0
        self._ok_streak = 0
        self.retries = retries
        self.default_headers = {"User-Agent": user_agent}
        if default_headers:
            self.default_headers.update(default_headers)

        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        try:
            self._client = httpx.AsyncClient(
                timeout=timeout, verify=verify_tls, follow_redirects=follow_redirects,
                proxy=proxy, limits=limits, trust_env=False, http2=http2,
            )
        except ImportError:
            # http2=True sem o pacote 'h2' instalado -> cai p/ HTTP/1.1
            self._client = httpx.AsyncClient(
                timeout=timeout, verify=verify_tls, follow_redirects=follow_redirects,
                proxy=proxy, limits=limits, trust_env=False,
            )
        self.sent = 0

    @staticmethod
    def _parse_retry_after(val: str) -> float:
        """Retry-After: segundos (int) ou data HTTP. Retorna segundos (>=0)."""
        val = (val or "").strip()
        if not val:
            return 0.0
        if val.isdigit():
            return float(val)
        try:
            from email.utils import parsedate_to_datetime
            import datetime
            dt = parsedate_to_datetime(val)
            if dt is not None:
                now = datetime.datetime.now(dt.tzinfo)
                return max(0.0, (dt - now).total_seconds())
        except (TypeError, ValueError):
            pass
        return 0.0

    def _vlog(self, req, resp) -> None:
        """Loga uma requisição no modo verbose (cada payload enviado)."""
        if not self._logfn:
            return
        st = str(resp.status) if resp.ok else "ERR"
        line = f"{st:>3} {req.method:<4} {req.url[:130]}"
        if self.verbose >= 2:
            if resp.ok:
                line += f"  [{resp.length}B {resp.elapsed:.2f}s]"
                if getattr(resp, "truncated", False):
                    line += " (cortado)"
            else:
                line += f"  [{(resp.error or '')[:50]}]"
            # PROPÓSITO (módulo) + ENCODER (transform) + tags + payload cru
            mod = getattr(req, "module", "") or ""
            pt = str(getattr(req, "point", "") or "")
            label = getattr(req, "label", "") or ""
            tags = [t for t in (getattr(req, "tags", []) or []) if t]
            meta = []
            if mod:
                meta.append(purpose_of(mod))
            if pt:
                meta.append(f"@{pt}")
            if label and label != "raw":
                meta.append(f"enc:{label}→{encoder_desc(label)}")
            elif label == "raw":
                meta.append("enc:cru")
            if tags:
                meta.append("#" + ",".join(tags[:4]))
            if meta:
                line += "  " + "  ".join(meta)
            inj = getattr(req, "injected", "") or ""
            if inj:
                line += f"\n            payload: {inj[:120]!r}"
        self._logfn(line)

    def _note_retry_after(self, status: int, headers) -> None:
        """Em 429/503 com Retry-After, aplica uma PAUSA GLOBAL (limitada)."""
        if status not in (429, 503):
            return
        ra = headers.get("retry-after")
        if not ra:
            return
        delay = min(self._parse_retry_after(ra), self._retry_after_cap)
        if delay > 0:
            self._pause_until = max(self._pause_until, time.monotonic() + delay)

    async def _throttle(self):
        jit = random.uniform(0, self.jitter) if (self.stealth and self.jitter) else 0.0
        if self._min_interval <= 0 and jit <= 0 and self._pause_until <= time.monotonic():
            return
        async with self._lock:
            now = time.monotonic()
            wait = (self._min_interval - (now - self._last) + jit) if self._min_interval > 0 else jit
            if self._pause_until > now:                # honra Retry-After do servidor
                wait = max(wait, self._pause_until - now)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    def note_block(self):
        """Sinal de bloqueio: no modo stealth, desacelera (backoff exponencial)."""
        if not self.stealth:
            return
        self._ok_streak = 0
        base = self._min_interval if self._min_interval > 0 else 0.2
        self._min_interval = min(self._max_interval, base * 1.7 + 0.15)

    def note_ok(self):
        """Resposta limpa: no modo stealth, recupera a vazão gradualmente."""
        if not self.stealth or self._min_interval <= self._base_interval:
            return
        self._ok_streak += 1
        if self._ok_streak >= 12:      # recupera devagar após uma sequência limpa
            self._ok_streak = 0
            self._min_interval = max(self._base_interval, self._min_interval * 0.85 - 0.05)

    @property
    def current_delay(self) -> float:
        return self._min_interval

    async def send(self, req: PreparedRequest) -> Response:
        headers = dict(self.default_headers)
        headers.update(req.headers or {})
        # rotação de User-Agent no modo stealth (se o caller não fixou um)
        if self.stealth and "User-Agent" not in (req.headers or {}):
            headers["User-Agent"] = random.choice(USER_AGENTS)
        last_err = None

        async with self.sem:
            for attempt in range(self.retries + 1):
                await self._throttle()
                start = time.monotonic()
                try:
                    # streaming p/ CORTAR corpos gigantes: um fuzzer que bate em
                    # endpoints de download baixaria MBs por requisição — cap protege
                    # memória e acelera similaridade/regex (detecção olha só o topo).
                    cap = self.max_response_bytes
                    async with self._client.stream(
                        req.method,
                        req.url,
                        headers=headers,
                        cookies=req.cookies or None,
                        data=req.data,
                        json=req.json_body,
                    ) as r:
                        buf = bytearray()
                        truncated = False
                        async for chunk in r.aiter_bytes():
                            buf += chunk
                            if cap and len(buf) >= cap:
                                truncated = True
                                del buf[cap:]
                                break
                        elapsed = time.monotonic() - start
                        try:
                            text = buf.decode(r.encoding or "utf-8", errors="replace")
                        except (LookupError, TypeError):
                            text = buf.decode("utf-8", errors="replace")
                    self.sent += 1
                    self._note_retry_after(r.status_code, r.headers)
                    resp = Response(
                        status=r.status_code,
                        headers=dict(r.headers),
                        text=text,
                        elapsed=elapsed,
                        url=str(r.url),
                        length=len(text),
                        truncated=truncated,
                    )
                    if self.verbose:
                        self._vlog(req, resp)
                    return resp
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    # timeout ainda importa para time-based; devolve elapsed
                    elapsed = time.monotonic() - start
                    if attempt >= self.retries:
                        resp = Response(
                            status=0, headers={}, text="", elapsed=elapsed,
                            url=req.url, error=last_err,
                        )
                        if self.verbose:
                            self._vlog(req, resp)
                        return resp
                    await asyncio.sleep(0.3 * (attempt + 1))
                except Exception as e:  # noqa: BLE001
                    resp = Response(status=0, headers={}, text="", elapsed=0.0,
                                    url=req.url, error=f"{type(e).__name__}: {e}")
                    if self.verbose:
                        self._vlog(req, resp)
                    return resp
        return Response(status=0, headers={}, text="", elapsed=0.0,
                        url=req.url, error=last_err or "unknown")

    async def aclose(self):
        await self._client.aclose()
