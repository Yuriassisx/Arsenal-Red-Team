"""
core/detector.py
================

Motor de detecção. Cada estratégia analisa a resposta a um payload (e o
baseline) e produz um veredito com confiança e evidência.

Estratégias:
  signature  -> regex de evidência forte na resposta (ex.: root:x:0:0, uid=)
  reflection -> marcador único do payload aparece refletido
  time       -> atraso induzido (blind time-based) vs baseline
  diff       -> divergência estrutural (status/tamanho/similaridade) vs baseline
  oob        -> callback out-of-band registrado com o token do payload
"""
from __future__ import annotations

import re
import difflib
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

from .http_client import Response


@dataclass
class Signal:
    detector: str
    hit: bool
    confidence: float          # 0..1
    evidence: str = ""


# ---------------------------------------------------------------------------
# Signature / evidence based
# ---------------------------------------------------------------------------
def compile_signatures(patterns: List[str]) -> List[Pattern]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
        except re.error:
            out.append(re.compile(re.escape(p), re.IGNORECASE))
    return out


def sig_detect(resp: Response, sigs: List[Pattern], baseline: Optional[Response] = None,
               injected: str = "") -> Signal:
    if not resp.ok or not resp.text:
        return Signal("signature", False, 0.0)
    for rx in sigs:
        m = rx.search(resp.text)
        if m:
            # se a MESMA assinatura casa no payload injetado, o match na resposta
            # é só reflexão do nosso input — não é evidência de execução. Pula.
            if injected and rx.search(injected):
                continue
            # se o baseline já continha a mesma evidência, degrada a confiança
            if baseline and baseline.text and rx.search(baseline.text):
                return Signal("signature", True, 0.45,
                              f"assinatura {rx.pattern!r} (presente também no baseline)")
            snippet = _context(resp.text, m.start(), m.end())
            return Signal("signature", True, 0.95, f"{rx.pattern!r} -> {snippet}")
    return Signal("signature", False, 0.0)


# ---------------------------------------------------------------------------
# Reflection
# ---------------------------------------------------------------------------
def reflect_detect(resp: Response, marker: str, raw_only: bool = False) -> Signal:
    if not resp.ok or not marker:
        return Signal("reflection", False, 0.0)
    if marker in resp.text:
        idx = resp.text.find(marker)
        return Signal("reflection", True, 0.6 if raw_only else 0.8,
                      f"marcador refletido: {_context(resp.text, idx, idx+len(marker))}")
    return Signal("reflection", False, 0.0)


# ---------------------------------------------------------------------------
# Time-based (blind)
# ---------------------------------------------------------------------------
def time_detect(resp: Response, baseline_elapsed: float, delay: float,
                margin: float = 1.5) -> Signal:
    """
    Considera hit quando o tempo de resposta ~ baseline + delay (com margem).
    delay = atraso pedido no payload (ex.: sleep 5).
    """
    threshold = baseline_elapsed + delay - margin
    if resp.elapsed >= threshold and resp.elapsed >= delay - margin:
        conf = min(0.95, 0.6 + 0.1 * (resp.elapsed - threshold))
        return Signal("time", True, conf,
                      f"elapsed={resp.elapsed:.2f}s baseline={baseline_elapsed:.2f}s delay={delay}s")
    return Signal("time", False, 0.0)


# ---------------------------------------------------------------------------
# Differential (boolean/blind por divergência)
# ---------------------------------------------------------------------------
def diff_detect(resp: Response, baseline: Response,
                len_ratio: float = 0.30) -> Signal:
    if not resp.ok or not baseline.ok:
        return Signal("diff", False, 0.0)
    ev = []
    conf = 0.0
    if resp.status != baseline.status:
        ev.append(f"status {baseline.status}->{resp.status}")
        conf = max(conf, 0.55)
    base_len = max(1, baseline.length)
    delta = abs(resp.length - baseline.length) / base_len
    if delta >= len_ratio:
        ev.append(f"len {baseline.length}->{resp.length} (Δ{delta*100:.0f}%)")
        conf = max(conf, 0.5)
    if conf > 0:
        # refina com similaridade textual
        sim = _similarity(baseline.text, resp.text)
        if sim < 0.6:
            conf = min(0.85, conf + 0.15)
            ev.append(f"similaridade={sim:.2f}")
        return Signal("diff", True, conf, "; ".join(ev))
    return Signal("diff", False, 0.0)


# ---------------------------------------------------------------------------
# Open redirect / CRLF (baseados em header)
# ---------------------------------------------------------------------------
REDIR_CANARY = "phredir1337"
CRLF_CANARY = "phcrlf"


def location_detect(resp: Response) -> Signal:
    if not resp.ok:
        return Signal("redirect", False, 0.0)
    loc = (resp.headers.get("location") or resp.headers.get("refresh") or "")
    if REDIR_CANARY in loc.lower():
        return Signal("redirect", True, 0.9, f"Location/Refresh -> {loc[:160]}")
    # meta refresh no corpo
    if resp.text and REDIR_CANARY in resp.text.lower():
        low = resp.text.lower()
        if "url=" in low and REDIR_CANARY in low[low.find("url="):low.find("url=") + 80]:
            return Signal("redirect", True, 0.6, "meta refresh no corpo aponta p/ canário")
    return Signal("redirect", False, 0.0)


def crlf_detect(resp: Response) -> Signal:
    if not resp.ok:
        return Signal("crlf", False, 0.0)
    for k, v in resp.headers.items():
        if CRLF_CANARY in k.lower() or CRLF_CANARY in str(v).lower():
            return Signal("crlf", True, 0.92, f"header injetado: {k}: {str(v)[:100]}")
    return Signal("crlf", False, 0.0)


# ---------------------------------------------------------------------------
# OOB
# ---------------------------------------------------------------------------
def oob_detect(token: str, oob_server) -> Signal:
    if oob_server is None:
        return Signal("oob", False, 0.0)
    hits = oob_server.hits(token)
    if hits:
        h = hits[0]
        return Signal("oob", True, 0.99, f"callback {h.kind} de {h.source_ip}: {h.detail}")
    return Signal("oob", False, 0.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _context(text: str, start: int, end: int, width: int = 40) -> str:
    a = max(0, start - width)
    b = min(len(text), end + width)
    frag = text[a:b].replace("\n", "\\n").replace("\r", "")
    return ("…" if a > 0 else "") + frag + ("…" if b < len(text) else "")


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    # atalho exato (memcmp em C): baseline manda amostras idênticas o tempo todo
    # e é o caso mais frequente — evita o SequenceMatcher O(n*m).
    if a == b:
        return 1.0
    a2 = a[:4000]
    b2 = b[:4000]
    if not a2 or not b2:
        return 0.0
    sm = difflib.SequenceMatcher(None, a2, b2)
    # real_quick_ratio é um LIMITE SUPERIOR O(1) do ratio real; se já é 0 (nenhum
    # caractere em comum) devolve 0 sem pagar o casamento quadrático. Como é um
    # limite superior exato, o resultado é idêntico ao ratio() completo.
    if sm.real_quick_ratio() == 0.0:
        return 0.0
    return sm.ratio()
