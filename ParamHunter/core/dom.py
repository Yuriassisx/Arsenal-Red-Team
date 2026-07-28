"""
core/dom.py
===========

Detecção de XSS baseada em DOM / execução real, usando o chromium do sistema em
modo headless (--dump-dom). Injeta payloads que SÓ produzem um marcador se o JS
realmente executar no navegador — então não há falso-positivo de "reflexão
codificada": ou o payload rodou (marcador presente no DOM renderizado) ou não.

Pega tanto XSS refletido que de fato executa quanto DOM XSS (sinks client-side
como location.hash -> innerHTML). Não precisa do driver do Playwright.
"""
from __future__ import annotations

import asyncio
import secrets
import shutil
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .target import RequestTemplate, InjectionPoint
from modules.base import Finding

_CHROMIUM = None


def chromium_path() -> Optional[str]:
    global _CHROMIUM
    if _CHROMIUM is None:
        _CHROMIUM = (shutil.which("chromium") or shutil.which("chromium-browser")
                     or shutil.which("google-chrome") or shutil.which("chrome") or "")
    return _CHROMIUM or None


def _payloads(mark: str) -> List[str]:
    js = f"document.title='{mark}';document.body&&document.body.setAttribute('data-{mark}','1')"
    return [
        f'<img src=x onerror="{js}">',
        f'"><img src=x onerror="{js}">',
        f"'><svg onload=\"{js}\">",
        f"<svg onload=\"{js}\">",
        f"<script>{js}</script>",
        f"</title><script>{js}</script>",
    ]


async def _render(url: str, timeout: float = 20.0) -> str:
    exe = chromium_path()
    if not exe:
        return ""
    args = [exe, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
            "--hide-scrollbars", "--mute-audio", "--virtual-time-budget=2500",
            "--dump-dom", url]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode("utf-8", "replace")
    except (asyncio.TimeoutError, Exception):
        try:
            proc.kill()
        except Exception:
            pass
        return ""


def _url_with(url_base: str, param: str, value: str, fragment: bool = False) -> str:
    parts = urlsplit(url_base)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    frag = parts.fragment
    if fragment:
        frag = value
    else:
        q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(q, safe="%<>\"'/="), frag))


class DOMScanner:
    def __init__(self, scope, on_finding=None, concurrency: int = 3):
        self.scope = scope
        self.on_finding = on_finding
        self.sem = asyncio.Semaphore(concurrency)

    async def _probe(self, url: str, mark: str) -> bool:
        async with self.sem:
            dom = await _render(url)
        return (f"<title>{mark}" in dom) or (f'data-{mark}="1"' in dom)

    async def scan(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        if not chromium_path():
            return out
        base = template.base_url
        if not self.scope.allows(base):
            return out
        points = [p for p in template.points(["query", "path"])]
        # também testa o fragmento (#) para sinks DOM puros
        targets = [(p.name, False) for p in points] or [("q", False)]
        targets.append(("__frag__", True))

        for pname, is_frag in targets:
            mark = "phx" + secrets.token_hex(4)
            confirmed = False
            for pl in _payloads(mark):
                url = _url_with(base if is_frag else _fill_query(template),
                                pname, pl, fragment=is_frag)
                if not self.scope.allows(url):
                    continue
                if await self._probe(url, mark):
                    where = "fragmento (#)" if is_frag else f"query:{pname}"
                    f = Finding(module="dom_xss", point=where, method="GET",
                                url=base, payload=pl[:80], base_payload="dom-xss",
                                transform="raw", confidence=0.95, detectors=["headless"],
                                evidence=f"payload EXECUTOU no navegador headless (marcador {mark} no DOM)",
                                tags=["dom-xss", "headless", "confirmed"])
                    out.append(f)
                    if self.on_finding:
                        self.on_finding(f)
                    confirmed = True
                    break
            if confirmed and is_frag:
                break
        return out


def _fill_query(template: RequestTemplate) -> str:
    """URL com os parâmetros de query da template (valores originais)."""
    parts = urlsplit(template.base_url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q.update(template.query)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q, safe="%"), ""))
