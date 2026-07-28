"""
core/auth.py
============

Scanning autenticado: login por form/JSON, captura de sessão (via cookie-jar do
httpx), extração/reenvio de CSRF token e detecção de "deslogado" para re-login
automático quando a sessão expira no meio do scan.

O cookie-jar do AsyncClient persiste a sessão automaticamente entre requests;
aqui cuidamos do fluxo de login, CSRF e verificação de sucesso.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple
from urllib.parse import parse_qsl

from .http_client import HttpClient
from .target import PreparedRequest, InjectionPoint

# padrões comuns de token CSRF em HTML
_CSRF_PATTERNS = [
    r'name=["\']?(?:csrf[_\-]?token|_token|authenticity_token|__RequestVerificationToken|'
    r'csrfmiddlewaretoken|xsrf[_\-]?token)["\']?[^>]*value=["\']([^"\']+)["\']',
    r'value=["\']([^"\']+)["\'][^>]*name=["\']?(?:csrf[_\-]?token|_token|authenticity_token)',
    r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
]
_CSRF_RX = [re.compile(p, re.IGNORECASE) for p in _CSRF_PATTERNS]

_CSRF_FIELD_RX = re.compile(
    r'name=["\']?([a-zA-Z0-9_\-]*(?:csrf|token|verification)[a-zA-Z0-9_\-]*)["\']?[^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE)


def extract_csrf(html: str, field: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Devolve (nome_do_campo, valor) do token CSRF, se achar."""
    if not html:
        return None
    if field:
        m = re.search(rf'name=["\']?{re.escape(field)}["\']?[^>]*value=["\']([^"\']+)["\']',
                      html, re.IGNORECASE)
        if m:
            return (field, m.group(1))
    m = _CSRF_FIELD_RX.search(html)
    if m:
        return (m.group(1), m.group(2))
    for rx in _CSRF_RX:
        m = rx.search(html)
        if m:
            return ("csrf_token", m.group(1))
    return None


class Authenticator:
    def __init__(self, client: HttpClient, login_url: str, data: str,
                 json_mode: bool = False, csrf_field: Optional[str] = None,
                 marker: Optional[str] = None, headers: Optional[dict] = None):
        self.client = client
        self.login_url = login_url
        self.raw_data = data
        self.json_mode = json_mode
        self.csrf_field = csrf_field
        self.marker = marker
        self.headers = headers or {}

    async def login(self) -> Tuple[bool, str]:
        # 1) GET a página de login p/ CSRF (se pedido) — o jar já captura cookies
        data_pairs = dict(parse_qsl(self.raw_data, keep_blank_values=True)) if not self.json_mode else None
        if self.csrf_field or not self.json_mode:
            getreq = PreparedRequest(method="GET", url=self.login_url, headers=self.headers,
                                     cookies={}, data=None, json_body=None, injected="",
                                     point=InjectionPoint("", "", ""))
            r = await self.client.send(getreq)
            tok = extract_csrf(r.text, self.csrf_field)
            if tok and data_pairs is not None:
                data_pairs[tok[0]] = tok[1]

        # 2) POST do login
        if self.json_mode:
            import json as _json
            try:
                jb = _json.loads(self.raw_data)
            except Exception:
                jb = {}
            req = PreparedRequest(method="POST", url=self.login_url, headers=self.headers,
                                  cookies={}, data=None, json_body=jb, injected="",
                                  point=InjectionPoint("", "", ""))
        else:
            req = PreparedRequest(method="POST", url=self.login_url, headers=self.headers,
                                  cookies={}, data=data_pairs, json_body=None, injected="",
                                  point=InjectionPoint("", "", ""))
        resp = await self.client.send(req)

        # 3) verificação de sucesso
        if self.marker:
            ok = self.marker in (resp.text or "") or self.marker in str(resp.headers)
            # login costuma redirecionar; um 3xx/2xx sem erro também é bom sinal
            ok = ok or (resp.status in (301, 302, 303) and "login" not in resp.headers.get("location", "").lower())
        else:
            ok = resp.status in (200, 301, 302, 303) and resp.ok
        info = f"status {resp.status}" + (f", marcador {'OK' if (self.marker and self.marker in (resp.text or '')) else 'ausente'}" if self.marker else "")
        return ok, info

    def looks_logged_out(self, text: str) -> bool:
        """Heurística: sessão perdida se o marcador de logado sumiu."""
        if not self.marker:
            return False
        return self.marker not in (text or "")
