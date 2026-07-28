"""
core/oob.py
===========

Interação out-of-band (OOB) para detecção de SSRF e injeção cega (blind).

Modelo:
  - Cada teste recebe um token único (subdomínio/caminho).
  - O payload força o alvo a bater num endpoint controlado carregando o token.
  - Uma interação registrada com aquele token = vulnerabilidade confirmada.

Dois modos:
  1. Listener HTTP local embutido (aiohttp) — ideal para labs/rede interna,
     onde o alvo consegue alcançar seu host. Registra hits por token.
  2. Domínio externo (interactsh, Burp Collaborator, webhook.site, requestbin)
     — você passa --oob-domain e checa as interações no serviço. A engine só
     gera os payloads com token; a confirmação é manual/por API do serviço.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit


def new_token(prefix: str = "ph") -> str:
    return f"{prefix}{secrets.token_hex(6)}"


@dataclass
class Interaction:
    token: str
    kind: str            # http | dns
    source_ip: str
    detail: str
    ts: float = field(default_factory=time.time)


class OOBServer:
    """
    Emissor/registrador de callbacks OOB. Três modos:
      - embutido (external=False): sobe listener HTTP e registra hits por token
        (host:porta/token). Confirmação automática.
      - externo subdomínio (external=True, sem webhook_url): token.dominio
        (interactsh/Collaborator/DNS). Confirmação no serviço.
      - webhook (webhook_url set): baseia no URL do webhook.site
        (https://webhook.site/<uuid>) -> callbacks em .../<uuid>/<token> e DNS em
        <token>.<uuid>.dnshook.site. Confirmação manual no painel do webhook.site.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8848,
                 public_host: Optional[str] = None, external: bool = False,
                 webhook_url: Optional[str] = None):
        self.host = host
        self.port = port
        self.webhook_url = webhook_url.rstrip("/") if webhook_url else None
        self.external = external or bool(self.webhook_url)
        self.interactions: Dict[str, List[Interaction]] = {}
        self._runner = None

        if self.webhook_url:
            parts = urlsplit(self.webhook_url)
            self._wh_scheme = parts.scheme or "https"
            self._wh_host = parts.netloc                    # webhook.site
            self._wh_id = parts.path.strip("/")             # <uuid>
            self.public_host = self._wh_host
        else:
            self.public_host = public_host or _guess_lan_ip()

    @property
    def base(self) -> str:
        if self.webhook_url:
            return f"{self._wh_host}/{self._wh_id}"
        return self.public_host if self.external else f"{self.public_host}:{self.port}"

    def payload_host(self, token: str) -> str:
        if self.webhook_url:
            return f"{self._wh_host}/{self._wh_id}/{token}"
        if self.external:
            return f"{token}.{self.public_host}"
        return f"{self.public_host}:{self.port}/{token}"

    def payload_url(self, token: str, scheme: str = "http") -> str:
        if self.webhook_url:
            return f"{self._wh_scheme}://{self.payload_host(token)}"
        return f"{scheme}://{self.payload_host(token)}"

    def payload_fqdn(self, token: str) -> str:
        """Nome DNS por-token (para nslookup/DNS exfil)."""
        if self.webhook_url:
            return f"{token}.{self._wh_id}.dnshook.site"
        if self.external:
            return f"{token}.{self.public_host}"
        return self.public_host

    def hits(self, token: str) -> List[Interaction]:
        return self.interactions.get(token, [])

    async def start(self):
        if self.external:
            return  # nada a subir; confirmação é no serviço externo
        try:
            from aiohttp import web
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("aiohttp necessário para o listener OOB embutido") from e

        async def handler(request):
            token = request.match_info.get("token", "")
            peer = request.remote or "?"
            self.interactions.setdefault(token, []).append(
                Interaction(
                    token=token,
                    kind="http",
                    source_ip=peer,
                    detail=f"{request.method} {request.path} UA={request.headers.get('User-Agent','')}",
                )
            )
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_route("*", "/{token}", handler)
        app.router.add_route("*", "/{token}/{tail:.*}", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()


def _guess_lan_ip() -> str:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
