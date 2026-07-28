"""
core/race.py
============

Teste de race condition (TOCTOU) por rajada concorrente. Dispara N requisições
IDÊNTICAS simultâneas e depois 1 sequencial (estado "assentado"). Se >=2 das
requisições da rajada divergem do estado assentado — todas pegaram o estado
PRÉ-limite (ex.: cupom ainda não usado, saldo ainda disponível) — é sinal de que
o limite foi contornado pela concorrência.

Endpoint com trava (mutex) deixa só 1 request "ganhar"; sem trava, vários ganham.
"""
from __future__ import annotations

import asyncio
from typing import List

from .http_client import HttpClient
from .target import RequestTemplate
from .detector import _similarity
from modules.base import Finding


class RaceScanner:
    def __init__(self, client: HttpClient, scope, on_finding=None, n: int = 20):
        self.client = client
        self.scope = scope
        self.on_finding = on_finding
        self.n = n

    async def scan(self, template: RequestTemplate) -> List[Finding]:
        out: List[Finding] = []
        base = template.baseline()
        if not self.scope.allows(base.url):
            return out

        # rajada concorrente de N requisições idênticas (mesmo instante)
        burst = await asyncio.gather(*[self.client.send(template.baseline())
                                       for _ in range(self.n)])
        oks = [r for r in burst if r.ok]
        if len(oks) < 2:
            return out

        # estado "assentado" (sequencial, após a rajada)
        settled = await self.client.send(template.baseline())

        # quantas da rajada divergem do estado assentado (pegaram o pré-limite)?
        winners = [r for r in oks if _similarity(r.text, settled.text) < 0.90
                   and r.status == settled.status]
        # e quantas divergem por status (ex.: 200 na rajada, 429 depois)?
        status_winners = [r for r in oks if r.status != settled.status and r.ok]
        won = max(len(winners), len(status_winners))

        if won >= 2:
            f = Finding(
                module="race", point="request", method=template.method,
                url=template.base_url, payload=f"burst x{self.n}",
                base_payload="race-condition", transform="raw",
                confidence=0.7 if won < self.n else 0.8, detectors=["race"],
                evidence=f"{won}/{self.n} requisições da rajada pegaram o estado pré-limite "
                         f"(divergem do estado assentado) — possível race condition (TOCTOU)",
                tags=["race", "toctou"])
            out.append(f)
            if self.on_finding:
                self.on_finding(f)
        return out
