"""
core/websocket.py
=================

Fuzzing de endpoints WebSocket. Conecta, envia payloads de injeção (crus e
embrulhados nos envelopes JSON mais comuns), lê as respostas e aplica detecção
por assinatura (erros de SQL/NoSQL, saída de comando, reflexão de marcador).

Requer aiohttp. Uso via --websocket ws://host/path.
"""
from __future__ import annotations

import json
import secrets
from typing import List, Optional

from .detector import compile_signatures
from modules.base import Finding

# assinaturas fortes reaproveitadas (SQL/NoSQL/cmd/erros)
_SIGS = compile_signatures([
    r"SQL syntax.*MySQL", r"You have an error in your SQL syntax",
    r"ORA-[0-9]{5}", r"PostgreSQL.*ERROR", r"SQLite3::", r"Unclosed quotation",
    r"MongoError|E11000|\$where",
    r"uid=\d+\([a-z0-9_]+\)", r"root:.*:0:0:",
    r"XPathException|LDAPException",
    r"TypeError|SyntaxError|ReferenceError",
])

# payloads de sondagem multi-classe
_PROBES = [
    "'", "\"", "') OR ('1'='1", "1;SELECT SLEEP(0)", "' || '1'=='1",
    ";id", "$(id)", "../../../../etc/passwd", "{{7*7}}", "<x>",
]

# envelopes JSON comuns em apps WS
_ENVELOPES = ["{}", '{"message":%s}', '{"data":%s}', '{"query":%s}',
              '{"type":"msg","content":%s}', '{"payload":%s}']


async def scan_ws(url: str, headers: Optional[dict] = None,
                  timeout: float = 10.0, on_finding=None) -> List[Finding]:
    try:
        import aiohttp
    except ImportError:
        raise RuntimeError("aiohttp necessário para --websocket")

    out: List[Finding] = []
    marker = "phw" + secrets.token_hex(4)

    async with aiohttp.ClientSession(headers=headers or {}) as sess:
        try:
            ws = await sess.ws_connect(url, timeout=timeout, heartbeat=None)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"falha no handshake WS: {e}")

        async def probe(msg: str, tag: str):
            try:
                await ws.send_str(msg)
                resp = await ws.receive(timeout=timeout)
            except Exception:
                return
            data = str(getattr(resp, "data", "") or "")
            for rx in _SIGS:
                m = rx.search(data)
                if m:
                    f = Finding(module="websocket", point=f"ws:{tag}", method="WS",
                                url=url, payload=msg[:120], base_payload=msg[:80],
                                transform="raw", confidence=0.9, detectors=["signature"],
                                evidence=f"{rx.pattern!r} -> {data[:120]}", tags=["websocket"])
                    out.append(f)
                    if on_finding:
                        on_finding(f)
                    return
            if marker in data:            # reflexão
                f = Finding(module="websocket", point=f"ws:{tag}", method="WS",
                            url=url, payload=msg[:120], base_payload=msg[:80],
                            transform="raw", confidence=0.6, detectors=["reflection"],
                            evidence=f"marcador refletido: {data[:120]}", tags=["websocket"])
                out.append(f)
                if on_finding:
                    on_finding(f)

        # reflexão base
        await probe(marker, "reflect")
        # payloads crus + em envelopes
        for p in _PROBES:
            await probe(p, "raw")
            for env in _ENVELOPES[1:]:
                await probe(env % json.dumps(p), "json")

        await ws.close()
    return out
