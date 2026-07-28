"""
core/discovery.py
=================

Enumeração / descoberta de parâmetros.

Três vetores:
  1. extract     -> extrai nomes de parâmetros do HTML (forms, links, inputs) e
                    de blocos JSON/JS refletidos na página.
  2. reflected   -> força nomes de uma wordlist em lotes com um canário único;
                    se o canário reflete, faz bisseção para achar qual nome o
                    provocou (técnica do Arjun).
  3. behavioral  -> compara status/tamanho da resposta ao injetar cada nome
                    (em lote) contra um baseline com nomes-lixo, revelando
                    parâmetros que alteram o comportamento sem refletir.

Parâmetros descobertos viram novos pontos de injeção para o fuzzing.
"""
from __future__ import annotations

import re
import secrets
import asyncio
from html.parser import HTMLParser
from typing import List, Set, Optional
from urllib.parse import urlsplit, parse_qsl

from .http_client import HttpClient
from .target import RequestTemplate, PreparedRequest, LOC_QUERY, LOC_BODY
from .detector import _similarity


# ---------------------------------------------------------------------------
# 1. Extração estática do HTML
# ---------------------------------------------------------------------------
class _FormParamParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.names: Set[str] = set()

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("input", "select", "textarea", "button"):
            if d.get("name"):
                self.names.add(d["name"])
        if tag == "a" and d.get("href"):
            self._from_url(d["href"])
        if tag == "form" and d.get("action"):
            self._from_url(d["action"])

    def _from_url(self, url: str):
        q = urlsplit(url).query
        for k, _ in parse_qsl(q, keep_blank_values=True):
            self.names.add(k)


_JS_KEYS = re.compile(r"""["']([a-zA-Z_][a-zA-Z0-9_\-]{1,40})["']\s*:""")


def extract_params(html: str) -> Set[str]:
    names: Set[str] = set()
    if not html:
        return names
    p = _FormParamParser()
    try:
        p.feed(html)
        names |= p.names
    except Exception:
        pass
    # chaves em objetos JSON/JS embutidos — candidatos a parâmetros de API
    for m in _JS_KEYS.finditer(html):
        names.add(m.group(1))
    return {n for n in names if 1 < len(n) <= 40}


# ---------------------------------------------------------------------------
# 2 & 3. Descoberta ativa por wordlist
# ---------------------------------------------------------------------------
async def discover(
    template: RequestTemplate,
    client: HttpClient,
    wordlist: List[str],
    location: str = LOC_QUERY,
    chunk: int = 40,
    reflection: bool = True,
    behavioral: bool = True,
) -> List[str]:
    found: Set[str] = set()
    canary = "phz" + secrets.token_hex(4)

    # baseline com nomes-lixo para calibrar variação normal
    junk = [f"phjunk{i}{secrets.token_hex(2)}" for i in range(6)]
    base_req = _inject_params(template, {n: canary for n in junk}, location)
    base_resp = await client.send(base_req)
    base_len = base_resp.length
    base_status = base_resp.status

    # limiar de variação "normal" observado com lixo
    noise = await _measure_noise(template, client, location, canary)

    words = [w for w in wordlist if w and w not in template.query and w not in template.body]

    async def probe(names: List[str]):
        req = _inject_params(template, {n: canary for n in names}, location)
        resp = await client.send(req)
        candidates = set()
        # reflexão
        if reflection and resp.ok and canary in resp.text:
            candidates |= await _bisect_reflection(template, client, names, canary, location)
        # comportamental
        if behavioral and resp.ok:
            len_delta = abs(resp.length - base_len)
            if resp.status != base_status or len_delta > noise:
                if len(names) == 1:
                    candidates.add(names[0])
                else:
                    candidates |= await _bisect_behavior(
                        template, client, names, canary, location,
                        base_status, base_len, noise,
                    )
        return candidates

    tasks = [probe(words[i:i + chunk]) for i in range(0, len(words), chunk)]
    for coro in asyncio.as_completed(tasks):
        found |= await coro

    return sorted(found)


async def _measure_noise(template, client, location, canary) -> int:
    """Mede a maior variação de tamanho entre duas requisições com lixo distinto."""
    lens = []
    for _ in range(2):
        names = {f"phn{secrets.token_hex(3)}": canary for _ in range(6)}
        r = await client.send(_inject_params(template, names, location))
        if r.ok:
            lens.append(r.length)
    if len(lens) < 2:
        return 50
    return max(50, abs(lens[0] - lens[1]) + 20)


async def _bisect_reflection(template, client, names, canary, location) -> Set[str]:
    if len(names) == 1:
        req = _inject_params(template, {names[0]: canary}, location)
        r = await client.send(req)
        return {names[0]} if (r.ok and canary in r.text) else set()
    mid = len(names) // 2
    left, right = names[:mid], names[mid:]
    out: Set[str] = set()
    for half in (left, right):
        req = _inject_params(template, {n: canary for n in half}, location)
        r = await client.send(req)
        if r.ok and canary in r.text:
            out |= await _bisect_reflection(template, client, half, canary, location)
    return out


async def _bisect_behavior(template, client, names, canary, location,
                           base_status, base_len, noise) -> Set[str]:
    if len(names) == 1:
        return {names[0]}
    mid = len(names) // 2
    out: Set[str] = set()
    for half in (names[:mid], names[mid:]):
        req = _inject_params(template, {n: canary for n in half}, location)
        r = await client.send(req)
        if not r.ok:
            continue
        if r.status != base_status or abs(r.length - base_len) > noise:
            out |= await _bisect_behavior(template, client, half, canary, location,
                                          base_status, base_len, noise)
    return out


def _inject_params(template: RequestTemplate, params: dict, location: str) -> PreparedRequest:
    import copy
    t = copy.deepcopy(template)
    if location == LOC_BODY:
        t.body.update(params)
        if t.method == "GET":
            t.method = "POST"
    else:
        t.query.update(params)
    return t.baseline()


# ---------------------------------------------------------------------------
# Descoberta de CAMPOS de API (corpo JSON) — estilo Arjun para JSON
# ---------------------------------------------------------------------------
async def discover_json_fields(
    template: RequestTemplate,
    client: HttpClient,
    wordlist: List[str],
    chunk: int = 30,
) -> List[str]:
    """
    Descobre campos aceitos num corpo JSON: injeta nomes-candidato com um
    canário e detecta reflexão (bisseção) ou mudança de comportamento.
    """
    import copy, json as _json
    found: Set[str] = set()
    canary = "phj" + secrets.token_hex(4)

    base_body = template.json_body if isinstance(template.json_body, dict) else {}
    existing = set(base_body.keys())
    words = [w for w in wordlist if w and w not in existing]

    def _req(names: List[str]) -> PreparedRequest:
        t = copy.deepcopy(template)
        jb = dict(base_body)
        for n in names:
            jb[n] = canary
        t.json_body = jb
        if t.method == "GET":
            t.method = "POST"
        return t.baseline()

    base_resp = await client.send(_req([f"phz{secrets.token_hex(2)}" for _ in range(4)]))
    base_len, base_status = base_resp.length, base_resp.status

    async def bisect(names: List[str]) -> Set[str]:
        if not names:
            return set()
        r = await client.send(_req(names))
        if not r.ok:
            return set()
        reflected = canary in r.text
        changed = r.status != base_status or abs(r.length - base_len) > max(40, base_len * 0.05)
        if not (reflected or changed):
            return set()
        if len(names) == 1:
            return {names[0]}
        mid = len(names) // 2
        return (await bisect(names[:mid])) | (await bisect(names[mid:]))

    tasks = [bisect(words[i:i + chunk]) for i in range(0, len(words), chunk)]
    for coro in asyncio.as_completed(tasks):
        found |= await coro
    return sorted(found)
