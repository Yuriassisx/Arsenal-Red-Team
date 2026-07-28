"""
core/importer.py
================

Importa requisições de formatos usados no dia a dia de teste de API:

  - raw HTTP request (estilo Burp/ZAP: "POST /api HTTP/1.1\\nHost: ...")
  - comando cURL (copiado do DevTools -> "Copy as cURL")

Ambos produzem um RequestTemplate pronto para o scanner, preservando método,
headers (Authorization/API-Key), cookies, content-type e corpo (JSON ou form).
"""
from __future__ import annotations

import shlex
from typing import Optional

from .target import RequestTemplate, from_url


# ---------------------------------------------------------------------------
# Raw HTTP request (Burp)
# ---------------------------------------------------------------------------
def from_raw_request(text: str, scheme: str = "https") -> RequestTemplate:
    text = text.replace("\r\n", "\n").strip("\n")
    if not text.strip():
        raise ValueError("request bruto vazio")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    first = lines[0].split()
    if len(first) < 2:
        raise ValueError(f"linha de requisição inválida: {lines[0]!r}")
    method, target = first[0], first[1]

    headers = {}
    cookies_raw = ""
    host = ""
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k, v = k.strip(), v.strip()
        lk = k.lower()
        if lk == "host":
            host = v
        elif lk == "cookie":
            cookies_raw = v
        else:
            headers[k] = v

    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        if not host:
            raise ValueError("request sem header Host e sem URL absoluta")
        url = f"{scheme}://{host}{target}"

    cookies = {}
    for part in cookies_raw.split(";"):
        if "=" in part:
            ck, cv = part.split("=", 1)
            cookies[ck.strip()] = cv.strip()

    tmpl = from_url(url, method=method, headers=headers, cookies=cookies,
                    data=body if body.strip() else None)
    return tmpl


# ---------------------------------------------------------------------------
# cURL
# ---------------------------------------------------------------------------
def from_curl(command: str) -> RequestTemplate:
    # normaliza continuações de linha
    command = command.replace("\\\n", " ").replace("\r", " ")
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    url = None
    method = None
    headers = {}
    cookies_raw = ""
    data = None
    user = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        # próximo token de forma segura (flag no fim do comando não deve crashar)
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-X", "--request"):
            method = nxt; i += 2; continue
        if t in ("-H", "--header"):
            hv = nxt; i += 2
            if ":" in hv:
                k, v = hv.split(":", 1)
                if k.strip().lower() == "cookie":
                    cookies_raw = v.strip()
                else:
                    headers[k.strip()] = v.strip()
            continue
        if t in ("-b", "--cookie"):
            cookies_raw = nxt; i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode"):
            data = (data + "&" + nxt) if data else nxt; i += 2; continue
        if t in ("-u", "--user"):
            user = nxt; i += 2; continue
        if t in ("-A", "--user-agent"):
            headers["User-Agent"] = nxt; i += 2; continue
        if t in ("-e", "--referer"):
            headers["Referer"] = nxt; i += 2; continue
        if t in ("--url",):
            url = nxt; i += 2; continue
        if t.startswith("-"):
            # flags sem valor (-s, -k, -L, --compressed...) ignoradas
            i += 1; continue
        # argumento posicional = URL
        if url is None:
            url = t
        i += 1

    if not url:
        raise ValueError("não foi possível extrair a URL do comando curl")
    if data and not method:
        method = "POST"
    if user:
        import base64
        headers.setdefault("Authorization", "Basic " + base64.b64encode(user.encode()).decode())

    cookies = {}
    for part in cookies_raw.split(";"):
        if "=" in part:
            ck, cv = part.split("=", 1)
            cookies[ck.strip()] = cv.strip()

    return from_url(url, method=method or "GET", headers=headers,
                    cookies=cookies, data=data)
