"""
core/crawler.py
===============

Descoberta de superfície: crawler HTTP em largura (BFS) que segue links e forms,
e extrai endpoints/paths embutidos em JavaScript. Devolve URLs COM parâmetros
(candidatas a fuzzing) e alvos de formulários (method+action+campos).

Fica sempre no escopo. Não executa JS (para SPA pesada, use um headless — fora
do escopo desta versão), mas o parsing de JS pega a maioria das rotas de API.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import List, Set, Dict, Tuple
from urllib.parse import urljoin, urlsplit, urldefrag

from .http_client import HttpClient
from .scope import Scope
from .target import PreparedRequest, InjectionPoint, from_url, RequestTemplate


class _LinkParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: Set[str] = set()
        self.forms: List[dict] = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.add(urljoin(self.base, d["href"]))
        elif tag in ("script", "link") and d.get("src"):
            self.links.add(urljoin(self.base, d["src"]))
        elif tag == "form":
            self._cur = {"action": urljoin(self.base, d.get("action", self.base)),
                         "method": (d.get("method", "get") or "get").upper(),
                         "fields": {}}
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            if d.get("name"):
                self._cur["fields"][d["name"]] = d.get("value", "1")

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


# endpoints/paths embutidos em JS (fetch/axios/xhr/strings de rota)
_JS_URL = re.compile(r"""["'`](/[a-zA-Z0-9_\-./]{1,120}(?:\?[a-zA-Z0-9_\-=&%]{0,120})?)["'`]""")
_JS_FULL = re.compile(r"""["'`](https?://[a-zA-Z0-9_\-./:]{4,160}(?:\?[^"'`]{0,120})?)["'`]""")


def extract_js_endpoints(text: str, base: str) -> Set[str]:
    out: Set[str] = set()
    for m in _JS_URL.finditer(text or ""):
        p = m.group(1)
        if any(p.endswith(ext) for ext in (".css", ".png", ".jpg", ".svg", ".woff", ".gif", ".ico")):
            continue
        out.add(urljoin(base, p))
    for m in _JS_FULL.finditer(text or ""):
        out.add(m.group(1))
    return out


def _norm(url: str) -> str:
    return urldefrag(url)[0]


def _has_params(url: str) -> bool:
    return bool(urlsplit(url).query)


async def crawl(client: HttpClient, scope: Scope, seeds: List[str],
                max_pages: int = 60, max_depth: int = 2,
                headers: dict = None) -> Tuple[List[str], List[RequestTemplate]]:
    """Retorna (urls_com_parametros, templates_de_formularios)."""
    seen: Set[str] = set()
    param_urls: Set[str] = set()
    form_templates: List[RequestTemplate] = []
    queue: List[Tuple[str, int]] = [(_norm(u), 0) for u in seeds]
    pages = 0

    while queue and pages < max_pages:
        url, depth = queue.pop(0)
        if url in seen or not scope.allows(url):
            continue
        seen.add(url)
        req = PreparedRequest(method="GET", url=url, headers=headers or {}, cookies={},
                              data=None, json_body=None, injected="",
                              point=InjectionPoint("", "", ""))
        resp = await client.send(req)
        if not resp.ok:
            continue
        pages += 1
        if _has_params(url):
            param_urls.add(url)

        ctype = resp.headers.get("content-type", "")
        # JS: só extrai endpoints
        if "javascript" in ctype or url.endswith(".js"):
            for e in extract_js_endpoints(resp.text, url):
                if scope.allows(e):
                    if _has_params(e):
                        param_urls.add(e)
                    if depth < max_depth and _norm(e) not in seen:
                        queue.append((_norm(e), depth + 1))
            continue

        # HTML: links + forms
        parser = _LinkParser(url)
        try:
            parser.feed(resp.text)
        except Exception:
            pass
        # endpoints em <script> inline
        for e in extract_js_endpoints(resp.text, url):
            if scope.allows(e) and _has_params(e):
                param_urls.add(e)
        for link in parser.links:
            link = _norm(link)
            if not scope.allows(link):
                continue
            if _has_params(link):
                param_urls.add(link)
            if depth < max_depth and link not in seen and link not in [q[0] for q in queue]:
                queue.append((link, depth + 1))
        for form in parser.forms:
            if not scope.allows(form["action"]) or not form["fields"]:
                continue
            data = "&".join(f"{k}={v}" for k, v in form["fields"].items())
            t = from_url(form["action"], method=form["method"],
                         headers=headers or {}, data=(data if form["method"] != "GET" else None))
            if form["method"] == "GET":
                for k, v in form["fields"].items():
                    t.query.setdefault(k, v)
            form_templates.append(t)

    return sorted(param_urls), form_templates
