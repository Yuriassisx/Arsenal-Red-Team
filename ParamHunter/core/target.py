"""
core/target.py
==============

Modelagem do alvo e dos pontos de injeção.

Um `RequestTemplate` descreve uma requisição HTTP base com um conjunto de
parâmetros em diferentes localizações (query string, corpo urlencoded, corpo
JSON, headers, cookies, e segmentos de path). Cada parâmetro é um
`InjectionPoint` onde a engine substitui o valor por payloads.
"""
from __future__ import annotations

import json
import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# localizações de injeção suportadas
LOC_QUERY = "query"
LOC_BODY = "body"        # application/x-www-form-urlencoded
LOC_JSON = "json"        # application/json
LOC_HEADER = "header"
LOC_COOKIE = "cookie"
LOC_PATH = "path"        # segmento de caminho (?/FUZZ)

VALID_LOCS = {LOC_QUERY, LOC_BODY, LOC_JSON, LOC_HEADER, LOC_COOKIE, LOC_PATH}


@dataclass
class InjectionPoint:
    name: str
    location: str
    original: str = ""

    def __str__(self):
        return f"{self.location}:{self.name}"


@dataclass
class RequestTemplate:
    """Requisição base + inventário de pontos de injeção."""
    url: str
    method: str = "GET"
    query: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, str] = field(default_factory=dict)
    json_body: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    # marcadores de path -> valor de amostra. Ex.: {"{id}": "1", "FUZZ": "1"}.
    # cada marcador presente na URL vira um ponto de injeção de path.
    path_params: Dict[str, str] = field(default_factory=dict)
    # nomes de ponto a NÃO injetar (por nome exato ou prefixo "pai."). Ex.: GraphQL
    # exclui "query" p/ fuzzar só as variables, não a operação inteira.
    skip_points: List[str] = field(default_factory=list)

    def __post_init__(self):
        # compat: 'FUZZ' bare na URL vira um path param automático
        if "FUZZ" in self.url and "FUZZ" not in self.path_params:
            self.path_params["FUZZ"] = "1"

    # ------------------------------------------------------------------
    def _fill_path(self, inject_marker: Optional[str] = None, inject_value: str = "") -> str:
        """Substitui os marcadores de path pelos samples; um deles pelo payload."""
        url = self.url
        for marker, sample in self.path_params.items():
            if marker == inject_marker:
                val = inject_value.replace(" ", "%20")
                url = url.replace(marker, val)
            else:
                url = url.replace(marker, sample or "1")
        return url

    @property
    def base_url(self) -> str:
        parts = urlsplit(self._fill_path())
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    def points(self, locations: Optional[List[str]] = None) -> List[InjectionPoint]:
        """Enumera todos os pontos de injeção disponíveis."""
        locs = set(locations) if locations else VALID_LOCS
        pts: List[InjectionPoint] = []
        if LOC_QUERY in locs:
            for k, v in self.query.items():
                pts.append(InjectionPoint(k, LOC_QUERY, v))
        if LOC_BODY in locs:
            for k, v in self.body.items():
                pts.append(InjectionPoint(k, LOC_BODY, v))
        if LOC_JSON in locs and self.json_body:
            for k, v in _flatten_json(self.json_body):
                pts.append(InjectionPoint(k, LOC_JSON, str(v)))
        if LOC_HEADER in locs:
            for k, v in self.headers.items():
                pts.append(InjectionPoint(k, LOC_HEADER, v))
        if LOC_COOKIE in locs:
            for k, v in self.cookies.items():
                pts.append(InjectionPoint(k, LOC_COOKIE, v))
        if LOC_PATH in locs:
            for marker, sample in self.path_params.items():
                if marker in self.url:
                    pts.append(InjectionPoint(marker, LOC_PATH, sample))
        if self.skip_points:
            pts = [p for p in pts if not any(
                p.name == s or p.name.startswith(s + ".") for s in self.skip_points)]
        return pts

    # ------------------------------------------------------------------
    def render(self, point: InjectionPoint, value: str, mode: str = "replace") -> "PreparedRequest":
        """
        Constrói a requisição concreta injetando `value` no ponto dado.

        mode:
          replace   -> substitui o valor original pelo payload
          append    -> concatena o payload ao valor original
          hpp       -> HTTP Parameter Pollution: envia o param 2x, payload por ÚLTIMO
                       (backends "last wins": PHP/Apache, etc.)
          hpp_first -> HPP com o payload PRIMEIRO ("first wins": ASP/alguns WAFs)
        """
        q = dict(self.query)
        b = dict(self.body)
        h = dict(self.headers)
        c = dict(self.cookies)
        jb = copy.deepcopy(self.json_body) if self.json_body else None
        hpp = mode in ("hpp", "hpp_first")

        def _mk(orig: str) -> str:
            return (orig + value) if mode == "append" else value

        if point.location == LOC_PATH:
            url = self._fill_path(inject_marker=point.name, inject_value=_mk(point.original))
        else:
            url = self._fill_path()

        if point.location == LOC_QUERY and not hpp:
            q[point.name] = _mk(q.get(point.name, ""))
        elif point.location == LOC_BODY:
            b[point.name] = _mk(b.get(point.name, "")) if not hpp else b.get(point.name, "")
        elif point.location == LOC_JSON and jb is not None:
            _set_json(jb, point.name, _mk(str(_get_json(jb, point.name) or "")))
        elif point.location == LOC_HEADER:
            h[point.name] = _mk(h.get(point.name, ""))
        elif point.location == LOC_COOKIE:
            c[point.name] = _mk(c.get(point.name, ""))

        # monta a query como LISTA de pares (permite chaves duplicadas p/ HPP)
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        # aplica os params da template (substituindo valores existentes)
        seen = {k for k, _ in pairs}
        pairs = [(k, q.get(k, v)) for k, v in pairs]
        for k, v in q.items():
            if k not in seen:
                pairs.append((k, v))

        if hpp and (point.location in (LOC_QUERY, LOC_BODY)):
            orig = (self.query if point.location == LOC_QUERY else self.body).get(point.name, "")
            if point.location == LOC_QUERY:
                if mode == "hpp_first":
                    pairs = [(point.name, value)] + [(k, v) for k, v in pairs if k != point.name] + [(point.name, orig)]
                else:
                    pairs = [(k, v) for k, v in pairs if k != point.name] + [(point.name, orig), (point.name, value)]

        final_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urlencode(pairs, doseq=False, safe="%"), parts.fragment)
        )

        # HPP em corpo urlencoded: duplica o campo (httpx repete campos c/ valor lista)
        if hpp and point.location == LOC_BODY:
            orig = self.body.get(point.name, "")
            b = dict(self.body)
            b[point.name] = [value, orig] if mode == "hpp_first" else [orig, value]

        data = None
        json_payload = None
        if jb is not None:
            json_payload = jb
        elif b:
            data = b

        return PreparedRequest(
            method=self.method,
            url=final_url,
            headers=h,
            cookies=c,
            data=data,
            json_body=json_payload,
            injected=value,
            point=point,
        )

    def baseline(self) -> "PreparedRequest":
        """Requisição sem injeção (valores originais)."""
        parts = urlsplit(self._fill_path())
        existing = dict(parse_qsl(parts.query, keep_blank_values=True))
        existing.update(self.query)
        url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(existing, safe="%"), parts.fragment)
        )
        return PreparedRequest(
            method=self.method,
            url=url,
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            data=dict(self.body) or None,
            json_body=copy.deepcopy(self.json_body),
            injected="",
            point=None,
        )


def curl_repro(req) -> str:
    """Monta um comando curl PRONTO que reproduz a requisição do achado."""
    parts = ["curl -sk"]
    if req.method and req.method.upper() != "GET":
        parts.append(f"-X {req.method.upper()}")
    # headers relevantes (pula os default do cliente; mantém auth/content-type/host)
    for k, v in (req.headers or {}).items():
        kl = k.lower()
        if kl in ("authorization", "content-type", "host", "x-forwarded-host",
                  "x-forwarded-for", "cookie") or kl.startswith("x-"):
            parts.append(f"-H {_shq(f'{k}: {v}')}")
    if req.cookies:
        ck = "; ".join(f"{k}={v}" for k, v in req.cookies.items())
        parts.append(f"-b {_shq(ck)}")
    if req.json_body is not None:
        import json as _json
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"--data {_shq(_json.dumps(req.json_body, ensure_ascii=False))}")
    elif req.data:
        if isinstance(req.data, dict):
            body = "&".join(f"{k}={v}" for k, v in req.data.items())
        else:
            body = str(req.data)
        parts.append(f"--data {_shq(body)}")
    parts.append(_shq(req.url))
    return " ".join(parts)


def _shq(s: str) -> str:
    """Aspas simples seguras p/ shell (escapa aspas simples internas)."""
    return "'" + str(s).replace("'", "'\\''") + "'"


@dataclass
class PreparedRequest:
    method: str
    url: str
    headers: Dict[str, str]
    cookies: Dict[str, str]
    data: Optional[Dict[str, str]]
    json_body: Optional[Dict[str, Any]]
    injected: str
    point: Optional[InjectionPoint]
    # metadados p/ o verbose detalhado (preenchidos pela engine)
    module: str = ""          # módulo de vuln (propósito)
    label: str = ""           # transform/encoder aplicado
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers JSON aninhado (dot-path)
# ---------------------------------------------------------------------------
def _flatten_json(obj: Any, prefix: str = "") -> List[tuple[str, Any]]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out.extend(_flatten_json(v, key))
            else:
                out.append((key, v))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                out.extend(_flatten_json(v, key))
            else:
                out.append((key, v))
    return out


def _get_json(obj: Any, dotpath: str):
    cur = obj
    for part in _split_path(dotpath):
        if isinstance(part, int):
            cur = cur[part]
        else:
            cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _set_json(obj: Any, dotpath: str, value: Any):
    parts = _split_path(dotpath)
    cur = obj
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value


def _split_path(dotpath: str):
    parts = []
    for seg in dotpath.replace("]", "").replace("[", ".").split("."):
        if seg == "":
            continue
        parts.append(int(seg) if seg.isdigit() else seg)
    return parts


# ---------------------------------------------------------------------------
# Parsing de entrada
# ---------------------------------------------------------------------------
def from_url(url: str, method: str = "GET", headers: Optional[dict] = None,
             cookies: Optional[dict] = None, data: Optional[str] = None) -> RequestTemplate:
    """Constrói RequestTemplate a partir de uma URL (e opcionalmente corpo)."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    body: Dict[str, str] = {}
    json_body = None

    if data:
        s = data.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                json_body = json.loads(s)
                if method == "GET":
                    method = "POST"
            except json.JSONDecodeError:
                body = dict(parse_qsl(data, keep_blank_values=True))
        else:
            body = dict(parse_qsl(data, keep_blank_values=True))
        if body and method == "GET":
            method = "POST"

    return RequestTemplate(
        url=url,
        method=method.upper(),
        query=query,
        body=body,
        json_body=json_body,
        headers=headers or {},
        cookies=cookies or {},
    )
