"""
core/openapi.py
===============

Exploração de API por especificação OpenAPI 3 / Swagger 2.

Lê a spec (arquivo ou URL, JSON ou YAML), resolve `$ref`, e gera um
RequestTemplate por operação (path × método). Cada parâmetro declarado —
path, query, header, cookie — e cada propriedade do corpo JSON viram pontos de
injeção que o scanner então fuzza com todos os módulos e encoders.

Segurança: por padrão só GET e POST são gerados (métodos que menos destroem
estado). PUT/PATCH/DELETE exigem inclusão explícita via --api-methods.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .target import RequestTemplate


def load_spec(source: str, timeout: float = 15.0) -> dict:
    """Carrega a spec de arquivo local ou URL (JSON ou YAML)."""
    if source.startswith("http://") or source.startswith("https://"):
        import httpx
        r = httpx.get(source, timeout=timeout, verify=False, follow_redirects=True)
        raw = r.text
    else:
        with open(source, "r", encoding="utf-8") as fh:
            raw = fh.read()
    raw = raw.strip()
    if raw.startswith("{"):
        return json.loads(raw)
    import yaml
    return yaml.safe_load(raw)


class SpecError(Exception):
    pass


class OpenAPIExplorer:
    def __init__(self, spec: dict, base_override: Optional[str] = None):
        self.spec = spec
        self.base = base_override or self._base_url()

    # ------------------------------------------------------------------
    def _base_url(self) -> str:
        # OpenAPI 3
        servers = self.spec.get("servers")
        if servers and isinstance(servers, list) and servers[0].get("url"):
            u = servers[0]["url"]
            # servers podem ser relativos; nesse caso não temos host -> erro
            if u.startswith("http"):
                return u.rstrip("/")
        # Swagger 2
        host = self.spec.get("host")
        if host:
            scheme = (self.spec.get("schemes") or ["https"])[0]
            base_path = self.spec.get("basePath", "")
            return f"{scheme}://{host}{base_path}".rstrip("/")
        return ""

    # ------------------------------------------------------------------
    def _resolve(self, node: Any, depth: int = 0) -> Any:
        """Resolve $ref (apenas refs locais #/...)."""
        if depth > 20:
            return {}
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref = node["$ref"]
                if ref.startswith("#/"):
                    cur: Any = self.spec
                    for part in ref[2:].split("/"):
                        part = part.replace("~1", "/").replace("~0", "~")
                        if isinstance(cur, dict):
                            cur = cur.get(part, {})
                        else:
                            return {}
                    return self._resolve(cur, depth + 1)
                return {}
            return {k: self._resolve(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self._resolve(x, depth + 1) for x in node]
        return node

    # ------------------------------------------------------------------
    def _sample(self, schema: dict, depth: int = 0) -> Any:
        """Gera um valor de amostra a partir de um schema."""
        if not isinstance(schema, dict) or depth > 8:
            return "test"
        for key in ("example", "default"):
            if key in schema:
                return schema[key]
        if "enum" in schema and schema["enum"]:
            return schema["enum"][0]
        t = schema.get("type")
        if t == "object" or "properties" in schema:
            out = {}
            for pname, psch in (schema.get("properties") or {}).items():
                out[pname] = self._sample(psch, depth + 1)
            if not out and schema.get("additionalProperties"):
                out["key"] = self._sample(schema["additionalProperties"], depth + 1)
            return out or {"field": "test"}
        if t == "array":
            return [self._sample(schema.get("items") or {}, depth + 1)]
        if t in ("integer", "number"):
            return 1
        if t == "boolean":
            return True
        return "test"

    # ------------------------------------------------------------------
    def templates(self, methods: Optional[List[str]] = None,
                  auth: Optional[Dict[str, str]] = None) -> List[RequestTemplate]:
        if not self.base:
            raise SpecError("não foi possível determinar a URL base da API; use --api-base")
        methods = [m.lower() for m in (methods or ["get", "post"])]
        out: List[RequestTemplate] = []
        paths = self.spec.get("paths") or {}

        for path, item in paths.items():
            item = self._resolve(item)
            common_params = item.get("parameters", []) or []
            for method, op in item.items():
                if method.lower() not in methods or not isinstance(op, dict):
                    continue
                params = common_params + (op.get("parameters", []) or [])
                tmpl = self._build(path, method.upper(), params, op, auth)
                if tmpl:
                    out.append(tmpl)
        return out

    # ------------------------------------------------------------------
    def _build(self, path: str, method: str, params: list, op: dict,
               auth: Optional[Dict[str, str]]) -> Optional[RequestTemplate]:
        url = self.base + path
        query: Dict[str, str] = {}
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        path_params: Dict[str, str] = {}

        for p in params:
            p = self._resolve(p)
            loc = p.get("in")
            name = p.get("name")
            if not name or not loc:
                continue
            sample = p.get("example")
            if sample is None:
                sample = self._sample(p.get("schema") or {})
            sample = _to_str(sample)
            if loc == "query":
                query[name] = sample
            elif loc == "header":
                headers[name] = sample
            elif loc == "cookie":
                cookies[name] = sample
            elif loc == "path":
                marker = "{" + name + "}"
                if marker in url:
                    path_params[marker] = sample or "1"

        # corpo JSON (OpenAPI 3 requestBody / Swagger 2 body param)
        json_body = None
        rb = self._resolve(op.get("requestBody") or {})
        content = rb.get("content") or {}
        for ctype, media in content.items():
            if "json" in ctype:
                json_body = self._sample(media.get("schema") or {})
                break
        if json_body is None:
            for p in params:
                p = self._resolve(p)
                if p.get("in") == "body":
                    json_body = self._sample(p.get("schema") or {})
                    break

        if auth:
            headers.update(auth)

        # garante que markers de path não resolvidos tenham sample
        import re
        for m in re.findall(r"\{[^}]+\}", url):
            path_params.setdefault(m, "1")

        return RequestTemplate(
            url=url, method=method, query=query,
            json_body=json_body if isinstance(json_body, dict) else None,
            headers=headers, cookies=cookies, path_params=path_params,
        )


def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)
