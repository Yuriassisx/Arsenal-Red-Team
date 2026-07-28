"""
core/graphql.py
===============

Exploração de API GraphQL: introspection -> fuzzing de campos.

1. envia a query de introspection e lê o schema (tipos, Query, Mutation);
2. para cada campo de Query/Mutation, monta uma operação parametrizada usando
   VARIABLES para os argumentos escalares:
     query op($a: String){ campo(arg: $a){ __typename } }
   com variables {"a": "test"};
3. cada variável vira um ponto de injeção JSON (`json:variables.a`) — o scanner
   fuzza com todos os módulos/encoders, e o payload chega no resolver.

Assim testamos SQLi/NoSQLi/command-injection/etc. através dos resolvers GraphQL.
"""
from __future__ import annotations

import json
from typing import List, Optional, Dict, Any

from .target import RequestTemplate

INTROSPECTION_QUERY = (
    "query IntrospectionQuery{__schema{queryType{name}mutationType{name}"
    "types{kind name fields{name args{name type{...TR}}type{...TR}}"
    "inputFields{name type{...TR}}enumValues{name}}}}"
    "fragment TR on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"
)

SCALARS = {"String", "Int", "Float", "Boolean", "ID"}


def introspect(url: str, headers: Optional[dict] = None, timeout: float = 15.0) -> dict:
    import httpx
    r = httpx.post(url, json={"query": INTROSPECTION_QUERY},
                   headers=headers or {}, timeout=timeout, verify=False,
                   follow_redirects=True)
    data = r.json()
    if "data" not in data or not data["data"].get("__schema"):
        raise ValueError("introspection desabilitada ou resposta inesperada")
    return data["data"]["__schema"]


class GraphQLExplorer:
    def __init__(self, schema: dict, url: str, headers: Optional[dict] = None):
        self.schema = schema
        self.url = url
        self.headers = headers or {}
        self.types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

    # ---- helpers de tipo ----
    def _unwrap(self, ref: dict):
        """Devolve (base_kind, base_name, required_top)."""
        required = ref.get("kind") == "NON_NULL"
        cur = ref
        while cur and cur.get("kind") in ("NON_NULL", "LIST"):
            cur = cur.get("ofType")
        if not cur:
            return (None, None, required)
        return (cur.get("kind"), cur.get("name"), required)

    def _type_str(self, ref: dict) -> str:
        k = ref.get("kind")
        if k == "NON_NULL":
            return self._type_str(ref["ofType"]) + "!"
        if k == "LIST":
            return "[" + self._type_str(ref["ofType"]) + "]"
        return ref.get("name") or "String"

    def _sample(self, kind, name):
        if name == "Int":
            return 1
        if name == "Float":
            return 1.0
        if name == "Boolean":
            return True
        if kind == "ENUM":
            t = self.types.get(name) or {}
            ev = t.get("enumValues") or []
            return ev[0]["name"] if ev else "A"
        return "test"   # String / ID / scalars customizados

    def _selection(self, ref: dict) -> str:
        kind, name, _ = self._unwrap(ref)
        if kind in ("OBJECT", "INTERFACE", "UNION"):
            return " { __typename }"
        return ""   # escalar/enum: sem seleção

    # ---- construção ----
    def templates(self, max_fields: int = 60) -> List[RequestTemplate]:
        out: List[RequestTemplate] = []
        for op_kind, tkey in (("query", "queryType"), ("mutation", "mutationType")):
            root = self.schema.get(tkey)
            if not root:
                continue
            rtype = self.types.get(root["name"]) or {}
            for field in (rtype.get("fields") or []):
                t = self._build(op_kind, field)
                if t:
                    out.append(t)
                if len(out) >= max_fields:
                    return out
        return out

    def _build(self, op_kind: str, field: dict) -> Optional[RequestTemplate]:
        args = field.get("args") or []
        var_decls = []
        arg_uses = []
        variables: Dict[str, Any] = {}
        for a in args:
            kind, name, required = self._unwrap(a["type"])
            if kind in ("SCALAR", "ENUM") or name in SCALARS:
                var = a["name"]
                var_decls.append(f"${var}: {self._type_str(a['type'])}")
                arg_uses.append(f"{a['name']}: ${var}")
                variables[var] = self._sample(kind, name)
            elif required:
                return None   # arg obrigatório não-escalar -> não sabemos preencher
        if not variables:
            return None       # sem argumento escalar p/ injetar

        sel = self._selection(field.get("type") or {})
        decl = "(" + ", ".join(var_decls) + ")" if var_decls else ""
        use = "(" + ", ".join(arg_uses) + ")" if arg_uses else ""
        query = f"{op_kind} op{decl}{{ {field['name']}{use}{sel} }}"

        return RequestTemplate(
            url=self.url, method="POST",
            json_body={"query": query, "variables": variables},
            headers=dict(self.headers),
            # fuzza SÓ as variables (json:variables.*), nunca a operação inteira
            skip_points=["query"],
        )


def summarize(schema: dict) -> str:
    q = (schema.get("queryType") or {}).get("name")
    m = (schema.get("mutationType") or {}).get("name")
    nq = nm = 0
    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    if q and q in types:
        nq = len(types[q].get("fields") or [])
    if m and m in types:
        nm = len(types[m].get("fields") or [])
    return f"{nq} queries, {nm} mutations, {len(types)} tipos"
