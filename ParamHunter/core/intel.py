"""
core/intel.py
=============

Inteligência de seleção: escolhe QUAIS módulos testar em cada parâmetro a partir
do NOME dele. Reduz drasticamente o volume de requisições (menos bloqueios) e
foca no que faz sentido — id -> SQLi/IDOR, redirect -> open-redirect/SSRF,
cmd -> command injection, file -> LFI, url -> SSRF, etc.
"""
from __future__ import annotations

import re
from typing import List, Set

# (regex no nome do parâmetro, [módulos], [técnicas])
# o resultado é a UNIÃO de todos os hints que casam com o nome.
HINTS = [
    # identificadores -> SQLi / NoSQL / IDOR
    (r"(^|[_\-])(id|uid|pid|gid|sid|oid|no|num|count|key|ref|rid|fid|tid)$",
     ["sqli", "nosqli"], ["idor"]),
    (r"(user_?id|account_?id|customer_?id|order_?id|item_?id|object_?id|"
     r"doc_?id|file_?id|invoice|record|profile_?id|group_?id|org_?id|team_?id)",
     ["sqli", "nosqli"], ["idor"]),
    # redirect -> open redirect + SSRF
    (r"(redirect|redir|return(url|to)?|returnurl|next|goto|continue|dest(ination)?|"
     r"forward|out|success_?url|cancel_?url|callback|back|ref_?url)",
     ["open_redirect", "ssrf"], []),
    # comando -> command injection
    (r"(cmd|exec|command|run|ping|shell|system|process|daemon|query_?cmd|"
     r"jobs?|cli|do|action|func|call|bash|sh)",
     ["cmdi"], []),
    # arquivo/caminho -> LFI
    (r"(file(name|path)?|(^|[_\-])path|page|template|tpl|include|inc|require|"
     r"document|(^|[_\-])doc|folder|directory|(^|[_\-])dir([_\-]|$)|(^|[_\-])load|"
     r"read|download|(^|[_\-])view|content|conf(ig)?|(^|[_\-])log|attachment|"
     r"resource|lang_?file|filepath)",
     ["lfi"], []),
    # url/host/fetch -> SSRF
    (r"(url|uri|link|host(name)?|domain|server|fetch|proxy|feed|site|port|ip|addr|"
     r"webhook|api|endpoint|target|src|source|remote|image_?url|imageurl|avatar|"
     r"upload_?url|import|load_?url|open|window|to)",
     ["ssrf"], []),
    # busca/texto curto -> XSS / SQLi
    (r"(^|[_\-])(q|s|kw)$", ["xss", "sqli"], []),
    (r"(search|query|keyword|term|name|title|text|message|msg|comment|content|"
     r"body|desc(ription)?|subject|label|caption|note|bio|about|tag|nick)",
     ["xss", "sqli", "ssti"], []),
    # template/render -> SSTI
    (r"(template|tpl|preview|render|theme|greeting|welcome|format|pattern|expr)",
     ["ssti"], []),
    # auth/filtro -> SQLi / NoSQL / LDAP / XPath
    (r"(user(name)?|login|email|mail|pass(word)?|filter|sort|order_?by|column|"
     r"table|where|group_?by|field|select|dn|cn)",
     ["sqli", "nosqli", "ldap", "xpath"], []),
    # xml/data -> XXE
    (r"(xml|soap|rss|feed|data|body|import|export|wsdl|svg)", ["xxe"], []),
    # headers/idioma -> CRLF
    (r"(header|lang|locale|referer|forward|charset|encoding|accept)", ["crlf"], []),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), mods, techs) for rx, mods, techs in HINTS]

# fallback p/ parâmetros sem pista: conjunto enxuto e universal (evita bloqueio)
DEFAULT_FALLBACK = ["sqli", "xss", "lfi", "ssti"]


def select(param_name: str, available: List[str]) -> Set[str]:
    """Módulos relevantes p/ um parâmetro (interseção com os disponíveis)."""
    avail = set(available)
    hit: Set[str] = set()
    for rx, mods, _techs in _COMPILED:
        if rx.search(param_name):
            hit |= set(mods)
    if not hit:
        hit = set(DEFAULT_FALLBACK)
    return hit & avail


def techniques(param_name: str) -> Set[str]:
    """Técnicas comportamentais relevantes p/ o parâmetro (ex.: idor)."""
    out: Set[str] = set()
    for rx, _mods, techs in _COMPILED:
        if rx.search(param_name):
            out |= set(techs)
    return out


# contexto XML: nome de parâmetro que sugere corpo/campo XML
_XML_RX = re.compile(r"(xml|soap|rss|wsdl|svg|xsd|dmn|feed|import|export|data)", re.IGNORECASE)


def smart_techniques(template, point_names) -> Set[str]:
    """
    Decide QUAIS técnicas dedicadas rodar num alvo, pelo contexto:
      - host_header, cache_poison: sempre (baratos, valem p/ qualquer alvo)
      - mass_assignment: só se há corpo JSON
      - xxe: só em contexto XML (content-type xml, corpo que começa com '<',
             ou parâmetro com nome tipo xml/data/soap...)
    """
    t: Set[str] = {"host_header", "cache_poison"}
    if isinstance(template.json_body, dict):
        t.add("mass_assignment")
    ct = (template.headers.get("Content-Type") or template.headers.get("content-type") or "").lower()
    xml_body = bool(template.body and any(str(v).strip().startswith("<") for v in template.body.values()))
    if "xml" in ct or xml_body or any(_XML_RX.search(n) for n in point_names):
        t.add("xxe")
    return t
