#!/usr/bin/env python3
"""
tests/test_units.py — testes unitários OFFLINE (sem rede, sem lab).

Cobre os encoders (encoders/transforms.py), os detectores (core/detector.py) e
helpers do cliente HTTP (core/http_client.py) de forma isolada e instantânea —
complementa o selftest/benchmark, que precisam subir o vuln_server.

Uso:  python3 tests/test_units.py     (sai 0 se tudo passar, 1 se algo falhar)
"""
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from encoders import expand, available, resolve_names, REGISTRY, GROUPS  # noqa: E402
from core import detector as det                                        # noqa: E402
from core import enum as en                                             # noqa: E402
from core.http_client import HttpClient, Response                       # noqa: E402
from urllib.parse import urlsplit                                       # noqa: E402

_fail = 0
_pass = 0


def check(name, cond):
    global _fail, _pass
    if cond:
        _pass += 1
        print(f"  [PASS] {name}")
    else:
        _fail += 1
        print(f"  [FAIL] {name}")


def R(text="", status=200, headers=None, elapsed=0.0):
    return Response(status=status, headers=headers or {}, text=text,
                    elapsed=elapsed, url="http://t/", length=len(text))


# ---------------------------------------------------------------------------
# encoders / transforms
# ---------------------------------------------------------------------------
def test_transforms():
    print("encoders/transforms:")
    av = available()
    check("available() traz raw e url", "raw" in av and "url" in av)
    check("available() ordenado", av == sorted(av))

    check("expand raw-only", expand("abc", ["raw"]) == [("abc", "raw")])
    check("raw sempre primeiro", expand("abc", ["url"])[0] == ("abc", "raw"))

    urlvars = [v for v, lbl in expand("../x", ["url"]) if lbl == "url"]
    check("url encoda a barra (%2F/%2f)",
          any("%2F" in v or "%2f" in v for v in urlvars))

    # case_upper("A") == "A" == raw -> deduplicado, sobra só o raw
    check("expand deduplica variante == raw",
          len(expand("A", ["case_upper"])) == 1)

    # limite corta o total
    big = expand("abcdef", available(), chain_depth=1, limit=5)
    check("expand respeita o limit", len(big) <= 5)

    ru = resolve_names(["url"])
    check("resolve_names expande o grupo url", len(ru) > 1 and "url_double" in ru)
    check("resolve_names('all') = registry inteiro",
          set(resolve_names(["all"])) == set(REGISTRY.keys()))
    check("GROUPS não vazio", len(GROUPS) >= 1)

    # todo transform devolve string(s) (lista possivelmente vazia quando não se
    # aplica ao input, ex.: ifs sem espaço) e nunca lança exceção.
    ok = True
    for nm, fn in REGISTRY.items():
        try:
            out = fn("a b/../c'd\"<x>")
            vals = [out] if isinstance(out, str) else list(out)
            if not all(isinstance(x, str) for x in vals):
                ok = False
                break
        except Exception:
            ok = False
            break
    check("todo transform retorna str(s) sem exceção", ok)


# ---------------------------------------------------------------------------
# detector
# ---------------------------------------------------------------------------
def test_detector():
    print("core/detector:")
    sigs = det.compile_signatures([r"root:.*:0:0:"])
    hit = det.sig_detect(R("conteudo root:x:0:0:root ..."), sigs)
    check("sig_detect casa assinatura", hit.hit and hit.confidence >= 0.9)

    # supressão de auto-reflexão: a assinatura veio do NOSSO payload injetado
    supp = det.sig_detect(R("eco: root:x:0:0:"), sigs, injected="root:x:0:0:")
    check("sig_detect suprime reflexão do payload", not supp.hit)

    check("reflect_detect acha o marcador",
          det.reflect_detect(R("<b>phm12345</b>"), "phm12345").hit)
    check("reflect_detect não acha ausente",
          not det.reflect_detect(R("<b>nada</b>"), "phm12345").hit)

    check("time_detect: hit acima do limiar",
          det.time_detect(R(elapsed=6.0), baseline_elapsed=1.0, delay=5, margin=1.5).hit)
    check("time_detect: sem atraso não casa",
          not det.time_detect(R(elapsed=1.2), baseline_elapsed=1.0, delay=5, margin=1.5).hit)

    base = R("home", status=200)
    check("diff_detect: mudança de status",
          det.diff_detect(R("erro 500 interno", status=500), base).hit)
    check("diff_detect: resposta igual não difere",
          not det.diff_detect(R("home", status=200), base).hit)

    check("crlf_detect: canário no header",
          det.crlf_detect(R(headers={"x-test": "phcrlf-inj"})).hit)
    check("location_detect: canário no Location",
          det.location_detect(R(headers={"location": "https://evil/phredir1337"})).hit)

    check("_similarity: iguais = 1.0", det._similarity("abcdef", "abcdef") == 1.0)
    check("_similarity: disjuntos ~ 0", det._similarity("aaaa", "bbbb") == 0.0)
    check("_similarity: parcial entre 0 e 1",
          0.0 < det._similarity("hello world", "hello there") < 1.0)


# ---------------------------------------------------------------------------
# http_client helpers
# ---------------------------------------------------------------------------
def test_http_helpers():
    print("core/http_client:")
    check("retry-after numérico", HttpClient._parse_retry_after("5") == 5.0)
    check("retry-after vazio", HttpClient._parse_retry_after("") == 0.0)
    check("retry-after lixo", HttpClient._parse_retry_after("garbage") == 0.0)
    check("retry-after data futura > 0",
          HttpClient._parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") > 0)
    check("Response.truncated default False", R().truncated is False)


def test_enum():
    print("core/enum (dedup/escopo):")
    check("in-scope: domínio exato", en._in_scope("alvo.com", "alvo.com"))
    check("in-scope: subdomínio", en._in_scope("api.alvo.com", "alvo.com"))
    check("fora de escopo: outro domínio", not en._in_scope("evil.com", "alvo.com"))
    check("fora de escopo: sufixo enganoso", not en._in_scope("alvo.com.evil.com", "alvo.com"))

    check("estático: .js descartado", en._static("/app/main.js"))
    check("estático: .php mantido", not en._static("/app/index.php"))

    # dedup por assinatura: mesmo endpoint/params (valores diferentes) = 1 só
    s1 = en._sig(urlsplit("http://a.com/p?id=1&cat=2"))
    s2 = en._sig(urlsplit("http://a.com/p?id=9&cat=8"))
    s3 = en._sig(urlsplit("http://a.com/p?id=1&page=2"))
    check("assinatura ignora VALORES (mesmo endpoint)", s1 == s2)
    check("assinatura diferencia NOMES de parâmetro", s1 != s3)
    check("have_tools() retorna dict gau/paramspider",
          set(en.have_tools().keys()) == {"gau", "paramspider"})


def main():
    test_transforms()
    test_detector()
    test_http_helpers()
    test_enum()
    total = _pass + _fail
    print(f"\n{_pass} passaram, {_fail} falharam de {total}")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
