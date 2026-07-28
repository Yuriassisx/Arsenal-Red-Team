#!/usr/bin/env python3
"""
tests/benchmark.py — mede TAXA DE DETECÇÃO e FALSO-POSITIVO do ParamHunter.

Roda contra endpoints vulneráveis (conhecidos) e endpoints LIMPOS (sem vuln) do
vuln_server, e reporta:
  - detecção (recall): % de vulns encontradas com alta confiança
  - falso-positivo: achados de alta confiança em endpoints limpos (deve ser ~0)

Uso: python3 tests/benchmark.py
"""
import os
import sys
import json
import time
import signal
import tempfile
import subprocess

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
PH = os.path.join(BASE, "paramhunter.py")
B = "http://127.0.0.1:8000"

# (nome, url, args, módulo esperado, confiança mínima)
VULN = [
    ("lfi",    f"{B}/read?file=x",   ["-m", "lfi"],           "lfi", 0.9),
    ("sqli",   f"{B}/sqli?id=1",     ["-m", "sqli"],          "sqli", 0.9),
    ("cmdi",   f"{B}/ping?host=x",   ["-m", "cmdi"],          "cmdi", 0.9),
    ("ssti",   f"{B}/tpl?name=x",    ["-m", "ssti"],          "ssti", 0.9),
    ("xss",    f"{B}/page?q=x",      ["-m", "xss"],           "xss", 0.9),
    ("redir",  f"{B}/go?next=/x",    ["-m", "open_redirect"], "open_redirect", 0.8),
    ("crlf",   f"{B}/hdr?lang=x",    ["-m", "crlf"],          "crlf", 0.9),
    ("nosqli", f"{B}/nosql?user=x",  ["-m", "nosqli"],        "nosqli", 0.9),
    ("ldap",   f"{B}/ldap?u=x",      ["-m", "ldap"],          "ldap", 0.9),
    ("xpath",  f"{B}/xpath?q=x",     ["-m", "xpath"],         "xpath", 0.9),
]

# endpoints LIMPOS (nenhuma vuln real) — qualquer achado de alta confiança = FP
CLEAN = [
    ("static", f"{B}/clean_static?q=x", []),
    ("escaped", f"{B}/clean_esc?q=x", []),
    ("numeric", f"{B}/clean_num?id=1", []),
    ("cleanjson", f"{B}/clean_json?a=1", []),
    ("dynamic", f"{B}/dynamic?id=1", []),
]


def run(url, extra):
    out = tempfile.mktemp(suffix=".json")
    cmd = [PY, PH, "-u", url] + extra + ["--yes", "--light", "-q", "--no-fingerprint", "-o", out]
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, cwd=BASE)
        with open(out) as fh:
            return json.load(fh)
    except Exception:
        return []
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


def main():
    srv = subprocess.Popen([PY, os.path.join(BASE, "tests", "vuln_server.py")],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           start_new_session=True)
    time.sleep(2.5)
    try:
        print("=== DETECÇÃO (endpoints vulneráveis) ===")
        detected = 0
        for name, url, extra, mod, minc in VULN:
            d = run(url, extra)
            hit = any(x["module"] == mod and x["confidence"] >= minc for x in d)
            detected += hit
            print(f"  [{'OK ' if hit else 'MISS'}] {name:8} -> {'detectado' if hit else 'NAO detectado'} "
                  f"(alta confiança >= {minc})")

        print("\n=== FALSO-POSITIVO (endpoints limpos) ===")
        fp_conf = fp_total = 0
        for name, url, extra in CLEAN:
            d = run(url, extra)
            vulns = [x for x in d if x["module"] not in ("waf",)]
            conf = [x for x in vulns if x["confidence"] >= 0.9]
            fp_conf += len(conf)
            fp_total += len(vulns)
            tag = "LIMPO" if not conf else f"{len(conf)} FP-alto"
            print(f"  [{tag:9}] {name:9} -> {len(vulns)} achado(s), {len(conf)} de alta confiança")

        n_v = len(VULN)
        print("\n=== RESUMO ===")
        print(f"  Detecção (recall):     {detected}/{n_v}  = {100*detected/n_v:.0f}%")
        print(f"  FP de ALTA confiança:  {fp_conf} em {len(CLEAN)} endpoints limpos")
        print(f"  Achados totais limpos: {fp_total} (inclui provável/suspeito)")
        ok = detected == n_v and fp_conf == 0
        print(f"\n  {'BENCHMARK OK' if ok else 'REVISAR'}: recall {'100%' if detected==n_v else '<100%'}, "
              f"{'0 FP-alto' if fp_conf==0 else str(fp_conf)+' FP-alto'}")
        sys.exit(0 if ok else 1)
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), signal.SIGKILL)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    main()
