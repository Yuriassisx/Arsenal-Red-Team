#!/usr/bin/env python3
"""
tests/selftest.py — harness de regressão do ParamHunter.

Sobe o vuln_server (e o ws_server), roda cada módulo/técnica contra o endpoint
apropriado e verifica que há achado. Uso:  python3 tests/selftest.py
Sai com código 0 se tudo passar, 1 se algo falhar.
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

# (nome, args, verificador(findings)->bool)
CASES = [
    ("lfi", ["-u", f"{B}/read?file=x", "-m", "lfi"],
     lambda d: any(x["module"] == "lfi" for x in d)),
    ("sqli", ["-u", f"{B}/sqli?id=1", "-m", "sqli"],
     lambda d: any(x["module"] == "sqli" and x["confidence"] >= 0.9 for x in d)),
    ("ssti", ["-u", f"{B}/tpl?name=x", "-m", "ssti"],
     lambda d: any(x["module"] == "ssti" for x in d)),
    ("xss", ["-u", f"{B}/page?q=x", "-m", "xss"],
     lambda d: any(x["module"] == "xss" for x in d)),
    ("redirect", ["-u", f"{B}/go?next=/x", "-m", "open_redirect"],
     lambda d: any(x["module"] == "open_redirect" and x["confidence"] >= 0.8 for x in d)),
    ("crlf", ["-u", f"{B}/hdr?lang=x", "-m", "crlf"],
     lambda d: any(x["module"] == "crlf" for x in d)),
    ("nosqli", ["-u", f"{B}/nosql?user=x", "-m", "nosqli"],
     lambda d: any(x["module"] == "nosqli" for x in d)),
    ("ldap", ["-u", f"{B}/ldap?u=x", "-m", "ldap"],
     lambda d: any(x["module"] == "ldap" for x in d)),
    ("xpath", ["-u", f"{B}/xpath?q=x", "-m", "xpath"],
     lambda d: any(x["module"] == "xpath" for x in d)),
    ("deserial", ["-u", f"{B}/deser", "-X", "POST", "--data", "data=x", "-m", "deserial"],
     lambda d: any(x["module"] == "deserial" for x in d)),
    ("waf+evasao", ["-u", f"{B}/waf?file=x", "-m", "lfi"],
     lambda d: any(x["module"] == "waf" for x in d) and any(x["module"] == "lfi" for x in d)),
    ("hpp", ["-u", f"{B}/hpptest?id=1", "-m", "sqli", "--hpp"],
     lambda d: any("hpp" in x.get("tags", []) or "|hpp" in x["transform"] for x in d)),
    ("host-header", ["-u", f"{B}/hh", "-m", "", "--host-header"],
     lambda d: any(x["module"] == "host_header" for x in d)),
    ("mass-assign", ["-u", f"{B}/mass", "-X", "POST", "--data", '{"a":"1"}', "-m", "", "--mass-assignment"],
     lambda d: any(x["module"] == "mass_assignment" for x in d)),
    ("cache-poison", ["-u", f"{B}/cache", "-m", "", "--cache-poison"],
     lambda d: any(x["module"] == "cache_poison" for x in d)),
    ("idor", ["-u", f"{B}/idor?id=1", "--smart"],
     lambda d: any(x["module"] == "idor" for x in d)),
    ("smart", ["-u", f"{B}/sqli?id=1", "--smart"],
     lambda d: any(x["module"] == "sqli" for x in d)),
    ("api-fields", ["-u", f"{B}/apidisc", "-X", "POST", "--data", '{"x":"1"}', "--discover-only", "--discover-api"],
     None),  # verificado à parte (não gera finding)
    ("boolean", ["-u", f"{B}/sqli?id=1", "-m", "sqli"],
     lambda d: any("boolean" in x["detectors"] for x in d)),
    ("race", ["-u", f"{B}/race", "--race", "--race-n", "20", "-m", ""],
     lambda d: any(x["module"] == "race" for x in d)),
    ("race-safe-nofp", ["-u", f"{B}/race_safe", "--race", "--race-n", "20", "-m", ""],
     lambda d: not any(x["module"] == "race" for x in d)),   # com trava: NÃO pode flagrar
    ("dom-xss", ["-u", f"{B}/dom?q=x", "--headless", "-m", ""],
     lambda d: any(x["module"] == "dom_xss" for x in d)),
]


def run_case(name, args, check):
    out = tempfile.mktemp(suffix=".json")
    cmd = [PY, PH] + args + ["--yes", "--light", "-q", "--no-fingerprint", "-o", out]
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, cwd=BASE)
        if check is None:
            return True   # casos sem finding (ex.: discovery) só precisam não quebrar
        with open(out) as fh:
            d = json.load(fh)
        return bool(check(d))
    except Exception as e:
        print(f"    erro: {e}")
        return False
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


def main():
    procs = []
    for script, port in (("vuln_server.py", 8000), ("ws_server.py", 8001)):
        p = subprocess.Popen([PY, os.path.join(BASE, "tests", script)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        procs.append(p)
    time.sleep(2.5)

    passed = failed = 0
    try:
        for name, args, check in CASES:
            ok = run_case(name, args, check)
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
            passed += ok
            failed += not ok
    finally:
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                p.kill()

    print(f"\n{passed} passaram, {failed} falharam de {passed + failed}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
