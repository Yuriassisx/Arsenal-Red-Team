"""
core/reporter.py
================

Saída para o console (com cor) e exportação estruturada (JSON / JSONL / txt).
"""
from __future__ import annotations

import json
import sys
from typing import List

from modules.base import Finding
from . import __version__
from .http_client import purpose_of, encoder_desc

_COLOR = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def red(s): return _c("31", s)
def green(s): return _c("32", s)
def yellow(s): return _c("33", s)
def blue(s): return _c("34", s)
def magenta(s): return _c("35", s)
def cyan(s): return _c("36", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)


def sev_label(conf: float) -> str:
    if conf >= 0.9:
        return red(bold("CONFIRMADO"))
    if conf >= 0.7:
        return yellow(bold("PROVÁVEL  "))
    return blue("SUSPEITO  ")


def banner():
    print(cyan(bold(r"""
  ____                       _   _             _
 |  _ \ __ _ _ __ __ _ _ __ | | | |_   _ _ __ | |_ ___ _ __
 | |_) / _` | '__/ _` | '_ \| |_| | | | | '_ \| __/ _ \ '__|
 |  __/ (_| | | | (_| | | | |  _  | |_| | | | | ||  __/ |
 |_|   \__,_|_|  \__,_|_| |_|_| |_|\__,_|_| |_|\__\___|_|
""")) + dim(f"  enumeração de parâmetros + fuzzing de payloads  v{__version__}\n"))


def print_finding(f: Finding):
    if f.module == "waf":
        print(yellow(bold("[WAF]      ")) + f"{cyan(f.point)}  {yellow(f.evidence)}")
        print()
        return
    head = f"[{sev_label(f.confidence)}] {magenta(f.module.upper())} @ {cyan(f.point)}"
    print(head)
    print(f"    {dim('detectores')} {', '.join(f.detectors)}  {dim('conf')} {f.confidence:.2f}"
          + (f"  {dim('tags')} {','.join(map(str, f.tags))}" if f.tags else ""))
    print(f"    {dim('payload')}    {f.base_payload}"
          + (f"  {dim('[' + f.transform + ']')}" if f.transform != 'raw' else ""))
    if f.payload != f.base_payload:
        print(f"    {dim('enviado')}    {f.payload[:200]}")
    print(f"    {dim('req')}        {f.method} {f.url[:180]}")
    print(f"    {dim('evidência')}  {green(f.evidence[:300])}")
    print()


def print_discovery(location: str, names: List[str]):
    if names:
        print(green(bold(f"[+] parâmetros descobertos ({location}): ")) + ", ".join(names))
    else:
        print(dim(f"[-] nenhum parâmetro novo descoberto em {location}"))


def summary(findings: List[Finding], sent: int):
    print(bold(cyan("\n─── resumo ───")))
    if not findings:
        print(dim(f"nenhum achado. {sent} requisições enviadas."))
        return
    by_mod: dict[str, int] = {}
    for f in findings:
        by_mod[f.module] = by_mod.get(f.module, 0) + 1
    for mod, n in sorted(by_mod.items(), key=lambda x: -x[1]):
        print(f"  {magenta(mod):20} {n} achado(s)")
    conf = sum(1 for f in findings if f.confidence >= 0.9)
    print(bold(f"\n  total: {len(findings)} achado(s) — {conf} confirmado(s) — {sent} req enviadas\n"))


def print_correlated(correlated: list):
    if not correlated:
        return
    print(bold(cyan("\n─── achados correlacionados (1 por bug) ───")))
    for g in correlated:
        print(f"[{sev_label(g['confidence'])}] {magenta(g['module'].upper())} @ {cyan(g['point'])}"
              f"  {dim('vetores')} {g['vectors']}")
        print(f"    {dim('detectores')} {', '.join(g['detectors'])}"
              f"  {dim('técnicas')} {', '.join(g['techniques'][:8])}")
        if g["evidences"]:
            print(f"    {dim('evidência')}  {green(g['evidences'][0][:200])}")
    print()


def _repro_for(f) -> str:
    return f.repro if getattr(f, "repro", "") else f"curl -sk '{f.url}'"


def confirmed_findings(findings: List[Finding], threshold: float = 0.9) -> List[Finding]:
    """Só o que FUNCIONOU: achados de alta confiança (exclui a sonda de WAF),
    deduplicados por (módulo, ponto, endpoint)."""
    out, seen = [], set()
    for f in findings:
        if f.module == "waf" or f.confidence < threshold:
            continue
        key = (f.module, f.point, (f.url or "").split("?")[0])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def print_confirmed(findings: List[Finding], threshold: float = 0.9):
    """Saída dedicada e VERDE só do que funcionou, com curl de reprodução."""
    conf = confirmed_findings(findings, threshold)
    if not conf:
        print(dim("\n[✓] nenhum achado CONFIRMADO (confiança >= %.2f)." % threshold))
        return
    print(bold(green(f"\n════════════ ✅ CONFIRMADOS — O QUE FUNCIONOU ({len(conf)}) ════════════")))
    for i, f in enumerate(conf, 1):
        print(bold(green(f"\n[{i}] {purpose_of(f.module)}  @ {f.point}   ")) +
              green(f"(confiança {f.confidence:.2f})"))
        print(f"    {dim('URL')}        {f.url}")
        print(f"    {dim('parâmetro')}  {f.point}")
        print(f"    {dim('payload')}    {f.base_payload}"
              + (f"   {dim('(encoder: ' + encoder_desc(f.transform) + ')')}" if f.transform not in ('raw', '-') else ""))
        if f.payload and f.payload != f.base_payload:
            print(f"    {dim('enviado')}    {f.payload[:180]}")
        print(f"    {dim('detecção')}   {', '.join(f.detectors)}")
        print(f"    {dim('evidência')}  {green(f.evidence[:320])}")
        print(bold(green("    ▶ reproduzir manualmente (curl):")))
        print(green(f"      {_repro_for(f)}"))
    print(bold(green("\n════════════════════════════════════════════════════════════")))


def export_poc(findings: List[Finding], path: str, threshold: float = 0.9):
    """Exporta os CONFIRMADOS como Markdown (pronto p/ relatório de bug bounty)."""
    conf = confirmed_findings(findings, threshold)
    out = [f"# ParamHunter — Achados CONFIRMADOS (PoC)\n",
           f"**Total confirmado:** {len(conf)}  ·  confiança mínima: {threshold}\n"]
    for i, f in enumerate(conf, 1):
        out.append(f"\n---\n\n## [{i}] {f.module.upper()} — {purpose_of(f.module)}  @ `{f.point}`\n")
        out.append(f"- **Confiança:** {f.confidence:.2f}")
        out.append(f"- **URL:** {f.url}")
        out.append(f"- **Parâmetro:** `{f.point}`")
        out.append(f"- **Payload (lógico):** `{f.base_payload}`")
        if f.payload and f.payload != f.base_payload:
            out.append(f"- **Enviado (encoded):** `{f.payload}`")
        out.append(f"- **Encoder:** {f.transform} ({encoder_desc(f.transform)})")
        out.append(f"- **Detectores:** {', '.join(f.detectors)}")
        out.append(f"- **Evidência:** {f.evidence}")
        out.append(f"- **Reproduzir manualmente:**\n\n  ```bash\n  {_repro_for(f)}\n  ```")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")


def export_json(findings: List[Finding], path: str):
    data = [f.to_dict() for f in findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def export_jsonl(findings: List[Finding], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")


def export_sarif(findings: List[Finding], path: str):
    """SARIF 2.1.0 — consumível por GitHub code scanning / pipelines."""
    def level(conf):
        return "error" if conf >= 0.9 else ("warning" if conf >= 0.7 else "note")
    rules = {}
    results = []
    for f in findings:
        d = f.to_dict() if isinstance(f, Finding) else f
        rid = d["module"]
        if rid not in rules:
            rules[rid] = {"id": rid, "name": rid,
                          "shortDescription": {"text": f"Possível {rid.upper()}"},
                          "defaultConfiguration": {"level": level(d["confidence"])}}
        results.append({
            "ruleId": rid,
            "level": level(d["confidence"]),
            "message": {"text": f"{rid.upper()} em {d['point']} — {d['evidence'][:300]}"},
            "properties": {"confidence": d["confidence"], "payload": d["base_payload"],
                           "transform": d["transform"], "detectors": d["detectors"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": d["url"].split("?")[0]},
                "region": {"startLine": 1}}}],
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "ParamHunter", "informationUri":
                       "https://local", "version": __version__, "rules": list(rules.values())}},
                       "results": results}]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, ensure_ascii=False, indent=2)
