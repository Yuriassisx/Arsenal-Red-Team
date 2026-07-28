"""
core/correlate.py
=================

Correlação de achados: o mesmo bug costuma ser encontrado por várias vias
(payloads, encoders, detectores, HPP…). Aqui agrupamos por (módulo, parâmetro)
e produzimos UM item consolidado com todas as evidências, técnicas e vetores.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import List, Dict

from modules.base import Finding


def correlate(findings: List) -> List[Dict]:
    fs = [f.to_dict() if isinstance(f, Finding) else f for f in findings]
    groups: "OrderedDict[tuple, dict]" = OrderedDict()

    for f in fs:
        if f["module"] == "waf":
            continue
        endpoint = f["url"].split("?")[0]      # mesmo bug = mesmo endpoint+parâmetro
        key = (f["module"], f["point"], endpoint)
        g = groups.get(key)
        if g is None:
            g = {
                "module": f["module"], "point": f["point"],
                "method": f["method"], "url": f["url"],
                "confidence": f["confidence"],
                "detectors": [], "techniques": [], "payloads": [],
                "evidences": [], "tags": [], "vectors": 0,
            }
            groups[key] = g
        g["vectors"] += 1
        if f["confidence"] > g["confidence"]:
            g["confidence"] = f["confidence"]
            g["url"] = f["url"]            # representa pelo de maior confiança
        for d in f.get("detectors", []):
            if d not in g["detectors"]:
                g["detectors"].append(d)
        if f["transform"] not in g["techniques"]:
            g["techniques"].append(f["transform"])
        if f["base_payload"] and f["base_payload"] not in g["payloads"]:
            g["payloads"].append(f["base_payload"])
        ev = f.get("evidence", "")
        if ev and ev not in g["evidences"]:
            g["evidences"].append(ev)
        for t in f.get("tags", []):
            if t not in g["tags"]:
                g["tags"].append(t)

    out = list(groups.values())
    # trunca listas para o relatório
    for g in out:
        g["techniques"] = g["techniques"][:15]
        g["payloads"] = g["payloads"][:12]
        g["evidences"] = g["evidences"][:6]
    out.sort(key=lambda g: (-g["confidence"], g["module"]))
    return out
