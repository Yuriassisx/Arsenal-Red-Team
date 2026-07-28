"""
core/report_html.py
====================

Relatório HTML autocontido (CSS inline, tema escuro), agrupado por endpoint e
severidade, com sumário de módulos, WAF detectado e cache de bypass por host.
"""
from __future__ import annotations

import html
import time
from typing import List, Dict
from collections import defaultdict

from modules.base import Finding


def _sev(conf: float):
    if conf >= 0.9:
        return ("CONFIRMADO", "#ff4d4d")
    if conf >= 0.7:
        return ("PROVÁVEL", "#ffb020")
    return ("SUSPEITO", "#4d9dff")


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def render(findings: List[Finding], meta: Dict) -> str:
    fs = [f.to_dict() if isinstance(f, Finding) else f for f in findings]
    vulns = [f for f in fs if f["module"] != "waf"]
    wafs = [f for f in fs if f["module"] == "waf"]

    by_mod = defaultdict(int)
    for f in vulns:
        by_mod[f["module"]] += 1
    conf_n = sum(1 for f in vulns if f["confidence"] >= 0.9)
    prov_n = sum(1 for f in vulns if 0.7 <= f["confidence"] < 0.9)
    susp_n = sum(1 for f in vulns if f["confidence"] < 0.7)

    # agrupa por endpoint (url sem query) + módulo
    groups = defaultdict(list)
    for f in vulns:
        ep = f["url"].split("?")[0]
        groups[ep].append(f)

    gen = time.strftime("%Y-%m-%d %H:%M:%S")
    parts: List[str] = []
    parts.append(f"""<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ParamHunter — Relatório</title><style>
:root{{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#c9d1d9;--dim:#8b949e;--ac:#58a6ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:16px;border-bottom:1px solid var(--bd);
padding-bottom:6px;margin:28px 0 12px}}
.sub{{color:var(--dim);margin-bottom:20px}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:8px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;min-width:120px}}
.card .n{{font-size:26px;font-weight:700}}.card .l{{color:var(--dim);font-size:12px}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#000}}
.pill{{display:inline-block;background:#21262d;border:1px solid var(--bd);border-radius:10px;
padding:1px 8px;font-size:11px;color:var(--dim);margin-right:4px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);
border-radius:8px;overflow:hidden;margin-bottom:8px}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}
th{{background:#1c2128;color:var(--dim);font-size:12px;text-transform:uppercase}}
td.p{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#e6edf3;
word-break:break-all;max-width:340px}}
td.ev{{color:#7ee787;font-family:ui-monospace,monospace;font-size:12px;word-break:break-all;max-width:320px}}
.ep{{color:var(--ac);font-family:ui-monospace,monospace;font-size:13px}}
.waf{{background:#3d2b00;border:1px solid #ffb020;color:#ffd580;border-radius:8px;padding:10px 14px;margin-bottom:8px}}
.mut{{color:var(--dim)}}code{{background:#21262d;padding:1px 5px;border-radius:4px}}
footer{{color:var(--dim);margin-top:32px;font-size:12px}}
</style></head><body><div class="wrap">""")

    parts.append(f"<h1>ParamHunter — Relatório de varredura</h1>")
    parts.append(f'<div class="sub">gerado em {gen} · '
                 f'{_e(meta.get("targets", 0))} alvo(s) · '
                 f'{_e(meta.get("sent", 0))} requisições enviadas</div>')

    # cards de resumo
    parts.append('<div class="cards">')
    parts.append(f'<div class="card"><div class="n">{len(vulns)}</div><div class="l">achados</div></div>')
    parts.append(f'<div class="card"><div class="n" style="color:#ff4d4d">{conf_n}</div><div class="l">confirmados</div></div>')
    parts.append(f'<div class="card"><div class="n" style="color:#ffb020">{prov_n}</div><div class="l">prováveis</div></div>')
    parts.append(f'<div class="card"><div class="n" style="color:#4d9dff">{susp_n}</div><div class="l">suspeitos</div></div>')
    parts.append('</div>')
    if by_mod:
        parts.append('<div class="cards">')
        for m, n in sorted(by_mod.items(), key=lambda x: -x[1]):
            parts.append(f'<span class="pill">{_e(m)}: {n}</span>')
        parts.append('</div>')

    # WAF
    waf_meta = meta.get("waf") or {}
    byp = meta.get("bypasses") or {}
    if wafs or waf_meta:
        parts.append("<h2>WAF / evasão</h2>")
        for host, vend in waf_meta.items():
            b = byp.get(host) or []
            bt = (" · bypasses eficazes: <code>" + _e(", ".join(b[:6])) + "</code>") if b else ""
            parts.append(f'<div class="waf"><b>{_e(host)}</b> → {_e(vend)}{bt}</div>')

    # achados correlacionados (1 por bug)
    correlated = meta.get("correlated") or []
    if correlated:
        parts.append("<h2>Achados correlacionados (1 por bug)</h2>")
        parts.append("<table><tr><th>sev</th><th>módulo</th><th>parâmetro</th>"
                     "<th>vetores</th><th>detectores</th><th>técnicas</th></tr>")
        for g in correlated:
            label, color = _sev(g["confidence"])
            parts.append(
                f'<tr><td><span class="badge" style="background:{color}">{label}</span></td>'
                f'<td>{_e(g["module"])}</td><td>{_e(g["point"])}</td>'
                f'<td>{_e(g["vectors"])}</td>'
                f'<td class="mut">{_e(", ".join(g["detectors"]))}</td>'
                f'<td class="mut">{_e(", ".join(g["techniques"][:10]))}</td></tr>'
            )
        parts.append("</table>")

    # achados por endpoint (todos os vetores)
    parts.append("<h2>Achados (todos os vetores)</h2>")
    if not vulns:
        parts.append('<p class="mut">Nenhum achado de vulnerabilidade.</p>')
    for ep in sorted(groups):
        rows = sorted(groups[ep], key=lambda f: -f["confidence"])
        parts.append(f'<div class="ep">{_e(ep)}</div>')
        parts.append("<table><tr><th>sev</th><th>módulo</th><th>parâmetro</th>"
                     "<th>payload</th><th>encoder</th><th>evidência</th></tr>")
        for f in rows:
            label, color = _sev(f["confidence"])
            parts.append(
                f'<tr><td><span class="badge" style="background:{color}">{label}</span></td>'
                f'<td>{_e(f["module"])}</td>'
                f'<td>{_e(f["point"])}</td>'
                f'<td class="p">{_e(f["base_payload"][:160])}</td>'
                f'<td class="mut">{_e(f["transform"])}</td>'
                f'<td class="ev">{_e(f["evidence"][:220])}</td></tr>'
            )
        parts.append("</table>")

    parts.append('<footer>ParamHunter · uso restrito a testes autorizados.</footer>')
    parts.append("</div></body></html>")
    return "".join(parts)
