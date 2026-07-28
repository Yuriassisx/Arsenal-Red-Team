"""
core/enum.py
============

Enumeração PASSIVA de URLs/parâmetros de um domínio, alimentando o pipeline
como uma fonte de alvos (igual a --openapi/--crawl). Usa duas ferramentas
externas que mineram ARQUIVOS PÚBLICOS da web (Wayback, CommonCrawl, OTX,
urlscan) — não tocam o alvo:

  - gau         (getallurls): todas as URLs conhecidas do domínio
  - paramspider: URLs COM parâmetros dos arquivos web

O valor agregado aqui é a **normalização/dedup por assinatura**
(host + path + nomes-de-parâmetro): os arquivos devolvem o mesmo endpoint com
centenas de valores diferentes (`?id=1`, `?id=2`, ...) — colapsamos para UM
representante por conjunto de parâmetros. Isso é o que torna `-d dominio`
utilizável com `--full` sem explodir o volume.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

# extensões estáticas sem parâmetro útil — descartadas
STATIC_EXT = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp", ".pdf", ".zip", ".rar",
    ".gz", ".mp3", ".avi", ".mov", ".webm", ".bmp", ".tif", ".tiff", ".m4a",
    ".otf", ".swf", ".apk", ".dmg", ".exe",
}


def have_tools() -> dict:
    """Quais ferramentas de enumeração estão disponíveis no PATH."""
    return {"gau": bool(shutil.which("gau")),
            "paramspider": bool(shutil.which("paramspider"))}


def _in_scope(host: Optional[str], domain: str) -> bool:
    host = (host or "").lower()
    domain = domain.lower().lstrip("*.")
    return host == domain or host.endswith("." + domain)


def _static(path: str) -> bool:
    dot = path.rfind(".")
    return dot != -1 and "/" not in path[dot:] and path[dot:].lower() in STATIC_EXT


def _sig(sp) -> tuple:
    """Assinatura de dedup: host + path + nomes de parâmetro ordenados."""
    names = tuple(sorted(k for k, _ in parse_qsl(sp.query, keep_blank_values=True)))
    return ((sp.hostname or "").lower(), sp.path, names)


def _run(cmd: List[str], timeout: float, cwd: Optional[str] = None) -> List[str]:
    """
    Roda o comando lendo o stdout em STREAMING e mantém o parcial ao bater o
    deadline. Crítico: gau/paramspider em domínios grandes paginam o arquivo por
    muito tempo e NÃO "terminam" dentro do timeout — mas já emitiram milhares de
    URLs. Um subprocess.run(timeout) simples levantaria TimeoutExpired e nós
    perderíamos TUDO. Aqui coletamos o que já saiu (igual a `timeout N gau`).
    """
    import threading
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, cwd=cwd, bufsize=1)
    except OSError:
        return []
    lines: List[str] = []

    def _reader():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip("\n"))
        except Exception:
            pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():          # deadline atingido -> mata e fica com o parcial
        try:
            p.kill()
        except Exception:
            pass
        t.join(3)
    # reap sempre (evita processo zumbi tanto no fim normal quanto após kill)
    try:
        p.wait(timeout=5)
    except Exception:
        pass
    return lines


def gau_urls(domain: str, subs: bool = False, threads: int = 5,
             timeout: float = 180, providers: str = "") -> List[str]:
    if not shutil.which("gau"):
        return []
    cmd = ["gau", "--threads", str(threads), "--timeout", "30",
           "--blacklist", "png,jpg,jpeg,gif,css,js,svg,woff,woff2,ttf,ico,mp4,pdf,webp"]
    if providers:
        # limita as fontes (ex.: "wayback") — útil quando commoncrawl/otx estão fora
        cmd += ["--providers", providers]
    if subs:
        cmd.append("--subs")
    cmd.append(domain)
    return _run(cmd, timeout)


def paramspider_urls(domain: str, timeout: float = 180) -> List[str]:
    if not shutil.which("paramspider"):
        return []
    # -s streama as URLs no stdout; -p 1 usa "1" como valor (evita o marcador FUZZ).
    # roda em cwd temporário porque o paramspider grava results/<dominio>.txt.
    with tempfile.TemporaryDirectory() as tmp:
        lines = _run(["paramspider", "-d", domain, "-s", "-p", "1"], timeout, cwd=tmp)
    return [l for l in lines if l.startswith("http")]


def enumerate_domain(domain: str, *, use_gau: bool = True,
                     use_paramspider: bool = True, subs: bool = False,
                     params_only: bool = True, max_urls: int = 500,
                     timeout: float = 180, providers: str = "",
                     log: Optional[Callable[[str], None]] = None
                     ) -> Tuple[List[str], dict]:
    """
    Retorna (urls_deduplicadas, meta). meta traz contagens por ferramenta,
    total cru e total após dedup. `params_only` mantém só URLs com parâmetro
    (o ParamHunter testa parâmetros); `max_urls` corta o total após o dedup.
    """
    def _log(msg):
        if log:
            log(msg)

    raw: List[str] = []
    meta = {"domain": domain, "gau": 0, "paramspider": 0, "raw": 0, "deduped": 0}

    if use_gau and shutil.which("gau"):
        _log(f"gau: consultando arquivos de {domain}...")
        g = gau_urls(domain, subs=subs, timeout=timeout, providers=providers)
        meta["gau"] = len(g)
        raw += g
        _log(f"gau: {len(g)} URLs")
    if use_paramspider and shutil.which("paramspider"):
        _log(f"paramspider: minerando parâmetros de {domain}...")
        p = paramspider_urls(domain, timeout=timeout)
        meta["paramspider"] = len(p)
        raw += p
        _log(f"paramspider: {len(p)} URLs")

    meta["raw"] = len(raw)
    seen = set()
    out: List[str] = []
    for u in raw:
        u = u.strip()
        if not u.startswith("http"):
            continue
        try:
            sp = urlsplit(u)
        except ValueError:
            continue
        if not _in_scope(sp.hostname, domain):
            continue
        if params_only and not sp.query:
            continue
        if _static(sp.path):
            continue
        sig = _sig(sp)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(u)
        if max_urls and len(out) >= max_urls:
            break

    meta["deduped"] = len(out)
    return out, meta
