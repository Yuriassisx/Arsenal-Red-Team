"""
core/waf_cache.py
=================

Persistência ENTRE EXECUÇÕES do aprendizado de WAF/bypass.

A engine já aprende, DENTRO de um run, quais encoders furam o WAF de cada host
(`host_bypasses`, move-to-front) e qual o fabricante (`known_waf`). Mas isso
morre quando o processo termina. Este módulo guarda esse conhecimento em disco,
por HOST, e devolve no próximo run:

  - vendor  -> dica de fabricante (só ENRIQUECE o rótulo quando um WAF é de fato
               detectado no run atual; NUNCA dispara escalada sozinho — senão
               viraria falso-positivo de WAF em host que hoje não bloqueia).
  - bypasses-> encoders que já furaram, tentados PRIMEIRO no próximo scan. Isso
               faz a evasão convergir mais rápido e mandar MENOS requisição —
               desejável tanto por desempenho quanto por rate-limit de programa.

Arquivo default: ~/.hunterparam/waf_cache.json
Override pela env HUNTERPARAM_WAF_CACHE (ou opção --waf-cache-file no CLI).

Best-effort: qualquer erro de IO/JSON é silencioso. O cache é OTIMIZAÇÃO, não
estado crítico — se corromper ou sumir, o scan roda normalmente do zero.
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Tuple

CACHE_VERSION = 1
MAX_BYPASSES = 12          # espelha o teto de host_bypasses na engine
MAX_HOSTS = 2000           # não deixa o arquivo crescer sem limite


def default_path() -> str:
    env = os.environ.get("HUNTERPARAM_WAF_CACHE")
    if env:
        return env
    base = os.path.join(os.path.expanduser("~"), ".hunterparam")
    return os.path.join(base, "waf_cache.json")


def load(path: str | None = None) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Carrega (host->vendor, host->[bypasses]). Devolve ({}, {}) em qualquer erro."""
    path = path or default_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}, {}
    if not isinstance(data, dict):
        return {}, {}
    hosts = data.get("hosts", {})
    if not isinstance(hosts, dict):
        return {}, {}
    vendor: Dict[str, str] = {}
    bypasses: Dict[str, List[str]] = {}
    for host, rec in hosts.items():
        if not isinstance(host, str) or not isinstance(rec, dict):
            continue
        v = rec.get("vendor")
        if isinstance(v, str) and v:
            vendor[host] = v
        bp = rec.get("bypasses")
        if isinstance(bp, list):
            clean = [str(x) for x in bp if isinstance(x, str) and x]
            if clean:
                bypasses[host] = clean[:MAX_BYPASSES]
    return vendor, bypasses


def save(vendor: Dict[str, str], bypasses: Dict[str, List[str]],
         path: str | None = None) -> bool:
    """
    Persiste o conhecimento acumulado. Faz MERGE com o que já está em disco
    (outro scan pode ter aprendido sobre hosts diferentes). Escrita atômica via
    arquivo temporário + os.replace. Devolve True se gravou.
    """
    path = path or default_path()

    # merge com o disco: preserva aprendizado de hosts não tocados neste run
    disk_vendor, disk_bypasses = load(path)
    disk_vendor.update({h: v for h, v in vendor.items() if v})
    for host, bp in bypasses.items():
        if bp:
            disk_bypasses[host] = bp[:MAX_BYPASSES]

    hosts: Dict[str, dict] = {}
    for host in set(disk_vendor) | set(disk_bypasses):
        rec: dict = {}
        if disk_vendor.get(host):
            rec["vendor"] = disk_vendor[host]
        if disk_bypasses.get(host):
            rec["bypasses"] = disk_bypasses[host][:MAX_BYPASSES]
        if rec:
            rec["updated"] = int(time.time())
            hosts[host] = rec

    # poda: se passou do teto, mantém os mais recentemente atualizados
    if len(hosts) > MAX_HOSTS:
        keep = sorted(hosts.items(), key=lambda kv: kv[1].get("updated", 0),
                      reverse=True)[:MAX_HOSTS]
        hosts = dict(keep)

    payload = {"version": CACHE_VERSION, "hosts": hosts}
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return True
    except OSError:
        return False
