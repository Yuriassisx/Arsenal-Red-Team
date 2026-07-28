#!/usr/bin/env python3
"""
paramhunter.py — ponto de entrada CLI

Enumeração de parâmetros vulneráveis + fuzzing de payloads com ampla
diversidade de bypass/encoding, cobrindo LFI, Command Injection, SSRF, SQLi,
XSS, SSTI, Open Redirect e CRLF.

USO SOMENTE EM ALVOS AUTORIZADOS. A trava de escopo bloqueia hosts fora da
allowlist; a flag --yes confirma a autorização legal do teste.
"""
from __future__ import annotations

import os
import sys
import argparse
import asyncio
from typing import List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core import __version__
from core.http_client import HttpClient
from core.scope import Scope
from core.target import from_url, RequestTemplate, VALID_LOCS, LOC_QUERY, LOC_BODY
from core.engine import Scanner, ScanOptions
from core.oob import OOBServer
from core import discovery
from core import reporter as R
from core import importer
from core import openapi as oa
from modules.base import load_modules
from encoders import available as available_transforms

PAYLOAD_DIR = os.path.join(BASE_DIR, "payloads")
DEFAULT_WORDLIST = os.path.join(BASE_DIR, "wordlists", "params.txt")


def parse_kv(items, sep=":"):
    out = {}
    for it in items or []:
        if sep in it:
            k, v = it.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def parse_cookies(raw: str) -> dict:
    out = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def build_args():
    p = argparse.ArgumentParser(
        prog="paramhunter",
        description="Enumeração de parâmetros + fuzzing de payloads (LFI/CMDi/SSRF/SQLi/XSS/SSTI/redirect/CRLF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"ParamHunter {__version__}")
    tgt = p.add_argument_group("alvo")
    tgt.add_argument("-u", "--url", help="URL alvo (use FUZZ ou {nome} no path para injetar no caminho)")
    tgt.add_argument("-l", "--urls-file", help="arquivo com uma URL por linha (lista de alvos)")
    tgt.add_argument("-d", "--domain", action="append", default=[],
                     help="DOMÍNIO: enumera URLs/parâmetros com gau + paramspider "
                          "(arquivos web) e testa tudo — sem precisar passar lista (repetível)")
    tgt.add_argument("-X", "--method", default="GET", help="método HTTP (default GET)")
    tgt.add_argument("--data", help="corpo da requisição (urlencoded ou JSON)")
    tgt.add_argument("-H", "--header", action="append", default=[], help="header 'Nome: Valor' (repetível)")
    tgt.add_argument("-b", "--cookie", default="", help="cookies 'a=b; c=d'")

    au = p.add_argument_group("autenticação (scanning autenticado)")
    au.add_argument("--login-url", help="URL de login — autentica antes do scan e mantém a sessão")
    au.add_argument("--login-data", help="dados do login: 'user=x&pass=y' (form) ou '{\"u\":\"x\"}' (json)")
    au.add_argument("--login-json", action="store_true", help="enviar o login como JSON")
    au.add_argument("--csrf-field", help="nome do campo CSRF a extrair da página de login e reenviar")
    au.add_argument("--auth-marker", help="string que aparece quando LOGADO (verifica login e dispara re-login)")

    ap = p.add_argument_group("API")
    ap.add_argument("--openapi", help="spec OpenAPI 3 / Swagger 2 (arquivo ou URL) — gera 1 alvo por endpoint")
    ap.add_argument("--api-base", help="URL base da API (sobrescreve servers/host da spec)")
    ap.add_argument("--api-methods", default="get,post",
                    help="métodos a gerar da spec (csv). CUIDADO: put/patch/delete mutam dados. default: get,post")
    ap.add_argument("--api-auth", action="append", default=[],
                    help="header de autenticação p/ toda a API, ex.: 'Authorization: Bearer XXX' (repetível)")
    ap.add_argument("--request-file", help="arquivo com request HTTP bruto (estilo Burp) — infere método/headers/corpo")
    ap.add_argument("--request-scheme", default="https", help="esquema p/ --request-file (default https)")
    ap.add_argument("--curl", help="comando cURL entre aspas (copiado do DevTools)")
    ap.add_argument("--curl-file", help="arquivo com um comando cURL")
    ap.add_argument("--graphql", help="endpoint GraphQL: introspection -> fuzza queries/mutations pelas variables")

    ap.add_argument("--websocket", help="endpoint WebSocket (ws://... ) — fuzza mensagens e detecta por assinatura")

    tk = p.add_argument_group("técnicas extras")
    tk.add_argument("--host-header", action="store_true",
                    help="testa Host-header injection (Host/X-Forwarded-Host/... com canário)")
    tk.add_argument("--xxe", action="store_true",
                    help="testa XXE (corpo XML com entidade externa: leitura de arquivo/OOB)")
    tk.add_argument("--mass-assignment", action="store_true",
                    help="testa mass assignment (injeta campos sensíveis no corpo JSON: isAdmin, role...)")
    tk.add_argument("--cache-poison", action="store_true",
                    help="testa web cache poisoning (canário em header não-chaveado + indícios de cache)")
    tk.add_argument("--discover-api", action="store_true",
                    help="descobre campos aceitos no corpo JSON (estilo Arjun p/ JSON)")
    tk.add_argument("--api-wordlist", default=os.path.join(BASE_DIR, "wordlists", "api_fields.txt"),
                    help="wordlist de nomes de campo p/ --discover-api")
    tk.add_argument("--jwt", action="store_true",
                    help="ataca JWTs na requisição (alg=none, segredo fraco, kid injection)")
    tk.add_argument("--headless", action="store_true",
                    help="DOM XSS via chromium headless: payload que SÓ marca se executar no navegador (sem FP)")
    tk.add_argument("--race", action="store_true",
                    help="race condition: rajada concorrente + detecção de estado pré-limite (TOCTOU)")
    tk.add_argument("--race-n", type=int, default=20, help="nº de requisições na rajada de --race (default 20)")
    tk.add_argument("--all-techniques", action="store_true",
                    help="liga HPP + host-header + XXE + mass-assignment + cache-poison de uma vez")

    sc = p.add_argument_group("escopo / autorização")
    sc.add_argument("--scope", action="append", default=[], help="host extra na allowlist (ou *.dominio)")
    sc.add_argument("--deny", action="append", default=[], help="host bloqueado (precedência)")
    sc.add_argument("--yes", action="store_true", help="confirmo que estou AUTORIZADO a testar estes alvos")

    md = p.add_argument_group("módulos / pontos")
    md.add_argument("-m", "--modules", help="módulos a rodar (csv). default: todos")
    md.add_argument("--loc", help=f"localizações de injeção (csv de {sorted(VALID_LOCS)}). default: query,body,json")
    md.add_argument("--api", action="store_true",
                    help="perfil API: injeta em query,json,header,path e amplia a descoberta")
    md.add_argument("--smart", action="store_true",
                    help="inteligência: escolhe módulos por nome do parâmetro (id->sqli/idor, "
                         "redirect->open-redirect/ssrf, cmd->cmdi, file->lfi...) — menos requests/bloqueios")
    md.add_argument("--list-modules", action="store_true", help="lista módulos e sai")
    md.add_argument("--list-transforms", action="store_true", help="lista transforms de bypass e sai")
    md.add_argument("--examples", action="store_true", help="mostra o guia completo de usos e sai")

    dc = p.add_argument_group("descoberta de parâmetros")
    dc.add_argument("--discover", action="store_true", help="enumera parâmetros ocultos antes do fuzzing")
    dc.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="wordlist de nomes de parâmetro")
    dc.add_argument("--discover-loc", default="query", help="onde descobrir: query|body (default query)")
    dc.add_argument("--discover-only", action="store_true", help="apenas descobre parâmetros, não faz fuzzing")
    dc.add_argument("--crawl", action="store_true", help="crawler: segue links/forms e extrai endpoints de JS a partir dos alvos")
    dc.add_argument("--crawl-depth", type=int, default=2, help="profundidade do crawler (default 2)")
    dc.add_argument("--crawl-max", type=int, default=60, help="máx. de páginas do crawler (default 60)")

    dm = p.add_argument_group("enumeração de domínio (-d, via gau + paramspider)")
    dm.add_argument("--enum-subs", action="store_true", help="incluir subdomínios (gau --subs)")
    dm.add_argument("--enum-max", type=int, default=500, help="máx. de URLs após dedup por domínio (default 500)")
    dm.add_argument("--enum-timeout", type=float, default=180, help="timeout por ferramenta de enumeração (s, default 180)")
    dm.add_argument("--enum-all-urls", action="store_true", help="manter também URLs SEM parâmetro (default: só com parâmetro)")
    dm.add_argument("--enum-providers", default="",
                    help="fontes do gau (csv: wayback,commoncrawl,otx,urlscan). "
                         "ex.: 'wayback' p/ pular provedores fora do ar")
    dm.add_argument("--no-gau", action="store_true", help="não usar o gau na enumeração")
    dm.add_argument("--no-paramspider", action="store_true", help="não usar o paramspider na enumeração")

    ob = p.add_argument_group("out-of-band (SSRF / injeção cega)")
    ob.add_argument("--oob", action="store_true", help="sobe listener HTTP embutido p/ callbacks")
    ob.add_argument("--oob-port", type=int, default=8848, help="porta do listener embutido")
    ob.add_argument("--oob-host", help="host/IP público alcançável pelo alvo (default: IP de LAN)")
    ob.add_argument("--oob-domain", help="usar serviço OOB externo (ex.: xxx.interactsh.com); confirmação manual")
    ob.add_argument("--webhook", help="URL do webhook.site (ex.: https://webhook.site/UUID) p/ callbacks OOB — cole a sua; confirmação no painel")

    en = p.add_argument_group("engine")
    en.add_argument("-c", "--concurrency", type=int, default=20, help="requisições concorrentes")
    en.add_argument("--rate", type=float, default=0.0, help="limite de req/s (0=ilimitado)")
    en.add_argument("--timeout", type=float, default=15.0, help="timeout por requisição (s)")
    en.add_argument("--retries", type=int, default=2, help="retries por requisição")
    en.add_argument("--max-response-kb", type=int, default=2000,
                    help="teto do corpo de resposta lido em KB (0=ilimitado; protege memória em endpoints grandes)")
    en.add_argument("--proxy", help="proxy (ex.: http://127.0.0.1:8080 p/ Burp)")
    en.add_argument("--insecure", action="store_true", default=True,
                    help="ignora erros TLS (default; use --secure para verificar certificados)")
    en.add_argument("--secure", action="store_true",
                    help="verifica certificados TLS (por padrão são ignorados)")
    en.add_argument("--http2", action="store_true",
                    help="habilita HTTP/2 (negociado quando o alvo suportar; requer o pacote 'h2')")
    en.add_argument("--max-variants", type=int, default=12, help="variantes de bypass por payload")
    en.add_argument("--threshold", type=float, default=0.5, help="confiança mínima p/ reportar (0..1)")
    en.add_argument("--all-variants", action="store_true", help="não parar no 1º hit forte por payload")
    en.add_argument("--inject-mode", choices=["replace", "append"], default="replace")
    en.add_argument("--verify", action="store_true",
                    help="re-envia o payload vencedor e exige o sinal de novo (corta flukes/FP)")
    en.add_argument("--no-dedup", action="store_true",
                    help="NÃO deduplica requisições idênticas (por padrão, dedup por módulo×ponto)")
    en.add_argument("--no-blind", action="store_true",
                    help="pula payloads time-based (blind sleep) — MUITO mais rápido (cmdi/sqli são "
                         "seriais). Use OOB/--webhook p/ pegar cego sem custo. Mantém erro/reflexão/diff")
    en.add_argument("--time-variants", type=int, default=4,
                    help="teto de variantes de encoding por payload TIME-BASED (default 4; é serial, "
                         "encoding quase não muda se o sleep executa)")
    en.add_argument("--time-endpoint", type=float, default=0,
                    help="tempo MÁXIMO (s) de fuzzing por endpoint; ao esgotar, cancela o que resta "
                         "e passa p/ o próximo (0=sem limite). Evita ficar horas num só alvo")

    ag = p.add_argument_group("MODO AGRESSIVO / bypass")
    ag.add_argument("--full", action="store_true",
                    help="MODO COMPLETO: liga TUDO (agressivo + todas as técnicas + JWT + headless + "
                         "race + crawler + descoberta + verificação + todos os locais). "
                         "PADRÃO: já vem ligado — use --light para desligar.")
    ag.add_argument("--light", action="store_true",
                    help="desliga o modo completo (que é o padrão) e roda um scan leve: "
                         "só os módulos de payload, sem técnicas extras/crawler/descoberta.")
    ag.add_argument("--yes-full", action="store_true",
                    help="confirma o VOLUME do modo completo/agressivo (padrão). Sem esta flag "
                         "(e sem --light), o scan aborta — evita disparo acidental contra produção.")
    ag.add_argument("-A", "--aggressive", action="store_true",
                    help="aplica TODOS os encoders em cada payload + encadeamento + testa todas as variantes")
    ag.add_argument("--chain-depth", type=int, default=1,
                    help="encadear encoders (2 = combina pares, ex.: overlong+double_url). CUIDADO: explode volume")
    ag.add_argument("--encoders",
                    help="encoders extras (csv). aceita nomes, grupos (url,unicode,case,path,cmd,sql,html,space) ou 'all'")
    ag.add_argument("--hpp", action="store_true",
                    help="HTTP Parameter Pollution: testa param=orig&param=payload (2 ordens) em query/body")
    ag.add_argument("--list-groups", action="store_true", help="lista grupos de encoders e sai")

    wf = p.add_argument_group("WAF / evasão adaptativa")
    wf.add_argument("--no-waf-detect", action="store_true", help="desliga a detecção de WAF")
    wf.add_argument("--no-waf-adapt", action="store_true",
                    help="detecta WAF mas NÃO re-testa com evasão (só reporta)")
    wf.add_argument("--evasion-variants", type=int, default=250,
                    help="teto de variantes na fase de evasão (default 250)")
    wf.add_argument("--no-waf-cache", action="store_true",
                    help="não ler/gravar o cache persistente de bypasses aprendidos (~/.hunterparam)")
    wf.add_argument("--waf-cache-file",
                    help="caminho do cache de WAF/bypass (default ~/.hunterparam/waf_cache.json "
                         "ou env HUNTERPARAM_WAF_CACHE)")
    wf.add_argument("--fingerprint", action=argparse.BooleanOptionalAction, default=True,
                    help="fingerprint ATIVO de WAF antes do scan (default: ligado; --no-fingerprint desliga)")
    wf.add_argument("--stealth", action="store_true",
                    help="modo furtivo: desacelera ao detectar bloqueio + jitter + rotação de User-Agent")
    wf.add_argument("--jitter", type=float, default=0.4,
                    help="atraso aleatório por request no modo stealth (s, default 0.4)")

    ot = p.add_argument_group("saída")
    ot.add_argument("-o", "--output", help="exporta findings em JSON")
    ot.add_argument("--jsonl", help="exporta findings em JSONL")
    ot.add_argument("--html", help="gera relatório HTML autocontido")
    ot.add_argument("--sarif", help="exporta findings em SARIF 2.1.0 (GitHub code scanning)")
    ot.add_argument("--poc", nargs="?", const="poc.md", default=None,
                    help="exporta SÓ os CONFIRMADOS (o que funcionou) como Markdown c/ curl "
                         "de reprodução (default poc.md se sem valor)")
    ot.add_argument("--poc-threshold", type=float, default=0.9,
                    help="confiança mínima p/ considerar 'confirmado' na saída de PoC (default 0.9)")
    ot.add_argument("--no-correlate", action="store_true",
                    help="não agrupar achados correlacionados (1 por bug)")
    ot.add_argument("-q", "--quiet", action="store_true", help="menos ruído no console")
    ot.add_argument("--heartbeat", type=float, default=15,
                    help="intervalo (s) do heartbeat de progresso (req/s, pontos, ETA); 0 desliga")
    ot.add_argument("-v", "--verbose", action="count", default=0,
                    help="modo verbose: mostra cada fase e cada requisição enviada. "
                         "-vv adiciona status/tempo/tamanho e o payload de cada request")
    return p


def load_wordlist(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


EXAMPLES = r"""
PARAMHUNTER — GUIA DE USOS
==========================
Todo scan de ataque exige --yes (confirmação de autorização). Use --proxy
http://127.0.0.1:8080 p/ inspecionar no Burp. Combine com -A p/ modo agressivo.

▶ BÁSICO
  # scan de uma URL (todos os módulos, todos os parâmetros)
  paramhunter.py -u 'https://alvo/app?id=1&file=a&q=b' --yes

  # só alguns módulos
  paramhunter.py -u 'https://alvo/p?id=1' -m lfi,sqli,ssrf --yes

  # várias URLs de um arquivo (-l = --urls-file)
  paramhunter.py -l urls.txt --yes -o achados.json

  # lista de alvos no MODO COMPLETO (pace com --rate/-c)
  paramhunter.py -l urls.txt --full --rate 30 -c 15 --yes -o achados.json

▶ ENUMERAÇÃO DE DOMÍNIO (-d)  ★  (gau + paramspider mineram os arquivos web)
  # passa só o DOMÍNIO: mapeia URLs+parâmetros (dedup por endpoint) e testa tudo
  paramhunter.py -d alvo.com --yes -o achados.json
  paramhunter.py -d alvo.com --enum-subs --smart --rate 10 --yes    # + subdomínios
  paramhunter.py -d alvo.com --full --rate 30 -c 15 --yes           # domínio no modo completo
  paramhunter.py -d alvo.com --enum-max 200 --no-paramspider --yes  # só gau, teto 200

▶ POSTS / CORPO
  # corpo urlencoded (vira POST automaticamente)
  paramhunter.py -u https://alvo/login -d 'user=x&pass=y' --yes

  # corpo JSON (injeta em cada campo, inclusive aninhado)
  paramhunter.py -u https://alvo/api -d '{"user":"x","perfil":{"role":"y"}}' --yes

▶ INJEÇÃO NO PATH
  # marcador FUZZ
  paramhunter.py -u 'https://alvo/download/FUZZ' -m lfi --yes
  # marcadores nomeados
  paramhunter.py -u 'https://alvo/users/{id}/files/{name}' --yes

▶ HEADERS / COOKIES / AUTENTICAÇÃO
  paramhunter.py -u https://alvo/api -H 'Authorization: Bearer XXX' \
      -b 'session=abc; role=user' --loc query,json,header,cookie --yes

▶ EXPLORAÇÃO DE API  ★
  # a partir de uma spec OpenAPI/Swagger (gera 1 alvo por endpoint)
  paramhunter.py --openapi https://alvo/openapi.json \
      --api-auth 'Authorization: Bearer XXX' --api --yes

  # spec local, incluindo métodos que mutam (cuidado!)
  paramhunter.py --openapi ./swagger.yaml --api-base https://staging/api \
      --api-methods get,post,put,patch --yes

  # importar request bruto do Burp (infere método/headers/corpo)
  paramhunter.py --request-file req.txt --api --yes

  # importar 'Copy as cURL' do DevTools
  paramhunter.py --curl "curl 'https://alvo/api/v2/user' -H 'Authorization: Bearer X' \
      --data-raw '{\"q\":\"1\"}'" --api --yes

  # GraphQL: introspection -> fuzza queries/mutations pelas variables
  paramhunter.py --graphql https://alvo/graphql -H 'Authorization: Bearer X' --yes

▶ SCANNING AUTENTICADO  ★
  # login (form c/ CSRF), mantém a sessão e re-loga se expirar
  paramhunter.py -u https://alvo/painel?q=x \
      --login-url https://alvo/login --login-data 'user=admin&pass=admin' \
      --csrf-field csrf_token --auth-marker 'Bem-vindo' --yes

▶ DESCOBERTA DE SUPERFÍCIE (crawler)  ★
  paramhunter.py -u https://alvo/ --crawl --crawl-depth 2 --yes   # segue links/forms + endpoints de JS

▶ JWT
  paramhunter.py -u https://alvo/api -H 'Authorization: Bearer eyJ...' --jwt --yes  # alg=none/segredo fraco/kid

▶ DOM XSS (execução real no navegador) e RACE CONDITION  ★
  paramhunter.py -u 'https://alvo/p?q=x' --headless --yes          # chromium headless, sem falso-positivo
  paramhunter.py -u https://alvo/cupom --race --race-n 30 --yes    # rajada concorrente (TOCTOU)

▶ TÉCNICAS EXTRAS  ★
  paramhunter.py -u 'https://alvo/p?id=1' --hpp --yes            # HTTP Parameter Pollution
  paramhunter.py -u https://alvo/reset --host-header --yes       # Host-header injection
  paramhunter.py -u https://alvo/import --xxe --oob --oob-host 10.0.0.5 --yes  # XXE
  paramhunter.py -u https://alvo/api -X POST -d '{"a":1}' --mass-assignment --yes  # mass assignment
  paramhunter.py -u https://alvo/page --cache-poison --yes       # web cache poisoning
  paramhunter.py -u https://alvo/api -X POST -d '{"a":1}' --discover-api --yes  # descobre campos JSON
  paramhunter.py --websocket ws://alvo/socket --yes              # fuzzing WebSocket
  paramhunter.py -u 'https://alvo/p?id=1' --all-techniques --yes # liga o pacote de técnicas

▶ DESCOBERTA DE PARÂMETROS OCULTOS
  paramhunter.py -u https://alvo/page --discover --yes           # descobre e fuzza
  paramhunter.py -u https://alvo/page --discover-only --yes      # só enumera
  paramhunter.py -u https://alvo/page --discover --discover-loc body --yes

▶ MODO COMPLETO (liga TUDO)  ★★
  # agressivo + todas as técnicas + JWT + headless + race + crawler + descoberta
  # + verificação, em todos os locais. Volume MUITO alto — pace com --rate:
  paramhunter.py -u 'https://alvo/app?id=1' --full --rate 30 -c 15 --yes

▶ MODO AGRESSIVO / BYPASS DE ENCODER  ★
  paramhunter.py -u 'https://alvo/p?id=1' -A --yes               # arsenal completo
  paramhunter.py -u 'https://alvo/p?id=1' --encoders url,unicode,best_fit --yes
  paramhunter.py -u 'https://alvo/p?id=1' --encoders poly --yes  # polimórficos
  paramhunter.py -u 'https://alvo/p?id=1' --chain-depth 2 --max-variants 400 --yes

▶ WAF / EVASÃO ADAPTATIVA  ★  (ligado por padrão)
  # ao detectar bloqueio de WAF num parâmetro, re-testa aquele parâmetro com o
  # arsenal de evasão: double/triple encode, polimórfico, poliglota, overlong,
  # best-fit, encadeamento. Identifica o fabricante (Cloudflare/Akamai/...).
  paramhunter.py -u 'https://alvo/p?id=1' --yes                  # adaptativo automático
  paramhunter.py -u 'https://alvo/p?id=1' --no-waf-adapt --yes   # só detecta/reporta
  paramhunter.py -u 'https://alvo/p?id=1' --no-waf-detect --yes  # desliga
  paramhunter.py -u 'https://alvo/p?id=1' --evasion-variants 400 --yes
  # fingerprint ativo (default) identifica o fabricante e escolhe a evasão ideal
  paramhunter.py -u 'https://alvo/p?id=1' --no-fingerprint --yes # desliga a sondagem
  # modo furtivo: desacelera ao ser bloqueado, jitter e rotação de User-Agent
  paramhunter.py -u 'https://alvo/p?id=1' --stealth --rate 5 --yes

▶ INTELIGÊNCIA (--smart)  ★  (menos requests, menos bloqueios)
  # escolhe os módulos por NOME do parâmetro: id->sqli/idor, redirect->open-redirect/ssrf,
  # cmd->cmdi, file->lfi, url->ssrf, q/search->xss/sqli/ssti...
  paramhunter.py -u 'https://alvo/app?id=1&redirect=/x&cmd=ls&file=a' --smart --yes

▶ OUT-OF-BAND (SSRF / injeção cega)
  paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf,cmdi --oob --oob-host 10.0.0.5 --yes
  paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf --oob-domain abc.oast.pro --yes
  # webhook.site: cole a SUA URL aleatória e confira os callbacks no painel
  paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf --webhook https://webhook.site/SEU-UUID --yes

▶ CONTROLE DE VAZÃO / EVASÃO
  paramhunter.py -u ... --rate 20 -c 10 --timeout 20 --yes       # devagar
  paramhunter.py -u ... -H 'X-Forwarded-For: 127.0.0.1' --yes    # spoof de origem

▶ RELATÓRIO / QUALIDADE
  paramhunter.py -u https://alvo/app?id=1 --yes --html report.html   # relatório HTML
  paramhunter.py -u https://alvo/app?id=1 --yes -o out.json --jsonl out.jsonl
  paramhunter.py -u https://alvo/app?id=1 --verify --yes             # re-verifica achados (corta FP)
  paramhunter.py -u https://alvo/app?id=1 --yes -v                   # verbose: cada fase + cada requisição
  paramhunter.py -u https://alvo/app?id=1 --yes -vv                  # + status/tempo/tamanho/payload

▶ INFORMAÇÕES
  paramhunter.py --list-modules      # módulos e detectores (lfi,cmdi,ssrf,sqli,xss,
                                     #   ssti,open_redirect,crlf,nosqli,ldap,xpath)
  paramhunter.py --list-transforms   # todos os encoders
  paramhunter.py --list-groups       # grupos de encoders p/ --encoders
"""


def build_templates(args) -> List[RequestTemplate]:
    """Constrói a lista de RequestTemplate de todas as fontes de entrada."""
    templates: List[RequestTemplate] = []
    headers = parse_kv(args.header)
    cookies = parse_cookies(args.cookie)

    # 1) OpenAPI / Swagger
    if args.openapi:
        spec = oa.load_spec(args.openapi)
        explorer = oa.OpenAPIExplorer(spec, base_override=args.api_base)
        methods = [m.strip() for m in args.api_methods.split(",") if m.strip()]
        auth = parse_kv(args.api_auth)
        auth.update(headers)
        templates += explorer.templates(methods=methods, auth=auth)

    # 1b) GraphQL (introspection -> 1 template por campo)
    if args.graphql:
        from core import graphql as gq
        schema = gq.introspect(args.graphql, headers=headers)
        explorer = gq.GraphQLExplorer(schema, args.graphql, headers=headers)
        templates += explorer.templates()

    # 2) request bruto (Burp)
    if args.request_file:
        with open(args.request_file, "r", encoding="utf-8", errors="ignore") as fh:
            templates.append(importer.from_raw_request(fh.read(), scheme=args.request_scheme))

    # 3) cURL
    curl_cmd = args.curl
    if args.curl_file:
        with open(args.curl_file, "r", encoding="utf-8", errors="ignore") as fh:
            curl_cmd = fh.read()
    if curl_cmd:
        templates.append(importer.from_curl(curl_cmd))

    # 4) URLs diretas
    urls: List[str] = []
    if args.url:
        urls.append(args.url)
    if args.urls_file:
        urls += load_wordlist(args.urls_file)

    # 3b) enumeração de domínio (gau + paramspider) -> vira URLs de alvo
    if args.domain:
        from core import enum
        avail = enum.have_tools()
        if not (avail["gau"] or avail["paramspider"]):
            print(R.red("[enum] nem gau nem paramspider encontrados no PATH — "
                        "instale ao menos um para usar -d/--domain"))
        else:
            def _log(m):
                if not args.quiet:
                    print(R.dim(f"  [enum] {m}"))
            for dom in args.domain:
                found, meta = enum.enumerate_domain(
                    dom, use_gau=not args.no_gau, use_paramspider=not args.no_paramspider,
                    subs=args.enum_subs, params_only=not args.enum_all_urls,
                    max_urls=args.enum_max, timeout=args.enum_timeout,
                    providers=args.enum_providers, log=_log)
                if not args.quiet:
                    print(R.green(f"[enum] {dom}: {meta['raw']} URLs brutas -> "
                                  f"{meta['deduped']} alvos únicos "
                                  f"(gau {meta['gau']}, paramspider {meta['paramspider']})"))
                urls += found

    for u in urls:
        templates.append(from_url(u, method=args.method, headers=headers,
                                  cookies=cookies, data=args.data))
    return templates


async def run(args):
    if not args.quiet:
        R.banner()

    # ---- módulos disponíveis ----
    only = [m.strip() for m in args.modules.split(",")] if args.modules else None
    modules = load_modules(PAYLOAD_DIR, only)

    if args.list_modules:
        for m in load_modules(PAYLOAD_DIR):
            print(f"  {R.magenta(m.name):16} {m.description}")
            print(f"      {R.dim('detectores:')} {', '.join(m.detectors)}  "
                  f"{R.dim('payloads:')} {len(m.payloads)}  "
                  f"{R.dim('transforms:')} {len(m.transforms)}")
        return 0
    if args.examples:
        print(EXAMPLES)
        return 0
    if args.list_transforms:
        if args.verbose:
            from encoders import meta as _tmeta
            for name in available_transforms():
                desc, evd = _tmeta(name)
                print(f"  {R.magenta(name):22} {desc}")
                print(f"  {'':22} {R.dim('evade:')} {evd}")
        else:
            print("  " + ", ".join(available_transforms()))
            print(R.dim("  (use -v/--verbose para ver o que cada um faz e evade)"))
        return 0
    if args.list_groups:
        from encoders import groups
        for g, names in groups().items():
            print(f"  {R.magenta(g):10} {', '.join(names)}")
        print(f"  {R.magenta('all'):10} (todos os {len(available_transforms())} encoders)")
        return 0

    # ---- MODO COMPLETO: liga tudo (PADRÃO; --light desliga) ----
    if not args.light:
        args.full = True
    # gate de VOLUME: full/agressivo é o padrão, mas o volume alto exige uma
    # confirmação explícita (--yes-full) p/ NÃO disparar sem querer contra
    # produção. Aborta ANTES da enumeração (falha rápido, sem tocar arquivos web).
    if args.full and not args.yes_full:
        print(R.red(R.bold(
            "[FULL] o modo completo/agressivo é o PADRÃO e dispara MILHARES de payloads "
            "de ataque (400 variantes × todas as técnicas × crawl/discover).")))
        print(R.yellow(
            "      Confirme o volume com  --yes-full  (junto de --yes),\n"
            "      OU rode leve com       --light     (12 variantes, só o módulo pedido)."))
        return 3
    if args.full:
        args.aggressive = True
        args.hpp = args.host_header = args.xxe = True
        args.mass_assignment = args.cache_poison = True
        args.jwt = args.headless = args.race = True
        args.crawl = args.discover = args.discover_api = True
        args.verify = True
        if not args.loc:
            args.loc = "query,body,json,header,cookie,path"
        if not args.quiet:
            print(R.red(R.bold("[FULL] modo completo — TODAS as técnicas ativas. "
                               "Volume de requisições MUITO alto; use --rate/-c e só em escopo autorizado.")))
        # OOB não é auto-ligado (precisa do SEU endpoint de callback). Sem ele,
        # as detecções CEGAS (SSRF/CMDi/XXE via callback) são puladas.
        if not (args.oob or args.oob_domain or args.webhook) and not args.quiet:
            print(R.yellow(R.bold(
                "[FULL] sem OOB configurado → SSRF cego, command-injection cego e "
                "XXE-OOB serão PULADOS. Para o full DE VERDADE, adicione um callback:")))
            print(R.yellow(
                "       --webhook https://webhook.site/<seu-uuid>   (mais fácil)\n"
                "       --oob --oob-host <ip-publico-alcancavel>    (listener embutido)\n"
                "       --oob-domain <sub.interactsh.com>           (interactsh/Collaborator)"))

    # ---- alvos (URL / OpenAPI / request bruto / cURL) ----
    try:
        templates = build_templates(args)
    except Exception as e:  # noqa: BLE001
        print(R.red(f"erro ao montar alvos: {e}"))
        return 2
    if not templates and not args.websocket:
        print(R.red("erro: informe um alvo (-u/--url, -l/--urls-file, -d/--domain, --openapi, --request-file, --curl ou --websocket)"))
        return 2

    # ---- escopo ----
    scope = Scope(allow=args.scope, deny=args.deny)
    for t in templates:
        scope.add_target(t.base_url)
    if args.websocket:
        scope.add_target(args.websocket.replace("ws://", "http://").replace("wss://", "https://"))
    if not args.quiet:
        print(R.dim(f"[escopo] {scope.describe()}"))
        print(R.dim(f"[alvos] {len(templates)} requisição(ões) a testar"))

    # ---- gate de autorização ----
    if not args.yes:
        print(R.yellow(
            "\n[!] Esta ferramenta envia payloads de ATAQUE. Rode SOMENTE contra "
            "sistemas que você está autorizado a testar."))
        print(R.yellow("    Confirme com --yes para prosseguir.\n"))
        return 3

    # ---- OOB ----
    oob_server = None
    uses_oob = any(m.uses_oob for m in modules)
    if args.webhook:
        oob_server = OOBServer(webhook_url=args.webhook)
        if not args.quiet:
            print(R.yellow(f"[oob] webhook.site: {oob_server.base}/<token> "
                           "— confira os callbacks no painel do webhook.site"))
    elif args.oob or args.oob_domain:
        if args.oob_domain:
            oob_server = OOBServer(public_host=args.oob_domain, external=True)
            if not args.quiet:
                print(R.dim(f"[oob] externo: *.{args.oob_domain} (confirmação manual no serviço)"))
        else:
            oob_server = OOBServer(port=args.oob_port, public_host=args.oob_host)
            await oob_server.start()
            if not args.quiet:
                print(R.dim(f"[oob] listener embutido em http://{oob_server.base}/<token>"))
    elif uses_oob and not args.quiet:
        print(R.dim("[oob] módulos com OOB carregados; use --oob, --webhook ou --oob-domain p/ ativá-los"))

    # ---- verbose: logger de fases (on_event) e de requisições (logfn) ----
    def vlog(level, msg):
        if args.verbose >= level:
            print(R.dim(f"    · {msg}"))

    def req_log(line):
        # cada requisição enviada (payload) — cor por classe de status
        st = line[:3].strip()
        head = line[:3]
        color = (R.green if st.startswith("2") else R.yellow if st[:1] in ("3", "4")
                 else R.red if (st.isdigit() or st == "ERR") else R.dim)
        print(R.dim("      → ") + color(head) + R.dim(line[3:]))

    # ---- client ----
    # stealth: concorrência baixa por padrão para reduzir pegada
    concurrency = args.concurrency
    if args.stealth and concurrency > 5:
        concurrency = 5
    client = HttpClient(
        concurrency=concurrency, rate=args.rate, timeout=args.timeout,
        retries=args.retries, proxy=args.proxy, verify_tls=args.secure,
        default_headers=parse_kv(args.header),
        stealth=args.stealth, jitter=args.jitter,
        max_response_bytes=max(0, args.max_response_kb) * 1024,
        http2=args.http2,
        verbose=args.verbose, logfn=(req_log if args.verbose else None),
    )
    if args.verbose:
        print(R.dim(f"[verbose] nível {args.verbose} — logando "
                    + ("fases + cada requisição" if args.verbose == 1
                       else "fases + cada requisição + status/tempo/payload")))
    if args.stealth and not args.quiet:
        print(R.yellow(f"[stealth] modo furtivo: conc={concurrency} jitter={args.jitter}s "
                       f"— desacelera ao ser bloqueado + rotação de User-Agent"))

    # ---- autenticação (login antes do scan; sessão mantida no cookie-jar) ----
    authenticator = None
    if args.login_url:
        from core.auth import Authenticator
        authenticator = Authenticator(
            client, args.login_url, args.login_data or "",
            json_mode=args.login_json, csrf_field=args.csrf_field,
            marker=args.auth_marker, headers=parse_kv(args.header))
        ok, info = await authenticator.login()
        if not args.quiet:
            tag = R.green("[auth] login OK") if ok else R.red("[auth] login FALHOU")
            print(f"{tag} ({info}) — {args.login_url}")
        if not ok:
            print(R.yellow("    aviso: seguindo mesmo assim; verifique --login-data/--auth-marker"))

    # modo agressivo: se o usuário não subiu o teto de variantes, elevamos;
    # e testamos todas as variantes (não paramos no 1º hit).
    max_variants = args.max_variants
    all_variants = args.all_variants
    chain_depth = args.chain_depth
    if args.aggressive:
        if max_variants == 12:            # ainda no default -> turbina
            max_variants = 400
        all_variants = True
        if chain_depth < 2:
            chain_depth = 2

    # --all-techniques liga o pacote de técnicas de uma vez
    if args.all_techniques:
        args.hpp = args.host_header = args.xxe = True
        args.mass_assignment = args.cache_poison = True

    extra = [e.strip() for e in args.encoders.split(",")] if args.encoders else []

    opts = ScanOptions(
        max_variants=max_variants, threshold=args.threshold,
        all_variants=all_variants, inject_mode=args.inject_mode,
        aggressive=args.aggressive, chain_depth=chain_depth,
        extra_transforms=extra,
        waf_detect=not args.no_waf_detect,
        waf_adapt=not (args.no_waf_adapt or args.no_waf_detect),
        evasion_max_variants=args.evasion_variants,
        verify=args.verify,
        hpp=args.hpp,
        waf_cache=not args.no_waf_cache,
        waf_cache_path=args.waf_cache_file or "",
        dedup=not args.no_dedup,
        blind=not args.no_blind,
        time_variants=max(1, args.time_variants),
    )
    if args.aggressive and not args.quiet:
        from encoders import available as _av
        print(R.yellow(R.bold(
            f"[AGRESSIVO] {len(_av())} encoders x encadeamento profundidade {chain_depth} "
            f"x até {max_variants} variantes/payload — volume de requisições ALTO")))

    all_findings = []
    seen_keys = set()
    interrupted = False

    def on_finding(f):
        # inclui os detectores na chave: um mesmo payload pode ser confirmado por
        # vias distintas (ex.: diff durante o scan + OOB resolvido depois) e as
        # duas evidências devem aparecer — a OOB não pode ser engolida pela diff.
        key = (f.module, f.point, f.base_payload, tuple(sorted(map(str, f.detectors))))
        if key in seen_keys:
            return
        seen_keys.add(key)
        all_findings.append(f)
        if not args.quiet:
            R.print_finding(f)

    scanner = Scanner(client, scope, opts, oob_server=oob_server,
                      on_finding=on_finding, on_event=(vlog if args.verbose else None))
    scanner.authenticator = authenticator

    # ---- crawler: descobre superfície a partir dos alvos-semente ----
    if args.crawl:
        from core import crawler
        seeds = [t.base_url for t in templates] + ([args.url] if args.url else [])
        pu, forms = await crawler.crawl(client, scope, seeds, max_pages=args.crawl_max,
                                        max_depth=args.crawl_depth, headers=parse_kv(args.header))
        for u in pu:
            templates.append(from_url(u, headers=parse_kv(args.header),
                                      cookies=parse_cookies(args.cookie)))
        templates += forms
        if not args.quiet:
            print(R.green(f"[crawl] +{len(pu)} URLs c/ parâmetros, +{len(forms)} forms descobertos"))

    if args.loc:
        locs = [l.strip() for l in args.loc.split(",")]
    elif args.api or args.openapi:
        locs = [LOC_QUERY, "json", "header", "path", LOC_BODY]
    else:
        locs = [LOC_QUERY, LOC_BODY, "json"]

    # ---- Ctrl-C gracioso: relatório PARCIAL em vez de perder o trabalho ----
    # Um SIGINT durante asyncio.run() é entregue ao event loop (não é injetado na
    # corrotina), então um try/except aqui dentro NÃO o veria. Registramos um
    # handler no loop que cancela o fuzzing pendente e deixa run() seguir para o
    # relatório/exports. 2º Ctrl-C força a saída imediata.
    import signal as _signal
    _loop = asyncio.get_running_loop()

    def _graceful_sigint():
        nonlocal interrupted
        if interrupted:                       # 2º Ctrl-C -> saída forçada
            raise KeyboardInterrupt
        interrupted = True
        if not args.quiet:
            print(R.yellow(R.bold("\n[!] interrompido — finalizando e gerando relatório "
                                  "parcial com o que já foi encontrado (Ctrl-C de novo p/ forçar)...")))
        cur = asyncio.current_task(_loop)
        for t in asyncio.all_tasks(_loop):
            if t is not cur:
                t.cancel()

    try:
        _loop.add_signal_handler(_signal.SIGINT, _graceful_sigint)
    except (NotImplementedError, RuntimeError):
        _loop = None                          # plataforma sem add_signal_handler (Windows)

    # ---- HEARTBEAT de progresso (req/s, pontos concluídos, ETA) ----
    import time as _time
    progress = {"targets_done": 0, "targets_total": len(templates),
                "points_done": 0, "points_total": 0}
    _scan_t0 = _time.monotonic()

    def _fmt(sec):
        sec = int(max(0, sec))
        h, r = divmod(sec, 3600)
        m, s = divmod(r, 60)
        return (f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}")

    async def _heartbeat():
        while True:
            await asyncio.sleep(max(1.0, args.heartbeat))
            el = _time.monotonic() - _scan_t0
            rate = client.sent / el if el > 0 else 0.0
            pd, pt = progress["points_done"], progress["points_total"]
            eta = ""
            if pd > 0 and pt > pd:
                eta = f" · ETA ~{_fmt((el / pd) * (pt - pd))}"
            elif pt and pd >= pt:
                eta = " · finalizando"
            print(R.cyan(f"  [♥ {_fmt(el)}] {client.sent} req · {rate:.0f} req/s · "
                         f"alvo {progress['targets_done']}/{progress['targets_total']} · "
                         f"pontos {pd}/{pt or '?'} · {len(all_findings)} achado(s){eta}"))

    hb_task = None
    if args.heartbeat > 0 and not args.quiet:
        hb_task = asyncio.ensure_future(_heartbeat())

    try:
        # ---- WebSocket (fluxo próprio) ----
        if args.websocket:
            from core import websocket as wsmod
            if not args.quiet:
                print(R.bold(R.cyan(f"\n══ WebSocket: {args.websocket} ══")))
            try:
                await wsmod.scan_ws(args.websocket, headers=parse_kv(args.header),
                                    on_finding=on_finding)
            except Exception as e:  # noqa: BLE001
                print(R.red(f"[ws] erro: {e}"))

        for template in templates:
            if not args.quiet:
                print(R.bold(R.cyan(f"\n══ alvo: {template.method} {template.base_url} ══")))

            # ---- descoberta de campos de API (corpo JSON) ----
            if args.discover_api and isinstance(template.json_body, dict):
                wl = load_wordlist(args.api_wordlist)
                fields = await discovery.discover_json_fields(template, client, wl)
                R.print_discovery("json", fields)
                for name in fields:
                    template.json_body.setdefault(name, "1")

            # ---- descoberta ----
            if args.discover or args.discover_only:
                dloc = LOC_BODY if args.discover_loc == "body" else LOC_QUERY
                wl = load_wordlist(args.wordlist)
                found = await discovery.discover(template, client, wl, location=dloc)
                # extrai também do HTML da resposta base
                base_resp = await client.send(template.baseline())
                found += sorted(discovery.extract_params(base_resp.text) - set(found))
                R.print_discovery(args.discover_loc, found)
                for name in found:
                    if dloc == LOC_BODY:
                        template.body.setdefault(name, "1")
                    else:
                        template.query.setdefault(name, "1")

            if args.discover_only:
                continue

            points = template.points(locs)
            if not points:
                # injeta um parâmetro sintético p/ permitir teste mesmo sem params
                template.query.setdefault("id", "1")
                points = template.points(locs)
            if not args.quiet:
                print(R.dim(f"[pontos] {', '.join(str(p) for p in points) or '(nenhum)'}"))

            # ---- fingerprint ATIVO de WAF (antes do fuzzing) ----
            if args.fingerprint and not args.no_waf_detect and points:
                fp = await scanner.fingerprint(template, points[0])
                if fp and fp[0]:
                    vend = fp[1] or "genérico"
                    if not args.quiet:
                        print(R.yellow(R.bold(f"[fingerprint] WAF detectado: {vend}"))
                              + R.dim(" — evasão será priorizada por fabricante"))

            # ---- técnicas extras (por alvo) ----
            # com --smart, as técnicas são decididas pelo CONTEXTO do alvo
            # (xxe só em XML, mass-assignment só em JSON, cache/host-header sempre).
            # As flags explícitas (--xxe etc.) continuam forçando a execução.
            smart_tech = set()
            if args.smart:
                from core import intel
                smart_tech = intel.smart_techniques(template, [p.name for p in points])
                if not args.quiet:
                    print(R.dim(f"  [smart] técnicas: {', '.join(sorted(smart_tech))}"))
            if args.host_header or "host_header" in smart_tech:
                vlog(1, "técnica: host-header injection")
                await scanner.scan_host_header(template)
            if args.xxe or "xxe" in smart_tech:
                vlog(1, "técnica: XXE")
                await scanner.scan_xxe(template)
            if args.mass_assignment or "mass_assignment" in smart_tech:
                vlog(1, "técnica: mass assignment")
                await scanner.scan_mass_assignment(template)
            if args.cache_poison or "cache_poison" in smart_tech:
                vlog(1, "técnica: web cache poisoning")
                await scanner.scan_cache_poison(template)
            # JWT: se pedido explícito, ou (smart) quando há um JWT na requisição
            if args.jwt or args.smart:
                from core.jwt import JWTScanner, find_jwts
                if args.jwt or find_jwts(template):
                    vlog(1, "técnica: JWT (alg=none/segredo fraco/kid)")
                    await JWTScanner(client, on_finding=on_finding).scan(template, scope)
            # DOM XSS via headless (execução real no navegador)
            if args.headless:
                from core.dom import DOMScanner, chromium_path
                if chromium_path():
                    vlog(1, "técnica: DOM XSS (chromium headless)")
                    await DOMScanner(scope, on_finding=on_finding).scan(template)
                elif not args.quiet:
                    print(R.yellow("[headless] chromium não encontrado — pulei DOM XSS"))
            # race condition (rajada concorrente)
            if args.race:
                from core.race import RaceScanner
                vlog(1, f"técnica: race condition ({args.race_n} req concorrentes)")
                await RaceScanner(client, scope, on_finding=on_finding, n=args.race_n).scan(template)

            # ---- fuzzing: módulo × ponto ----
            vlog(1, f"▶ FUZZING: {len(modules)} módulo(s) × {len(points)} ponto(s) "
                    f"= {len(modules) * len(points)} combinações")
            sem = asyncio.Semaphore(max(2, args.concurrency // 4))

            async def do(mod, pt):
                async with sem:
                    await scanner.scan_point(mod, template, pt)
                progress["points_done"] += 1

            async def do_idor(pt):
                async with sem:
                    await scanner.scan_idor(template, pt)
                progress["points_done"] += 1

            async def _run_budgeted(tasks, tgt):
                """Roda o fuzzing do endpoint com teto de tempo (--time-endpoint)."""
                if args.time_endpoint and args.time_endpoint > 0:
                    gathered = asyncio.gather(*tasks)
                    try:
                        await asyncio.wait_for(gathered, timeout=args.time_endpoint)
                    except asyncio.TimeoutError:
                        if not args.quiet:
                            print(R.yellow(f"  [⏱ timeout] endpoint {tgt}: "
                                           f"{args.time_endpoint:.0f}s esgotados — "
                                           f"pulando p/ o próximo"))
                else:
                    await asyncio.gather(*tasks)

            if args.smart:
                # inteligência: por parâmetro, só os módulos relevantes ao nome
                from core import intel
                avail = [m.name for m in modules]
                bymod = {m.name: m for m in modules}
                tasks = []
                for pt in points:
                    chosen = intel.select(pt.name, avail)
                    for mn in chosen:
                        tasks.append(do(bymod[mn], pt))
                    if "idor" in intel.techniques(pt.name):
                        tasks.append(do_idor(pt))
                    if not args.quiet:
                        print(R.dim(f"  [smart] {pt} -> {', '.join(sorted(chosen))}"
                                    + (" +idor" if 'idor' in intel.techniques(pt.name) else "")))
                progress["points_total"] += len(tasks)
                await _run_budgeted(tasks, template.base_url)
            else:
                tasks = [do(mod, pt) for mod in modules for pt in points]
                # modo full: IDOR também, nos parâmetros id-like
                if args.full:
                    from core import intel
                    tasks += [do_idor(pt) for pt in points if "idor" in intel.techniques(pt.name)]
                progress["points_total"] += len(tasks)
                await _run_budgeted(tasks, template.base_url)
            progress["targets_done"] += 1

        # ---- resolve OOB pendentes ----
        if oob_server is not None and not oob_server.external:
            if not args.quiet:
                print(R.dim(f"\n[oob] aguardando {opts.oob_grace:.0f}s por callbacks..."))
            await scanner.resolve_oob()

    except (KeyboardInterrupt, asyncio.CancelledError):
        # o handler de SIGINT já sinalizou 'interrupted' e cancelou as tarefas de
        # fuzzing; o gather propaga CancelledError até aqui e caímos no relatório
        # parcial. Se veio de outra origem (não a interrupção), repropaga.
        if not interrupted:
            raise
    finally:
        if hb_task:
            hb_task.cancel()
        # persiste o aprendizado de WAF/bypass p/ acelerar o próximo scan
        try:
            scanner.save_cache()
        except Exception:   # noqa: BLE001 — cache é otimização, nunca fatal
            pass
        if _loop is not None:
            try:
                _loop.remove_signal_handler(_signal.SIGINT)
            except (NotImplementedError, RuntimeError, ValueError):
                pass
        await client.aclose()
        if oob_server is not None and not oob_server.external:
            await oob_server.stop()

    # ---- correlação ----
    correlated = []
    if not args.no_correlate:
        from core import correlate as corr
        correlated = corr.correlate(all_findings)

    # ---- relatório ----
    if not args.quiet:
        if interrupted:
            print(R.yellow(R.bold("  (scan interrompido — resultados PARCIAIS)")))
        R.summary(all_findings, client.sent)
        if correlated:
            R.print_correlated(correlated)
        if scanner.known_waf:
            waflist = ", ".join(f"{h} [{v}]" for h, v in scanner.known_waf.items())
            print(R.yellow(f"  WAF por rota: {waflist}"))
        # ---- SAÍDA DEDICADA: só o que FUNCIONOU (verde + curl de reprodução) ----
        R.print_confirmed(all_findings, threshold=args.poc_threshold)
    if args.poc:
        R.export_poc(all_findings, args.poc, threshold=args.poc_threshold)
        print(R.green(f"[+] PoC (confirmados) salvo em {args.poc}"))
    if args.output:
        R.export_json(all_findings, args.output)
        print(R.green(f"[+] JSON salvo em {args.output}"))
    if args.jsonl:
        R.export_jsonl(all_findings, args.jsonl)
        print(R.green(f"[+] JSONL salvo em {args.jsonl}"))
    if args.sarif:
        R.export_sarif(all_findings, args.sarif)
        print(R.green(f"[+] SARIF salvo em {args.sarif}"))
    if args.html:
        from core import report_html
        meta = {"targets": len(templates), "sent": client.sent,
                "waf": scanner.known_waf, "bypasses": scanner.host_bypasses,
                "correlated": correlated}
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report_html.render(all_findings, meta))
        print(R.green(f"[+] HTML salvo em {args.html}"))

    return 0 if not all_findings else 1


def main():
    args = build_args().parse_args()
    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\ninterrompido.")
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
