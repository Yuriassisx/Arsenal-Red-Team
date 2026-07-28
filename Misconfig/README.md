# misconfig.py

**Scanner ofensivo, single-file, para descoberta de _misconfigurations_, exposição de dados
sensíveis, _information disclosure_, falhas de API (OWASP API Security Top 10), SSRF validado
_out-of-band_, fingerprint de tecnologias/CVEs e recon de subdomínios/URLs — tudo em um único
arquivo Python.**

Feito para **pentest e bug bounty autorizados**. Saída em português, colorida por criticidade,
com um comando `curl` de reprodução em todo achado acionável e um resumo executivo no final.

> **Sobre o `misconfig.py` deste repositório:** é um **build ofuscado** (bytecode
> compilado + comprimido + empacotado num stub carregador) — protege o
> código-fonte de leitura/cópia direta, mas roda de forma **idêntica** ao
> original (mesma CLI, mesmo comportamento). Requer **Python 3.13.x** (o
> bytecode é específico da versão).
>
> **Motivo da ofuscação:** este arquivo contém lógica de detecção e técnicas
> de bypass **privadas e autorais**, desenvolvidas por mim — a ofuscação evita
> cópia/reuso direto do código sem impedir o uso normal da ferramenta.

## Licenciamento

Toda instalação nova tem **3 dias de avaliação gratuita**, contados a partir do
primeiro uso. Depois disso, é necessário ativar uma chave de licença.

```bash
python3 misconfig.py --license-status          # ve quanto tempo resta
python3 misconfig.py --activate SUA-CHAVE-AQUI # ativa uma licenca
```

Planos disponíveis: **1 mês**, **6 meses** e **1 ano**. Para adquirir uma
chave, entre em contato com o autor. As chaves são assinadas digitalmente
(Ed25519) — não é possível gerar chaves válidas sem autorização do autor.

---

> ## ⚠️ AVISO LEGAL — LEIA ANTES DE USAR
>
> Use **somente** contra alvos que você está **autorizado** a testar: pentest com contrato
> assinado, programa de bug bounty **dentro do escopo**, laboratórios/CTF ou ativos próprios.
>
> O tráfego é **agressivo e ruidoso** (centenas a milhares de requisições, fuzzing de parâmetros,
> brute-force de conteúdo, tentativas de bypass). O uso contra terceiros **sem autorização** pode
> constituir crime (no Brasil, Lei 12.737/2012 — "Lei Carolina Dieckmann" — e correlatas).
> O autor e os contribuidores **não se responsabilizam** por uso indevido.

---

## Índice

- [Visão geral](#visão-geral)
- [Principais recursos](#principais-recursos)
- [Instalação](#instalação)
- [Uso rápido](#uso-rápido)
- [Modos de operação](#modos-de-operação)
- [Referência completa de flags](#referência-completa-de-flags)
- [O que ele detecta (módulos)](#o-que-ele-detecta-módulos)
- [SSRF validado por webhook (out-of-band)](#ssrf-validado-por-webhook-out-of-band)
- [Bypass de WAF / filtros](#bypass-de-waf--filtros)
- [Redução de falsos positivos](#redução-de-falsos-positivos)
- [Autenticação (scan autenticado)](#autenticação-scan-autenticado)
- [Formatos de saída](#formatos-de-saída)
- [Exemplos práticos](#exemplos-práticos)
- [Como funciona por dentro](#como-funciona-por-dentro)
- [Performance e tuning](#performance-e-tuning)
- [Garantia: nunca deleta nada](#garantia-nunca-deleta-nada)
- [Solução de problemas](#solução-de-problemas)
- [Estrutura do projeto](#estrutura-do-projeto)
- [FAQ](#faq)
- [Licença](#licença)

---

## Visão geral

`misconfig.py` recebe um ou mais alvos e executa uma bateria completa de verificações de
segurança **web e de API**, do recon passivo à exploração ativa (não destrutiva). Ele foi
desenhado para três coisas:

1. **Cobertura máxima** — dezenas de módulos cobrindo desde `.env` exposto até OWASP API Top 10.
2. **Ruído mínimo no relatório** — calibra _baselines_ por host e por diretório para descartar
   falsos positivos; **não reporta 403** a menos que um bypass funcione; SSRF só entra se
   confirmado por callback real.
3. **Acionabilidade** — cada achado mostra **o quê**, **onde** (método + URL) e **criticidade**,
   e traz o `curl` exato para reproduzir manualmente.

| | |
|---|---|
| **Linguagem** | Python 3.7+ |
| **Dependência obrigatória** | `requests` |
| **Dependências opcionais** | `dnspython` (recon DNS), `cryptography` (análise TLS) |
| **Arquivo** | 1 único `.py` (~4.700 linhas), sem framework |
| **Plataformas** | Linux, WSL, macOS, Windows |
| **Concorrência** | `ThreadPoolExecutor` (alvos em paralelo + pools por fase) |
| **Versão** | 1.0.0 |

---

## Principais recursos

- 🔎 **Recon completo** — enumeração de subdomínios (passiva via crt.sh/OSINT + brute-force DNS
  + permutações _altdns-like_) e de URLs (Wayback, sitemap, robots, spider ativo, brute de
  conteúdo).
- 🗝️ **Dados sensíveis** — `.env`, `.git`/`.svn`, chaves privadas, dumps SQL, `terraform.tfstate`,
  `kubeconfig`, `.htpasswd` e ~60 padrões de segredo (AWS/GCP/GitHub/Stripe/JWT/connection strings).
- ☁️ **Cloud** — buckets S3/GCS/Azure/DigitalOcean abertos e Firebase RTDB.
- 🧩 **OWASP API Security Top 10** — descoberta e enumeração de endpoints, Swagger/OpenAPI,
  BOLA/BFLA, IDOR por IDs, GraphQL (introspection/mutations/batching/CSRF), JWT (`alg:none`,
  segredo fraco, replay), auth bypass, shadow APIs, CORS por endpoint, mass assignment, rate limit.
- 💉 **Injeção por parâmetro** — SQLi (erro + _blind boolean_), XSS refletido, LFI/traversal,
  open redirect.
- 🎯 **SSRF out-of-band** — validado por **callback real** no seu webhook: **zero falso positivo**.
- 🛡️ **Bypass de WAF** — se um payload é bloqueado, tenta variantes encodadas/ofuscadas e reporta
  qual contornou.
- 🧬 **Fingerprint de tecnologias/CVEs** — identifica stack e sinaliza CVEs conhecidos por versão.
- 🌐 **DNS/e-mail** — subdomain takeover, SPF/DMARC, transferência de zona (AXFR).
- 📉 **Baixo falso positivo** — baseline por host/diretório + similaridade fuzzy.
- 📊 **Saída rica** — console PT-BR colorido + JSON + HTML navegável (offline, com busca/filtro).
- 🔒 **Nunca deleta** — no máximo modifica **uma linha** (com `--unsafe-methods`), registrando o quê.

---

## Instalação

Requer **Python 3.7+**. Apenas `requests` é obrigatório; `dnspython` e `cryptography` são
opcionais (sem eles, apenas os módulos de DNS e de certificado TLS ficam desativados).

### Opção 1 — rodar direto (mais simples)

```bash
pip install -r requirements.txt
python3 misconfig.py -h
```

### Opção 2 — instalar como comando de terminal `misconfig`

```bash
pip install .              # mínimo (só requests)
pip install ".[full]"      # completo (com dnspython + cryptography)
misconfig -h
```

### Kali Linux / Debian (PEP 668 — "externally-managed-environment")

Distros recentes bloqueiam `pip install` global. Use um **venv** (recomendado):

```bash
python3 -m venv venv && . venv/bin/activate
pip install ".[full]"
misconfig -h
```

Ou, se preferir, `pipx install .` (gerencia o venv sozinho).

> **Atenção (Kali):** o `python`/`pip` padrão pode apontar para Python 2. Use sempre `python3` /
> `python3 -m pip`.

---

## Uso rápido

```bash
misconfig -d exemplo.com -v                    # 1 host, mostra fases + achados ao vivo
misconfig -l dominios.txt -o saida.json        # lista de alvos + relatório JSON
misconfig -D empresa.com -v                    # RECON COMPLETO: subdomínios + URLs + scan
misconfig -d alvo.com --html rel.html          # relatório HTML navegável
misconfig -d alvo.com --webhook auto           # + SSRF validado por callback (zero FP)
misconfig -d alvo.com --full                   # ATIVA TUDO (cuidado: faz escrita)
```

---

## Modos de operação

O alvo é definido por **exatamente um** de `-d`, `-l` ou `-D` (mutuamente exclusivos):

| Flag | Modo | Descrição |
|------|------|-----------|
| `-d ALVO` | **Único** | Escaneia um domínio ou URL. Se a URL tiver `?param=x`, esses parâmetros são sempre testados. |
| `-l ARQUIVO` | **Lista** | Um alvo por linha; escaneados em paralelo (`-t`). |
| `-D DOMÍNIO` | **Recon completo** | Enumera **subdomínios** → alive-check → enumera **URLs** de cada um → escaneia tudo. |

E sobre esses, os "perfis" de intensidade:

| Flag | Efeito |
|------|--------|
| `-A` / `--aggressive` | Sobe threads, profundidade de crawl e limites ao máximo; ativa param mining. |
| `--full` / `--tudo` | **Ativa TUDO**: agressivo + enum de URLs + todos os módulos + **escrita** (PUT/PATCH/mass assignment). Nunca deleta; registra o que modificou. |
| `--api-mode` | Foca em API (pula backups/cloud/DNS/crawl/arquivos). |
| `--light` | Modo educado: menos requisições e threads (bom para alvos com WAF/lentos). |

---

## Referência completa de flags

### Alvo (obrigatório, escolha um)

| Flag | Descrição |
|------|-----------|
| `-d, --domain` | Domínio ou URL único (scan direto). |
| `-l, --list` | Arquivo com lista de domínios (um por linha). |
| `-D, --enum DOMAIN` | Enumera subdomínios + URLs do domínio e escaneia tudo. |

### Geral

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `-v, --verbose` | — | Detalhe extra. Padrão já mostra fases+achados; `-v` mostra cada requisição HTTP; `-vv` = máximo. |
| `-q, --quiet` | — | Silencioso: só o relatório final. |
| `-A, --aggressive` | — | Sobe threads/profundidade/limites ao máximo. |
| `--full, --tudo` | — | Ativa tudo + métodos de escrita. |
| `--api-mode` | — | Foca em testes de API. |
| `--light` | — | Modo leve/educado. |
| `--no-adaptive` | — | Desliga o backoff automático ao detectar rate limiting (429/503). |
| `-t, --threads` | `8` | Alvos simultâneos. |
| `--path-threads` | `20` | Threads de probing por alvo. |
| `--timeout` | `10.0` | Timeout por requisição (s). |
| `--retries` | `1` | Retries por requisição. |
| `--delay` | `0.0` | Delay entre requisições por thread (s). |
| `-o, --output` | — | Salvar relatório **JSON**. |
| `--html` | — | Salvar relatório **HTML** navegável (auto-contido, abre offline). |
| `--proxy` | — | Proxy (ex.: `http://127.0.0.1:8080` para Burp). |
| `--user-agent` | UA de navegador | User-Agent customizado. |
| `-w, --wordlist` | — | Paths extras para fuzzing (um por linha). |
| `--verify-tls` | — | Validar certificados TLS. |
| `--no-tls` | — | Pular checagem de certificado/SAN. |
| `--no-color` | — | Desabilitar cores. |
| `--no-banner` | — | Não exibir o banner. |

### Autenticação (scan autenticado)

| Flag | Descrição |
|------|-----------|
| `-u, --user USUARIO` | Usuário ou e-mail para autenticar (login/Basic). |
| `-p, --password SENHA` | Senha (evite: fica no histórico; prefira `--ask-password` ou a env `MISCONFIG_PASSWORD`). |
| `--ask-password` | Pergunta a senha interativamente (não vai para o histórico do shell). |
| `--login-url` | URL de login específica (senão tenta endpoints comuns). |
| `--auth-type {auto,basic,form,json}` | Tipo de auth (padrão `auto`: login + fallback Basic). |
| `--no-session-cookies` | Não guardar cookies entre requisições (requisições sem estado). |

### SSRF (validação por webhook.site)

| Flag | Descrição |
|------|-----------|
| `--webhook URL` | Ativa SSRF validado por callback **OOB**. Passe a URL do seu webhook (ex.: `--webhook https://webhook.site/SEU-ID`) **ou** `auto` para criar um token automaticamente. Só reporta SSRF se o alvo **realmente** bater no seu webhook. |

### Módulos web

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--no-backup` | — | Pular fuzzing de backups. |
| `--no-dns` | — | Pular recon de DNS (CNAME/SPF/DMARC/AXFR/takeover). |
| `--no-cloud` | — | Pular checagem de buckets (S3/GCS/Azure/DO) e Firebase. |
| `--no-crawl` | — | Pular crawling de assets JS. |
| `--max-assets` | `25` | Máx. de arquivos JS baixados no crawling. |

### API (OWASP API Top 10)

| Flag | Descrição |
|------|-----------|
| `--no-api-enum` | Pular enumeração ativa de endpoints (brute de recursos + BOLA por IDs). |
| `--no-api-deep` | Pular testes profundos (auth bypass, JWT bypass, shadow, CORS). |
| `--no-ratelimit` | Não testar ausência de rate limiting (evita rajada em `/login`). |
| `--no-fingerprint` | Não fazer fingerprint de tecnologias/CVEs. |
| `--unsafe-methods` | Permitir **escrita** (PUT/PATCH/POST) e mass assignment. **Nunca deleta**; registra recursos modificados. |

### Enumeração (recon)

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--urls` | — | Com `-d`/`-l`: também enumerar URLs (Wayback/sitemap/crawl) por host. |
| `--no-urls` | — | Com `-D`: **não** enumerar URLs (só subdomínios + raiz). |
| `--subs-only` | — | Com `-D`: apenas listar subdomínios (não escaneia). |
| `--sub-wordlist` | — | Wordlist para brute-force **ativo** de subdomínios. |
| `--no-brute` | — | Não fazer brute-force DNS de subdomínios. |
| `--no-perms` | — | Não gerar permutações de subdomínios (altdns-like). |
| `--max-perms` | `1500` | Máx. de permutações testadas. |
| `--no-wayback` | — | Não consultar o Wayback Machine. |
| `--crawl-depth` | `2` | Profundidade do spider ativo de URLs (0 desliga). |
| `--no-active-crawl` | — | Não fazer crawl ativo (spider recursivo). |
| `--no-content-brute` | — | Não fazer brute-force ativo de conteúdo/diretórios. |
| `--content-wordlist` | — | Wordlist para brute-force de conteúdo. |
| `--no-params` | — | Não testar parâmetros (SQLi/XSS/LFI/open redirect/SSRF por parâmetro). |
| `--param-mining` | auto no `-A`/`--full` | Descobrir parâmetros ocultos por reflexão. |
| `--no-evasion` | — | Não tentar variantes encodadas quando o WAF bloquear. |
| `--no-alive` | — | Com `-D`: não filtrar por alive (escaneia todos os subdomínios resolvidos). |
| `--max-urls` | `300` | Máx. de URLs enumeradas por host. |
| `--enum-threads` | `40` | Threads para enumeração/resolução. |

---

## O que ele detecta (módulos)

Ordem aproximada das fases executadas em cada alvo:

### 1. Recon / enumeração
- **Subdomínios** (modo `-D`): passivo (crt.sh e fontes OSINT) + **brute-force DNS** por wordlist +
  **permutações** _altdns-like_; opcional alive-check HTTP(S).
- **URLs**: passivo (**Wayback Machine**, `sitemap.xml`, `robots.txt`) + **spider ativo** recursivo
  (profundidade configurável) + **brute-force de conteúdo** (diretórios/arquivos).
- **Inventário de parâmetros** descobertos por endpoint.

### 2. Dados sensíveis expostos
`.env`, `.git/` e `.svn/` (com confirmação de exposição), chaves privadas (`id_rsa`, `.pem`),
`.htpasswd`, dumps e bancos (`.sql`, `.sqlite`, `.db`), `master.key`, `terraform.tfstate`,
`kubeconfig`, backups (`.bak`, `.old`, `.zip`, `.tar.gz`…) e **~60 padrões de segredo** em corpo/JS
(AWS keys, GCP, tokens GitHub/GitLab, Stripe, JWT, _connection strings_, etc.).

### 3. Cloud
Buckets **S3/GCS/Azure/DigitalOcean** abertos (listáveis/graváveis) e **Firebase RTDB** exposto.
Buckets **referenciados no site** entram com alta confiança; nomes **adivinhados** entram com
confiança média (precisam de confirmação de posse).

### 4. API — OWASP API Security Top 10
- Descoberta de endpoints + parse de **Swagger/OpenAPI**.
- **BOLA/BFLA** e **IDOR** por enumeração de IDs.
- **GraphQL**: introspection, mutations, _field suggestion_, batching, CSRF.
- **JWT**: `alg:none`, segredo fraco (crack HMAC), replay/forja de token.
- **Auth bypass** (headers e path confusion), **shadow/deprecated APIs** (versionamento).
- **CORS por endpoint** (com credenciais = alto impacto), **excessive data exposure**,
  **mass assignment** (com `--unsafe-methods`), **ausência de rate limit** em autenticação.

### 5. Injeção por parâmetro
- **SQLi** — baseada em erro **e** _blind boolean_ (compara respostas TRUE vs FALSE; só em página
  estável, para reduzir ruído).
- **XSS refletido** — só conta em contexto **HTML** (JSON/texto refletido não é explorável).
- **LFI / path traversal** — com variantes de traversal encodado se bloqueado.
- **Open redirect** — por parâmetro.
- **SSRF** — **out-of-band**, veja a [seção dedicada](#ssrf-validado-por-webhook-out-of-band).

### 6. Information disclosure
Stack traces / erros de SQL, headers com versão, **source maps** (vazam código-fonte), segredos e
endpoints internos em **JS**, comentários HTML sensíveis, `.well-known` estendido, disclosure
baseado em erro (`'` no parâmetro).

### 7. Misconfiguration
Headers de segurança ausentes (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy), **CORS** permissivo, **métodos HTTP** (OPTIONS/TRACE),
**verb tampering**, cookies inseguros, **directory listing**, **host header injection**.

### 8. Tecnologias / CVEs
Fingerprint por `Server`, `X-Powered-By`, cookies e assinaturas de JS; sinaliza **CVEs conhecidos**
por versão detectada.

### 9. DNS / e-mail
**Subdomain takeover**, **SPF/DMARC** ausentes/fracos, **transferência de zona (AXFR)**, e
subdomínios extraídos dos **SANs do certificado** TLS.

---

## SSRF validado por webhook (out-of-band)

O módulo de SSRF por parâmetro **só roda com `--webhook`** — e é o jeito de **eliminar falso
positivo**. Sem `--webhook`, o SSRF por parâmetro **não é testado** (a detecção por assinatura
in-band gerava muitos falsos positivos).

### Como funciona

1. Para cada parâmetro candidato a fetch de URL (`url`, `uri`, `src`, `image`, `redirect`,
   `callback`, `proxy`, `feed`, `next`…), injeta uma **URL de callback única** apontando para o
   seu webhook (variantes `http://` e `https://`).
2. Se o servidor-alvo **realmente** buscar essa URL, o webhook registra a requisição — com o
   **IP de saída do alvo** como prova.
3. No fim do scan, a ferramenta consulta a API do webhook.site e **só então cria o achado**,
   correlacionando cada _canary_ único → (host, parâmetro, URL injetada). Achado = **CRÍTICO**,
   confiança **alta**, com `curl` de reprodução e o IP do alvo.

Sem callback ⇒ **nenhum achado** ⇒ nenhum falso positivo.

### Uso

```bash
# cria um token do webhook.site automaticamente (recomendado)
misconfig -d 'alvo.com/fetch?url=x' --webhook auto -v

# usa o seu próprio token
misconfig -D empresa.com --webhook https://webhook.site/SEU-UUID
```

> **Tokens anônimos do webhook.site expiram.** Se o seu token retornar erro, a ferramenta avisa e
> sugere `--webhook auto` (que cria um token novo na hora e imprime a URL para você acompanhar os
> callbacks ao vivo no navegador).

Funciona igualmente com `-d`, `-l` e `-D`: os probes de todos os alvos/subdomínios são coletados em
uma única fase ao final, com **janela de espera adaptativa** ao número de probes.

---

## Bypass de WAF / filtros

Quando um payload é **bloqueado** (403/406/419/429/501/999/418 ou assinaturas de WAF), a ferramenta
**reage** tentando variantes do mesmo payload e reporta **qual técnica contornou** — em vez de
simplesmente reportar o 403.

Técnicas de transformação: URL-encoding, **double-URL**, hex, unicode, entidades HTML,
_mixed-case_, whitespace, encadeamento; e, para SSRF, **representações alternativas de IP**
(decimal/hex/octal/IPv6-mapped) e hostnames de metadata. Aplicado reativamente a
**SQLi, XSS, LFI, open redirect e SSRF**.

> **403 não vira achado.** Só é reportado quando um bypass **de fato** obtém acesso. Desligue as
> tentativas com `--no-evasion`.

---

## Redução de falsos positivos

Para minimizar ruído, o scanner:

- **Calibra um baseline por host e por diretório** — envia paths aleatórios inexistentes e aprende
  o padrão _catch-all_ do alvo (status, tamanho, fingerprint de conteúdo, tokens estáveis).
- **Descarta** achados cuja resposta bate com o catch-all — por fingerprint, tamanho (±3%),
  contenção de tokens estáveis, ou **similaridade fuzzy (Jaccard ≥ 0,85)** para páginas que ecoam
  o path.
- **Gates específicos**: XSS só em contexto HTML; SQLi _blind_ só em página estável (dois baselines
  dentro de 1%); SSRF só com callback OOB confirmado.
- **Confiança por achado** (`alta`/`media`/`baixa`) para triagem.

---

## Autenticação (scan autenticado)

```bash
misconfig -d alvo.com -u admin -p senha123                 # login automático (form/JSON) ou Basic
misconfig -d alvo.com -u user@x.com --ask-password          # senha via prompt (não vai p/ histórico)
misconfig -d alvo.com -u admin --login-url /api/v1/login    # endpoint de login específico
misconfig -d alvo.com -u admin --auth-type basic            # força HTTP Basic
MISCONFIG_PASSWORD=senha misconfig -d alvo.com -u admin      # senha via variável de ambiente
```

Ordem de resolução da senha: `--ask-password` (prompt oculto) > env `MISCONFIG_PASSWORD` > `-p`.
Após autenticar, a home autenticada é re-buscada e o token/cookie de sessão é reutilizado nas fases
seguintes.

---

## Formatos de saída

### Console (PT-BR)
Agrupado por alvo, mostrando **o quê / onde (método + URL) / criticidade**, colorido por
severidade, com **`curl` de reprodução** em todo achado acionável e um **resumo executivo** final
(CRÍTICO / ALTO / MÉDIO).

Cores por severidade: **CRÍTICO** (roxo), **ALTO** (vermelho), **MÉDIO** (laranja),
**BAIXO** (azul), **INFO** (cinza).

### JSON (`-o saida.json`)
Estrutura com `meta`, `summary` (contagem por severidade) e `findings[]` — cada finding com
`target`, `category`, `severity`, `title`, `detail`, `url`, `evidence`, `method`, `curl`,
`confidence`. Ideal para pipelines/CI.

### HTML (`--html rel.html`)
Relatório **auto-contido** (abre offline no navegador), com **busca** e **filtro por severidade**,
e botão de copiar o `curl`. O caminho é impresso como **URL `file://` clicável** — inclusive
convertendo caminhos WSL:

```
[+] Relatorio HTML salvo em: file:///C:/Users/yurid/Downloads/relatorio-nava.html
```

### Código de saída
- `2` quando há achados **CRÍTICO** ou **ALTO** (útil para falhar um pipeline).
- `0` caso contrário.

---

## Exemplos práticos

**Básico**
```bash
misconfig -d exemplo.com -v                      # 1 host, verbose
misconfig -d https://alvo.com -vv                # -vv mostra cada requisição
misconfig -l dominios.txt -t 20 -o saida.json    # lista + JSON
```

**Ativar tudo / agressivo**
```bash
misconfig -d alvo.com --full -v                  # ATIVA TUDO (inclui escrita!)
misconfig -D empresa.com -A -o saida.json        # recon completo + agressivo (não destrutivo)
misconfig -d alvo.com -A --unsafe-methods        # agressivo + escrita (PUT/PATCH/mass assign)
```

**API (OWASP API Top 10)**
```bash
misconfig -d api.alvo.com --api-mode -v
misconfig -d api.alvo.com --api-mode -u admin -p senha
misconfig -d api.alvo.com --login-url /api/v1/login -u a@b.com -p s3nha
```

**Recon / enumeração**
```bash
misconfig -D empresa.com -v                       # subdomínios + URLs + scan
misconfig -D empresa.com --subs-only              # só listar subdomínios
misconfig -d alvo.com --urls -w paths.txt         # host + enum de URLs + wordlist
misconfig -D empresa.com --sub-wordlist subs.txt --crawl-depth 3
```

**SSRF out-of-band**
```bash
misconfig -d 'alvo.com/fetch?url=x' --webhook auto -v
misconfig -D empresa.com -A --webhook https://webhook.site/SEU-UUID
```

**Alvos com WAF / Cloudflare (educado)**
```bash
misconfig -d alvo.com --light
misconfig -d alvo.com --path-threads 5 --delay 0.3
```

**Outros**
```bash
misconfig -d alvo.com --proxy http://127.0.0.1:8080     # via Burp
misconfig -d alvo.com -o saida.json --html rel.html      # JSON + HTML
misconfig -d alvo.com -u admin --ask-password            # senha via prompt
```

---

## Como funciona por dentro

```
                 ┌───────────────────────────────────────────────┐
   -d / -l / -D  │  main(): parse args → monta opts → FindingBag  │
                 └───────────────────────┬───────────────────────┘
                                         │
        (modo -D) enumerate_subdomains → filter_alive → targets
                                         │
              ThreadPoolExecutor(threads)│  ← alvos em paralelo
                                         ▼
                              ┌────────────────────┐
                              │   scan_target()    │  por alvo:
                              │  calibra baseline  │
                              │  headers/fingerprint│
                              │  corpo/segredos    │
                              │  CORS / métodos    │
                              │  arquivos/.git/bak │
                              │  API (enum+deep)   │
                              │  GraphQL / POST    │
                              │  cloud / firebase  │
                              │  crawl JS          │
                              │  enum URLs → params│ → injeta probes SSRF
                              │  well-known/TLS    │
                              └─────────┬──────────┘
                                        │ achados → FindingBag (dedupe + curl)
                                        ▼
                    fase de coleta SSRF-OOB (webhook) → achados finais
                                        ▼
                     print_report + save_json + save_html + exit code
```

Detalhes de robustez: **rate limiting adaptativo** (backoff automático em 429/503), retries,
dedupe de achados por `(alvo, título, URL)`, e `stdout` reconfigurado para UTF-8.

---

## Performance e tuning

| Objetivo | Como |
|----------|------|
| Mais rápido / mais cobertura | `-A` (agressivo) e/ou `-t`/`--path-threads`/`--enum-threads` maiores. |
| Mais educado (alvo frágil/WAF) | `--light`, ou `--path-threads 5 --delay 0.3`. |
| Focar em API | `--api-mode`. |
| Reduzir volume | `--no-content-brute`, `--no-perms`, `--max-urls`, `--max-perms`, `--max-assets`. |
| Via proxy (Burp/ZAP) | `--proxy http://127.0.0.1:8080`. |
| Não falhar por rate limit | manter o backoff (padrão); `--no-adaptive` desliga. |

---

## Garantia: nunca deleta nada

- A ferramenta **nunca envia `DELETE`**.
- Com `--unsafe-methods`/`--full`, no máximo faz uma **escrita mínima** (PUT/PATCH/POST/mass
  assignment) para provar a falha — e **registra** exatamente o que modificou, na seção
  "RECURSO MODIFICADO", com o `curl` correspondente.
- Todo achado acionável traz o `curl` para você **reproduzir manualmente** e confirmar.

---

## Solução de problemas

| Sintoma | Causa / solução |
|---------|-----------------|
| `ERROR: No matching distribution found for setuptools>=61` | O `pip` está no **Python 2**. Use `python3 -m pip`. |
| `externally-managed-environment` (Kali/Debian) | PEP 668. Use um **venv** ou `pipx` (veja [Instalação](#instalação)). |
| `--webhook` não confirma SSRF | Token do webhook **expirado** — use `--webhook auto`. |
| Nenhum subdomínio no `-D` | Instale `dnspython` (`pip install ".[full]"`) e/ou passe `--sub-wordlist`. |
| Muito lento | Reduza limites (`--max-urls`, `--no-content-brute`) ou suba threads com cautela. |
| Cloudflare bloqueando | `--light`, reduza threads e use `--delay`; o backoff adaptativo já recua sozinho. |
| Acentos quebrados no Windows | O `stdout` é reconfigurado para UTF-8; use um terminal moderno (Windows Terminal). |

---

## Estrutura do projeto

```
Misconfig-Sensitive-Info-Disclosure/
├── misconfig.py        # a ferramenta (single-file, ~4.700 linhas)
├── pyproject.toml      # empacotamento (cria o comando `misconfig`)
├── requirements.txt    # requests (obrigatório) + dnspython/cryptography (opcionais)
└── README.md           # este arquivo
```

---

## FAQ

**Preciso de `dnspython`/`cryptography`?**
Não. Sem eles, apenas os módulos de DNS (takeover/SPF/DMARC/AXFR) e de certificado TLS ficam
desativados; todo o resto funciona.

**Posso usar em produção de um cliente?**
Somente com autorização por escrito e dentro da janela combinada. O tráfego é agressivo.

**Ele explora as falhas?**
Ele **valida** de forma não destrutiva (leitura, ou no máximo uma escrita registrada com
`--unsafe-methods`). Não deleta, não faz DoS. A exploração final é sua, com o `curl` fornecido.

**Por que não reporta 403?**
Porque 403 costuma ser ruído. Só reporta se um **bypass** realmente obtiver acesso.

**Funciona com autenticação por cookie e por token?**
Sim — login automático (form/JSON), HTTP Basic, e reuso de Bearer/cookie de sessão.

---

## Licença

Distribuído sob a licença **MIT**. Uso por sua conta e risco, **somente em alvos autorizados**.
