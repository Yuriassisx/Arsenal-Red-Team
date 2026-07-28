# ParamHunter

**Scanner de parâmetros vulneráveis + fuzzer de payloads**, assíncrono e orientado
a dados (YAML), com foco em duas coisas que a maioria das ferramentas faz mal:
**ampla diversidade de bypass/encoding** para furar filtros/WAFs, e **alta
precisão** (pouco falso-positivo) via confirmação estatística e oráculos.

> ⚠️ **Uso legal apenas.** Rode somente contra sistemas que você tem permissão
> **explícita** para testar. Há uma trava de escopo (allowlist de hosts), um gate
> `--yes` (autorização) e um gate `--yes-full` (confirmação do volume agressivo).

**Números:** 12 módulos de vulnerabilidade · 9 técnicas dedicadas · ~510 payloads ·
58 encoders de bypass · 10 perfis de evasão por fabricante de WAF · v1.1.0.

> **Sobre o `paramhunter.py` deste repositório:** é um **build ofuscado**
> (bytecode compilado + comprimido + empacotado num stub carregador) — protege
> o código-fonte de leitura/cópia direta, mas roda de forma **idêntica** ao
> original (mesma CLI, mesmo comportamento). Requer **Python 3.13.x** (o
> bytecode é específico da versão). O restante do projeto (`core/`,
> `encoders/`, `modules/`, `payloads/`) permanece em texto claro.
>
> **Motivo da ofuscação:** este arquivo contém lógica de detecção e técnicas
> de bypass **privadas e autorais**, desenvolvidas por mim — a ofuscação evita
> cópia/reuso direto do código sem impedir o uso normal da ferramenta.

---

## Índice

1. [Filosofia](#filosofia)
2. [Instalação](#instalação)
3. [Início rápido](#início-rápido)
4. [Modos: FULL (padrão) vs LIGHT](#modos-full-padrão-vs-light)
5. [Fontes de alvo](#fontes-de-alvo)
6. [Classes de vulnerabilidade](#classes-de-vulnerabilidade)
7. [Técnicas dedicadas](#técnicas-dedicadas)
8. [Pontos de injeção](#pontos-de-injeção)
9. [Motor de detecção](#motor-de-detecção)
10. [Diversidade de bypass / encoding](#diversidade-de-bypass--encoding)
11. [WAF: detecção + evasão adaptativa](#waf-detecção--evasão-adaptativa)
12. [Out-of-band (OOB)](#out-of-band-oob)
13. [Scanning autenticado](#scanning-autenticado)
14. [Descoberta de superfície](#descoberta-de-superfície)
15. [Controle de velocidade e volume](#controle-de-velocidade-e-volume)
16. [Progresso: verbose e heartbeat](#progresso-verbose-e-heartbeat)
17. [Relatórios e saídas](#relatórios-e-saídas)
18. [Referência completa de flags](#referência-completa-de-flags)
19. [Códigos de saída](#códigos-de-saída)
20. [Arquitetura](#arquitetura)
21. [Estender](#estender)
22. [Testes](#testes)
23. [Segurança e uso legal](#segurança-e-uso-legal)

---

## Filosofia

O objetivo dos encoders **não é "codificar corretamente"** e sim gerar o maior
número de **representações plausíveis** que WAFs, filtros e parsers frágeis tratam
de forma **divergente do backend real**. Ao mesmo tempo, cada achado passa por
**confirmação** (oráculo booleano, mediana estatística de tempo, reconfirmação,
execução real no navegador) para que o que sai como **CONFIRMADO** seja de fato
explorável — e reproduzível por um `curl`.

Por padrão testa **TODOS os parâmetros** de cada alvo: cada parâmetro vira um
`InjectionPoint` e roda contra todos os módulos relevantes.

---

## Instalação

**Installer (recomendado)** — cria um venv isolado, instala as dependências e
disponibiliza o comando `paramhunter` no PATH (não copia `tests/` nem outputs):

```bash
./install.sh                 # instala (venv + comando paramhunter)
./install.sh --with-tools    # + tenta instalar gau/paramspider/chromium
./install.sh uninstall       # remove
```
Como root instala em `/opt/paramhunter` + `/usr/local/bin`; sem root, em
`~/.local`. Prefixo custom: `./install.sh --prefix ~/apps/ph`.

**Manual:**
```bash
pip install -r requirements.txt        # httpx, aiohttp, PyYAML
```

**Dependências opcionais** (habilitam recursos):

| Recurso | Dependência | Como instalar |
|---------|-------------|---------------|
| `-d/--domain` (enumeração) | **gau** | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `-d/--domain` (enumeração) | **paramspider** | `pipx install git+https://github.com/devanshbatham/paramspider` |
| `--headless` (DOM XSS real) | **chromium** | `apt install chromium` (ou chromium-browser) |
| `--http2` | **h2** | `pip install h2` |

---

## Início rápido

```bash
# scan LEVE de uma URL (rápido, 12 variantes, só os módulos)
python3 paramhunter.py -u 'https://alvo/app?id=1&file=a&q=b' -m sqli,lfi,xss --light --yes

# scan COMPLETO/agressivo (precisa confirmar o volume com --yes-full)
python3 paramhunter.py -u 'https://alvo/app?id=1' --yes --yes-full

# lista de URLs
python3 paramhunter.py -l urls.txt --light --yes -o achados.json

# domínio inteiro (gau + paramspider mapeiam URLs/params sozinhos)
python3 paramhunter.py -d alvo.com --enum-subs --yes --yes-full

# guia completo de usos:
python3 paramhunter.py --examples
```

---

## Modos: FULL (padrão) vs LIGHT

O **modo completo (`--full`) é o PADRÃO** — todo scan roda agressivo + todas as
técnicas, a menos que você use `--light`. Pelo **volume alto**, o full exige
**confirmação explícita** com `--yes-full`; sem ela (e sem `--light`), o scan
**aborta**, evitando disparo acidental contra produção.

| | **`--light`** | **`--full` (padrão, exige `--yes-full`)** |
|--|---------------|-------------------------------------------|
| Variantes/payload | 12 | **400** + encadeamento |
| Técnicas extras | não | host-header, XXE, mass-assignment, cache-poison, HPP |
| JWT / DOM XSS / race | não | **sim** |
| Crawler / descoberta | não | **sim** |
| Locais de injeção | query, body, json | **todos** (+ header, cookie, path) |
| `--verify` | não | **sim** |
| Velocidade | rápido | lento (bounde com `--time-endpoint`) |

```bash
python3 paramhunter.py -u 'https://alvo/p?id=1' -m sqli --light --yes        # leve
python3 paramhunter.py -u 'https://alvo/p?id=1' --yes --yes-full             # completo
```

---

## Fontes de alvo

O ParamHunter aceita alvos de **7 fontes** — todas viram `RequestTemplate` e passam
pelo mesmo pipeline:

### URL direta / lista
```bash
python3 paramhunter.py -u 'https://alvo/app?id=1&file=a' --yes --light
python3 paramhunter.py -l urls.txt --yes --light            # uma URL por linha
```

### Domínio (`-d`) — enumeração passiva
Passe só o **domínio**: **gau** (getallurls) + **paramspider** mineram os
**arquivos públicos da web** (Wayback, CommonCrawl, OTX, urlscan) — **passivo, não
toca o alvo** — e o pipeline testa tudo.

```bash
python3 paramhunter.py -d alvo.com --enum-subs --yes --yes-full
python3 paramhunter.py -d alvo.com --enum-subs --enum-providers wayback --enum-timeout 300 --yes --light
```

O diferencial é a **dedup por assinatura de endpoint** (`host + path +
nomes-de-parâmetro`): os arquivos devolvem o mesmo endpoint com centenas de
valores (`?id=1`, `?id=2`…) e a engine colapsa para **um representante por conjunto
de parâmetros**. `--enum-subs` é essencial em sites grandes (o apex costuma ter ~0;
o conteúdo está nos subdomínios). Controles: `--enum-max`, `--enum-timeout`,
`--enum-all-urls`, `--enum-providers`, `--no-gau`, `--no-paramspider`.

### OpenAPI / Swagger
```bash
python3 paramhunter.py --openapi https://alvo/openapi.json --api-auth 'Authorization: Bearer X' --api --yes
python3 paramhunter.py --openapi ./swagger.yaml --api-base https://staging/api --api-methods get,post,put --yes
```
Resolve `$ref`, gera valores de amostra e transforma cada parâmetro (path/query/
header/cookie) e cada propriedade do corpo JSON num ponto. Por segurança, só
`get,post` são gerados por padrão (`put/patch/delete` mutam dados).

### Request bruto (Burp) / cURL (DevTools)
```bash
python3 paramhunter.py --request-file req.txt --api --yes           # raw HTTP request
python3 paramhunter.py --curl "curl 'https://alvo/api' -X POST --data '{\"q\":\"1\"}'" --api --yes
```
Ideal para endpoints de **ação/POST**: importa método, headers e **corpo** — aí o
fuzzing atinge cada campo do corpo JSON (inclusive aninhado), que é onde as vulns
reais desses endpoints estão.

### GraphQL / WebSocket
```bash
python3 paramhunter.py --graphql https://alvo/graphql -H 'Authorization: Bearer X' --yes
python3 paramhunter.py --websocket ws://alvo/socket --yes
```
GraphQL: introspection → monta uma operação por campo usando *variables* e fuzza
**só as variables** (`json:variables.<arg>`), sem corromper a operação.

---

## Classes de vulnerabilidade

12 módulos orientados a dados (YAML em `payloads/`). O detector usado por cada um
define como o achado é confirmado:

| Módulo | Payloads | Detectores | Confirma via |
|--------|:--------:|------------|--------------|
| **lfi** (path traversal) | 99 | signature | conteúdo do arquivo vazado (`root:x:0:0`) |
| **sqli** | 75 | signature, **boolean**, time, oob | erro SQL / oráculo true-false / sleep |
| **cmdi** (OS command) | 81 | signature, time, oob, diff | saída do comando (`uid=`) / sleep / callback |
| **ssrf** | 79 | oob, signature, diff | callback out-of-band |
| **xss** (refletido) | 52 | signature, reflection | reflexão do marcador (+ headless p/ execução) |
| **ssti** | 39 | signature | avaliação de expressão (`1337*1337`) |
| **open_redirect** | 20 | redirect, diff | canário no `Location`/refresh |
| **crlf** (header injection) | 13 | crlf | header injetado refletido |
| **nosqli** | 16 | signature, diff, **boolean** | erro / oráculo booleano |
| **ldap** | 12 | signature, diff | erro LDAP |
| **xpath** | 12 | signature, diff | erro XPath |
| **deserial** (Java/PHP/.NET/Python/Ruby/Node) | 12 | signature, diff | erro de desserialização |

---

## Técnicas dedicadas

Além dos módulos, há técnicas com lógica própria na engine (ligadas por flag, ou
todas no `--full`):

- **HPP — HTTP Parameter Pollution (`--hpp`)**: envia o param 2× (payload por
  último e por primeiro) em query e corpo. Fura WAFs que inspecionam só a 1ª
  ocorrência enquanto o backend usa a última.
- **Host-header injection (`--host-header`)**: canário em `Host`,
  `X-Forwarded-Host`, `Forwarded`, … detecta reflexão no corpo ou no `Location`
  (password-reset/cache poisoning).
- **XXE (`--xxe`)**: corpo XML com entidade externa (leitura de arquivo via
  `file://`/`php://filter` + exfil **OOB**).
- **Mass assignment (`--mass-assignment`)**: injeta campos sensíveis no JSON
  (`isAdmin`, `role`, `is_superuser`, `balance`…) e detecta se "colam".
- **Web cache poisoning (`--cache-poison`)**: canário em header não-chaveado +
  verificação de cacheabilidade (`Age`, `X-Cache: HIT`, `Cache-Control: public`).
- **IDOR (`--smart` ou `--full`)**: em params id-like, troca o valor (n±1, 0, 1,
  2…) e flagra quando retorna **outro objeto válido** (controle de acesso quebrado).
- **JWT (`--jwt`)**: alg=none, segredo HMAC fraco, kid injection.
- **DOM XSS headless (`--headless`)**: chromium renderiza o payload; **só marca se
  o JS EXECUTAR de verdade** — zero falso-positivo de reflexão codificada.
- **Race condition (`--race`, `--race-n`)**: rajada concorrente + detecção de
  estado pré-limite (TOCTOU).

`--all-techniques` liga HPP + host-header + XXE + mass-assignment + cache-poison
de uma vez.

---

## Pontos de injeção

Cada parâmetro em cada localização vira um ponto. Controle com `--loc` (csv):

`query` · `body` (urlencoded) · `json` (inclusive **aninhado**, dot-path) ·
`header` · `cookie` · `path` (marcador `FUZZ` ou `{nome}` na URL).

```bash
python3 paramhunter.py -u 'https://alvo/download/FUZZ' -m lfi --yes --light      # path
python3 paramhunter.py -u https://alvo/api -H 'Authorization: Bearer X' \
    -b 'session=abc' --loc query,json,header,cookie --yes --light
```

Se um alvo não tem parâmetro, injeta um `id=1` sintético para permitir teste.

---

## Motor de detecção

Cada estratégia produz um sinal com **confiança** e **evidência**:

| Detector | Prova | Anti-falso-positivo |
|----------|-------|---------------------|
| **signature** (0.95) | regex de evidência forte na resposta | suprime match que também aparece no payload injetado (auto-reflexão) ou no baseline |
| **boolean** (0.92) | oráculo true/false: `true≈baseline` e `true≠false` | praticamente zero FP |
| **time** (estatístico) | atraso induzido (`sleep`) | mediana de N amostras (imune a pico de rede); reconfirma |
| **diff** | status/tamanho/similaridade vs baseline | **só roda se o baseline for ESTÁVEL** (página dinâmica → desliga) |
| **reflection** | marcador único do payload refletido | marcador aleatório por request |
| **redirect / crlf** | canário no `Location`/header | canário verificável |
| **oob** (0.99) | callback out-of-band | evidência externa — o mais forte |

**Reforços de qualidade:**
- **Estabilidade de baseline**: 3 amostras; se a página varia sozinha, o detector
  `diff` é desligado naquele alvo (mata a maior fonte de FP).
- **`--verify`** (auto no full): re-envia o payload vencedor e só confirma se o
  sinal repetir.
- **Severidade**: `CONFIRMADO` (≥0.9) · `PROVÁVEL` (0.7–0.9) · `SUSPEITO` (<0.7).
- **Correlação** (default): o mesmo bug achado por vários vetores é consolidado num
  único item (`--no-correlate` desliga).

---

## Diversidade de bypass / encoding

**58 encoders** (`--list-transforms`) em grupos (`--list-groups`): `url, unicode,
case, path, cmd, sql, html, space, poly`. Inclui percent-encoding
simples/duplo/triplo com caixa hex mista (`%2f`/`%2F`), overlong UTF-8 (2 e 3
bytes), `%uXXXX` (IIS), fullwidth, **best-fit homoglyph**, HTML entities
(dec/hex), `String.fromCharCode`, `${IFS}`/`%09`/espaço ideográfico, quebra de
keyword (`i""d`, `c\url`), globbing (`/???/c?t`), comentário `/**/` inline, null
byte em 6 codificações, e **polimórficos** (grupo `poly`, mutação aleatória por
request).

**Modo agressivo (`-A`, incluso no `--full`)**: joga o arsenal inteiro em cada
payload, ativa **encadeamento** de encoders (`--chain-depth 2`) e testa todas as
variantes. 1 payload de LFI vira ~600 variantes.

**Controles finos:**
```bash
--encoders url,unicode,best_fit    # adiciona grupos/encoders específicos
--encoders all                     # todos, sem encadeamento
--chain-depth 2                    # encadeia pares (CUIDADO: explode volume)
--max-variants 400                 # teto de variantes por payload
```

Deduplicação automática por (módulo×ponto): payloads distintos que colidem na
**mesma requisição** após o encode não são reenviados (`--no-dedup` desliga).

---

## WAF: detecção + evasão adaptativa

Ligado por padrão (`core/waf.py`). Inspeciona cada resposta vs baseline procurando
bloqueio (status 403/406/429/503, página de bloqueio, ou drop de rede
**sistemático** — evita FP de erro pontual) e identifica o **fabricante**
(Cloudflare, Akamai, Imperva, ModSecurity, AWS WAF, Sucuri, F5, FortiWeb,
Wordfence…). Rastreado **por rota** (host+path).

- **Fingerprint ATIVO** (`--fingerprint`, default): envia payloads-sonda antes do
  scan, identifica o fabricante e prioriza o **perfil de evasão** ideal.
- **FASE 2 — escalonamento**: ao detectar bloqueio num parâmetro, re-testa aquele
  parâmetro com o arsenal de evasão (double/triple encode, overlong, best-fit,
  polimórfico, poliglota, encadeamento).
- **Cache de bypass por host** (`~/.hunterparam/waf_cache.json`, persistente): o
  encoder que fura o WAF é memorizado e testado **primeiro** nos demais parâmetros
  — do host atual e em execuções futuras. `--no-waf-cache` desliga.
- **Modo stealth (`--stealth`)**: backoff exponencial ao apanhar (até 8s), jitter,
  **rotação de User-Agent** (pool de 6), concorrência reduzida. Respeita
  `Retry-After` em 429/503.

```bash
python3 paramhunter.py -u 'https://alvo/p?id=1' --stealth --rate 5 --yes --light
python3 paramhunter.py -u 'https://alvo/p?id=1' --no-waf-adapt --yes --light   # só detecta/reporta
```

---

## Out-of-band (OOB)

Para SSRF e injeção **cega** (blind). Três modos:

```bash
# 1) listener HTTP embutido (labs/rede interna — o alvo precisa alcançar seu host)
python3 paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf --oob --oob-host 10.0.0.5 --yes --light

# 2) serviço externo (interactsh/Collaborator) — confirmação no serviço
python3 paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf --oob-domain abc.oast.pro --yes --light

# 3) webhook.site — cole a SUA URL; confira os callbacks no painel
python3 paramhunter.py -u 'https://alvo/fetch?url=x' -m ssrf --webhook https://webhook.site/SEU-UUID --yes --light
```

> **Importante:** sem OOB configurado, os payloads cegos (SSRF/CMDi/XXE via
> callback) são **pulados**. Para o full "de verdade", adicione `--webhook`.

---

## Scanning autenticado

```bash
python3 paramhunter.py -u https://alvo/painel?q=x \
    --login-url https://alvo/login --login-data 'user=admin&pass=admin' \
    --csrf-field csrf_token --auth-marker 'Bem-vindo' --yes --light
```

Login form/JSON + extração de CSRF + sessão via cookie-jar + **re-login automático**
quando a sessão expira no meio do scan.

---

## Descoberta de superfície

- **`--discover`**: força nomes de wordlist e detecta parâmetros **ocultos** por
  reflexão (com bisseção, à la Arjun) e por diferencial de resposta; extrai nomes
  de forms/links/JSON do HTML. `--discover-only` só enumera.
- **`--discover-api`**: força nomes de campo JSON (estilo Arjun para JSON).
- **`--crawl`** (`--crawl-depth`, `--crawl-max`): BFS segue links/forms + extrai
  endpoints de JavaScript a partir das seeds.
- **`-d/--domain`**: enumeração passiva via gau + paramspider (ver
  [Fontes de alvo](#fontes-de-alvo)).

---

## Controle de velocidade e volume

O modo full é pesado por natureza. Ferramentas para não "ficar dias rodando":

| Flag | Efeito |
|------|--------|
| **`--time-endpoint N`** | teto de **N segundos de fuzzing por endpoint**; ao esgotar, cancela o resto e passa pro próximo (mantém achados parciais) |
| **`--no-blind`** | pula payloads time-based (`sleep`, que são **seriais** e o maior custo); confie no OOB/`--webhook` para pegar cego sem custo serial |
| **`--time-variants N`** | teto de variantes por payload time-based (default 4; encoding quase não muda se o `sleep` executa) |
| `--rate`, `-c` | req/s e concorrência |
| `--light` | 12 variantes em vez de 400 (~33× mais rápido) |
| `--smart` | escolhe módulos por nome do parâmetro (~7× menos requests) |
| `--max-response-kb` | teto do corpo lido (protege memória em endpoints grandes) |

```bash
python3 paramhunter.py -l urls.txt --yes --yes-full --time-endpoint 600     # 10 min/endpoint
python3 paramhunter.py -u https://alvo?id=1 --yes --yes-full --no-blind     # sem os sleeps seriais
```

---

## Progresso: verbose e heartbeat

```bash
python3 paramhunter.py -u https://alvo?id=1 --yes --yes-full --heartbeat 15
```
**Heartbeat** (`--heartbeat N`, default 15) imprime periodicamente:
```
[♥ 02:15] 8432 req · 62 req/s · alvo 3/10 · pontos 34/48 · 5 achado(s) · ETA ~00:38
```

**Verbose:**
- `-v` — cada **fase** (baseline, FUZZING, FASE 1/2 WAF, técnicas) + cada
  **requisição** com status colorido.
- `-vv` — adiciona tamanho/tempo/tag e o **payload** de cada request, com o
  propósito (módulo) e o encoder usado.

> Em scan de lista/domínio grande use `-v` (ou só o heartbeat); `-vv` gera muita
> saída (`-vv 2>&1 | tee scan.log`).

---

## Relatórios e saídas

- **Console — seção verde "✅ CONFIRMADOS"**: no fim do scan, **só o que funcionou**
  (dedup por endpoint), com URL, parâmetro, payload, encoder, evidência e um
  **comando `curl` pronto para reproduzir**.
- **`--poc [arquivo]`** (default `poc.md`): exporta os confirmados em **Markdown**
  pronto para laudo de bug bounty (com o curl de reprodução). `--poc-threshold`
  ajusta a confiança mínima (default 0.9).
- **`-o out.json` / `--jsonl out.jsonl`**: exportação estruturada.
- **`--html report.html`**: relatório autocontido (tema escuro), agrupado por
  endpoint/severidade, com WAF detectado e bypasses eficazes.
- **`--sarif out.sarif`**: SARIF 2.1.0 para GitHub code scanning / pipelines.

**Como saber que funcionou:** confie no **CONFIRMADO + evidência concreta**; para
cegos, cheque o painel do OOB (webhook.site). Sempre valide com o `curl` do PoC
antes de reportar.

---

## Referência completa de flags

<details>
<summary><b>Alvo</b></summary>

| Flag | Descrição |
|------|-----------|
| `-u, --url` | URL alvo (use `FUZZ`/`{nome}` no path para injetar no caminho) |
| `-l, --urls-file` | arquivo com uma URL por linha |
| `-d, --domain` | enumera URLs/params do domínio (gau + paramspider) — repetível |
| `-X, --method` | método HTTP (default GET) |
| `--data` | corpo da requisição (urlencoded ou JSON) |
| `-H, --header` | header `Nome: Valor` (repetível) |
| `-b, --cookie` | cookies `a=b; c=d` |
</details>

<details>
<summary><b>Autenticação</b></summary>

| Flag | Descrição |
|------|-----------|
| `--login-url` | URL de login — autentica antes e mantém a sessão |
| `--login-data` | `user=x&pass=y` (form) ou `{"u":"x"}` (json) |
| `--login-json` | envia o login como JSON |
| `--csrf-field` | campo CSRF a extrair da página de login e reenviar |
| `--auth-marker` | string que aparece quando LOGADO (dispara re-login) |
</details>

<details>
<summary><b>API / fontes alternativas</b></summary>

| Flag | Descrição |
|------|-----------|
| `--openapi` | spec OpenAPI 3 / Swagger 2 (arquivo ou URL) |
| `--api-base` | URL base da API (sobrescreve a spec) |
| `--api-methods` | métodos a gerar da spec (default get,post) |
| `--api-auth` | header de auth p/ toda a API (repetível) |
| `--request-file`, `--request-scheme` | request bruto (Burp) |
| `--curl`, `--curl-file` | comando cURL do DevTools |
| `--graphql` | endpoint GraphQL (introspection → variables) |
| `--websocket` | endpoint WebSocket (`ws://…`) |
| `--api` | perfil API: injeta em query,json,header,path |
</details>

<details>
<summary><b>Técnicas extras</b></summary>

`--host-header` · `--xxe` · `--mass-assignment` · `--cache-poison` ·
`--discover-api` (`--api-wordlist`) · `--jwt` · `--headless` · `--race`
(`--race-n`) · `--all-techniques`
</details>

<details>
<summary><b>Módulos / pontos</b></summary>

| Flag | Descrição |
|------|-----------|
| `-m, --modules` | módulos a rodar (csv). default: todos |
| `--loc` | localizações: `query,body,json,header,cookie,path` |
| `--smart` | escolhe módulos por nome do parâmetro (menos requests) |
| `--list-modules`, `--list-transforms`, `--list-groups`, `--examples` | informações |
</details>

<details>
<summary><b>Descoberta / enumeração</b></summary>

`--discover` · `--discover-only` · `--wordlist` · `--discover-loc` · `--crawl`
(`--crawl-depth`, `--crawl-max`) · `--enum-subs` · `--enum-max` · `--enum-timeout`
· `--enum-all-urls` · `--enum-providers` · `--no-gau` · `--no-paramspider`
</details>

<details>
<summary><b>Out-of-band</b></summary>

`--oob` (`--oob-port`, `--oob-host`) · `--oob-domain` · `--webhook`
</details>

<details>
<summary><b>Engine / velocidade</b></summary>

| Flag | Descrição |
|------|-----------|
| `-c, --concurrency` | requisições concorrentes |
| `--rate` | limite de req/s (0=ilimitado) |
| `--timeout`, `--retries` | por requisição |
| `--max-response-kb` | teto do corpo lido (0=ilimitado; default 2000) |
| `--proxy` | proxy (ex.: Burp) |
| `--insecure` / `--secure` | ignora / verifica certificados TLS |
| `--http2` | habilita HTTP/2 |
| `--max-variants`, `--threshold`, `--all-variants`, `--inject-mode` | controle de fuzzing |
| `--verify` | re-verifica o achado (corta FP) |
| `--no-dedup` | não deduplica requisições idênticas |
| `--no-blind` | pula time-based (serial) |
| `--time-variants` | teto de variantes por payload time-based (default 4) |
| `--time-endpoint` | tempo máx. de fuzzing por endpoint (0=sem limite) |
</details>

<details>
<summary><b>Modo agressivo / WAF</b></summary>

| Flag | Descrição |
|------|-----------|
| `--full` | modo completo (**é o padrão**) |
| `--light` | desliga o full (scan leve) |
| `--yes-full` | confirma o volume agressivo |
| `-A, --aggressive` | todos os encoders + encadeamento + todas as variantes |
| `--chain-depth`, `--encoders`, `--hpp` | bypass |
| `--no-waf-detect`, `--no-waf-adapt`, `--evasion-variants` | WAF |
| `--no-waf-cache`, `--waf-cache-file` | cache persistente de bypass |
| `--fingerprint` / `--no-fingerprint` | fingerprint ativo de WAF |
| `--stealth`, `--jitter` | modo furtivo |
</details>

<details>
<summary><b>Saída / autorização</b></summary>

| Flag | Descrição |
|------|-----------|
| `--scope`, `--deny` | ampliar/bloquear escopo |
| `--yes` | confirmo que estou AUTORIZADO |
| `-o`, `--jsonl`, `--html`, `--sarif` | exportações |
| `--poc [arq]`, `--poc-threshold` | laudo só dos confirmados (+ curl) |
| `--no-correlate` | não agrupar achados |
| `-q, --quiet`, `-v/-vv`, `--heartbeat` | verbosidade / progresso |
</details>

---

## Códigos de saída

`0` sem achados · `1` achados encontrados · `2` erro de uso · `3` falta `--yes`
(ou falta `--yes-full` no modo full).

---

## Arquitetura

```
paramhunter.py            CLI / orquestração
core/
  target.py               modelo de requisição + pontos (query/body/json/header/cookie/path) + curl_repro
  http_client.py          engine HTTP async (httpx): concorrência, rate-limit, retries, streaming c/ cap,
                          Retry-After, verbose, HTTP/2, stealth
  scope.py                trava de escopo (allow/deny por host e *.dominio)
  discovery.py            enumeração de parâmetros ocultos (HTML + reflexão c/ bisseção + diferencial)
  enum.py                 enumeração de domínio (gau + paramspider) + dedup por endpoint
  detector.py             detectores: signature, reflection, time, diff, redirect, crlf, oob
  waf.py / waf_cache.py   detecção/fingerprint/evasão de WAF + cache persistente
  oob.py                  callbacks out-of-band (embutido / externo / webhook.site)
  engine.py               loop módulo × ponto × payload × variante (o orquestrador)
  reporter.py             console colorido + CONFIRMADOS verde + JSON/JSONL/SARIF/PoC
  report_html.py          relatório HTML autocontido
  auth.py / crawler.py / intel.py / correlate.py / jwt.py / dom.py / race.py / graphql.py / openapi.py /
  importer.py / websocket.py
encoders/transforms.py    58 encoders de bypass/encoding
modules/base.py           módulo de vuln orientado a dados (YAML) + modelo Finding
payloads/*.yaml           bibliotecas de payloads por classe (~510 payloads)
wordlists/                params.txt, api_fields.txt
tests/                    selftest.py (regressão), benchmark.py (recall/FP), test_units.py (offline), vuln_server.py (lab)
```

**Fluxo:** parsing do alvo → escopo → gate `--yes`/`--yes-full` → [auth] →
[enumeração/crawler] → por endpoint: descoberta → fingerprint WAF → técnicas →
**fuzzing** (baseline estável → FASE 1 concorrente → FASE 2 evasão se WAF →
oráculo booleano → time-based serial) → resolve OOB → correlação → relatório.

---

## Estender

Adicionar uma classe de vulnerabilidade = criar um YAML em `payloads/`:

```yaml
name: minhavuln
description: ...
detectors: [signature, time, diff]
transforms: [url, url_double, case_random]
signatures: ['regex de evidencia']
payloads:
  - { value: "payload {MARK}", tags: [x] }
  - { value: "payload lento", tags: [blind], delay: 5 }
  - { value: "callback {OOBURL}", tags: [oob], oob: true }
```

Placeholders: `{MARK}` (reflexão), `{OOBURL}`/`{OOBHOST}`/`{OOBFQDN}` (OOB). Novos
transforms: registre com `@register("nome")` em `encoders/transforms.py`.

---

## Testes

```bash
python3 tests/test_units.py      # offline (encoders/detector/enum/http), instantâneo — 38 casos
python3 tests/selftest.py        # sobe o lab e valida cada módulo/técnica — 22 casos
python3 tests/benchmark.py       # mede recall (detecção) e taxa de FP de alta confiança
```

O benchmark roda contra endpoints vulneráveis **e** limpos e reporta recall +
FP-alto. Resultado atual: **recall 100% (10/10 classes), 0 falso-positivo de alta
confiança**.

---

## Segurança e uso legal

- **Travas:** allowlist de escopo (auto-derivada dos alvos) + gate `--yes`
  (autorização) + gate `--yes-full` (volume agressivo).
- **Só teste o que você tem permissão explícita para testar.** O modo full envia
  **milhares de payloads de ataque** — contra produção de terceiro é o tipo de
  volume que causa dano, ban e responsabilização.
- **Endpoints de ação** (criar/confirmar/cancelar/enviar): fuzzar esses pode
  disparar ações reais. Prefira importar o request real (`--request-file`/`--curl`)
  e teste com cuidado; evite volume agressivo neles.
