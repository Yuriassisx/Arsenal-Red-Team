#!/usr/bin/env bash
# =============================================================================
# ParamHunter — installer
#
# Instala a ferramenta (TUDO menos tests/) num prefixo isolado com venv próprio,
# e cria o comando `paramhunter` no PATH. Também detecta/instala as ferramentas
# externas opcionais (gau, paramspider, chromium).
#
# Uso:
#   ./install.sh                    # instala (venv + comando paramhunter)
#   ./install.sh --with-tools       # + tenta instalar gau/paramspider/chromium
#   ./install.sh --prefix ~/apps/ph # prefixo custom
#   ./install.sh uninstall          # remove
#
# Root (/opt + /usr/local/bin) usa sudo automaticamente; sem root cai p/ ~/.local.
# =============================================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- cores ----
if [ -t 1 ]; then R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; B=$'\033[1m'; Z=$'\033[0m';
else R=; G=; Y=; C=; B=; Z=; fi
info(){ echo "${C}[*]${Z} $*"; }
ok(){   echo "${G}[+]${Z} $*"; }
warn(){ echo "${Y}[!]${Z} $*"; }
err(){  echo "${R}[x]${Z} $*" >&2; }

# ---- defaults / args ----
WITH_TOOLS=0
ACTION="install"
if [ "$(id -u)" -eq 0 ]; then
  DEF_PREFIX="/opt/paramhunter"; DEF_BIN="/usr/local/bin"; SUDO=""
else
  DEF_PREFIX="$HOME/.local/share/paramhunter"; DEF_BIN="$HOME/.local/bin"; SUDO="sudo"
fi
PREFIX="${PREFIX:-$DEF_PREFIX}"
BIN_DIR="${BIN_DIR:-$DEF_BIN}"

while [ $# -gt 0 ]; do
  case "$1" in
    uninstall)      ACTION="uninstall" ;;
    --with-tools)   WITH_TOOLS=1 ;;
    --prefix)       PREFIX="$2"; shift ;;
    --bin)          BIN_DIR="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -20; exit 0 ;;
    *) err "argumento desconhecido: $1"; exit 2 ;;
  esac
  shift
done

LAUNCHER="$BIN_DIR/paramhunter"

# sudo só é necessário fora do $HOME
need_sudo(){ case "$PREFIX $BIN_DIR" in *"$HOME"*) echo "";; *) echo "$SUDO";; esac; }
S="$(need_sudo)"

# =============================================================================
# UNINSTALL
# =============================================================================
if [ "$ACTION" = "uninstall" ]; then
  info "removendo ParamHunter..."
  $S rm -rf "$PREFIX"
  $S rm -f "$LAUNCHER"
  ok "removido: $PREFIX  e  $LAUNCHER"
  exit 0
fi

# =============================================================================
# INSTALL
# =============================================================================
echo "${B}${C}"
echo "  ParamHunter — installer"
echo "${Z}  prefixo: $PREFIX"
echo "  comando: $LAUNCHER"
echo

# ---- 1) pré-requisitos ----
command -v python3 >/dev/null || { err "python3 não encontrado"; exit 1; }
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
info "python $PYV"
python3 -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,8) else 1)' \
  || { err "requer Python 3.8+"; exit 1; }
python3 -m venv --help >/dev/null 2>&1 || { err "módulo venv ausente (apt install python3-venv)"; exit 1; }

# ---- 2) copia SÓ os componentes da ferramenta (allowlist) ----
# Allowlist em vez de denylist: assim NUNCA copiamos tests/, caches, nem os
# outputs/scratch do usuário (achados.json, *.html, laudos — que podem ter dados
# sensíveis). tests/ fica de fora simplesmente por não estar na lista.
info "instalando componentes da ferramenta em $PREFIX (sem tests/ nem outputs)..."
$S mkdir -p "$PREFIX"
COMPONENTS=(paramhunter.py requirements.txt README.md core encoders modules payloads wordlists)
copied=0
for c in "${COMPONENTS[@]}"; do
  if [ -e "$SRC_DIR/$c" ]; then
    $S cp -r "$SRC_DIR/$c" "$PREFIX"/ && copied=$((copied+1))
  else
    warn "componente ausente na origem: $c"
  fi
done
# remove caches que possam ter vindo dentro dos diretórios
$S find "$PREFIX" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
$S find "$PREFIX" -type f -name '*.pyc' -delete 2>/dev/null || true
ok "$copied componentes instalados (tests/ e outputs ficaram de fora)"

# ---- 3) venv + dependências ----
info "criando venv e instalando dependências (httpx, aiohttp, PyYAML, h2)..."
$S python3 -m venv "$PREFIX/venv"
VENV_PY="$PREFIX/venv/bin/python"
$S "$VENV_PY" -m pip install --quiet --upgrade pip
if [ -f "$PREFIX/requirements.txt" ]; then
  $S "$VENV_PY" -m pip install --quiet -r "$PREFIX/requirements.txt"
fi
$S "$VENV_PY" -m pip install --quiet "h2>=4.0"   # habilita --http2
ok "dependências Python instaladas no venv"

# ---- 4) launcher no PATH ----
info "criando o comando 'paramhunter' em $LAUNCHER..."
$S mkdir -p "$BIN_DIR"
TMP_LAUNCH="$(mktemp)"
cat > "$TMP_LAUNCH" <<EOF
#!/usr/bin/env bash
# launcher gerado pelo install.sh do ParamHunter
exec "$PREFIX/venv/bin/python" "$PREFIX/paramhunter.py" "\$@"
EOF
$S install -m 0755 "$TMP_LAUNCH" "$LAUNCHER"
rm -f "$TMP_LAUNCH"
ok "comando instalado: paramhunter"

# ---- 5) ferramentas externas opcionais ----
echo
info "ferramentas opcionais (habilitam -d/--domain e --headless):"
check_tool(){ if command -v "$1" >/dev/null; then ok "$1: presente"; return 0; else warn "$1: ausente"; return 1; fi; }

have_gau=0; check_tool gau && have_gau=1
have_ps=0;  check_tool paramspider && have_ps=1
have_cr=0;  { command -v chromium >/dev/null || command -v chromium-browser >/dev/null; } \
              && { ok "chromium: presente"; have_cr=1; } || warn "chromium: ausente"

if [ "$WITH_TOOLS" -eq 1 ]; then
  echo
  info "--with-tools: tentando instalar as ausentes..."
  # gau (via go)
  if [ "$have_gau" -eq 0 ]; then
    if command -v go >/dev/null; then
      info "instalando gau via go..."
      go install github.com/lc/gau/v2/cmd/gau@latest && ok "gau instalado (garanta ~/go/bin no PATH)" || warn "falha ao instalar gau"
    else
      warn "gau: instale Go e rode 'go install github.com/lc/gau/v2/cmd/gau@latest'"
    fi
  fi
  # paramspider (via pipx ou pip --user)
  if [ "$have_ps" -eq 0 ]; then
    if command -v pipx >/dev/null; then
      info "instalando paramspider via pipx..."
      pipx install git+https://github.com/devanshbatham/paramspider && ok "paramspider instalado" || warn "falha ao instalar paramspider"
    else
      warn "paramspider: instale pipx ('apt install pipx') e rode 'pipx install git+https://github.com/devanshbatham/paramspider'"
    fi
  fi
  # chromium (via apt)
  if [ "$have_cr" -eq 0 ]; then
    if command -v apt-get >/dev/null; then
      info "instalando chromium via apt..."
      $SUDO apt-get update -qq && $SUDO apt-get install -y chromium 2>/dev/null || \
        $SUDO apt-get install -y chromium-browser 2>/dev/null || warn "falha ao instalar chromium (instale manualmente)"
      command -v chromium >/dev/null || command -v chromium-browser >/dev/null && ok "chromium instalado"
    else
      warn "chromium: instale pelo gerenciador de pacotes do seu sistema"
    fi
  fi
else
  echo "    (rode com ${B}--with-tools${Z} para tentar instalá-las, ou instale manualmente:)"
  echo "      gau         -> go install github.com/lc/gau/v2/cmd/gau@latest"
  echo "      paramspider -> pipx install git+https://github.com/devanshbatham/paramspider"
  echo "      chromium    -> apt install chromium"
fi

# ---- 6) verificação + PATH ----
echo
if "$PREFIX/venv/bin/python" "$PREFIX/paramhunter.py" --version >/dev/null 2>&1; then
  VER="$("$PREFIX/venv/bin/python" "$PREFIX/paramhunter.py" --version 2>&1)"
  ok "instalado com sucesso: $VER"
else
  err "algo deu errado na verificação — cheque as dependências"
  exit 1
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) warn "$BIN_DIR não está no PATH. Adicione ao seu shell rc:"
     echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo
echo "${B}${G}Pronto!${Z} Uso:"
echo "  ${C}paramhunter --examples${Z}                      # guia de usos"
echo "  ${C}paramhunter -u 'https://alvo/p?id=1' -m sqli --light --yes${Z}"
echo "  ${C}paramhunter -d alvo.com --enum-subs --yes --yes-full${Z}"
echo
echo "Desinstalar:  ${C}./install.sh uninstall${Z}"
