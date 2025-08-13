#!/usr/bin/env bash
# =========================================================
#  Toolkit Maintainer — validator, fixer, updater
#  Purpose: keep scripts and tools healthy even when things break
#  Author: kdairatchi toolkit helpers
# =========================================================

set -Eeuo pipefail
IFS=$'\n\t'

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()      { printf "${CYAN}[i]${NC} %s\n" "$*"; }
ok()       { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()     { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()      { printf "${RED}[-]${NC} %s\n" "$*"; }
headline() { printf "\n${BLUE}==> %s${NC}\n" "$*"; }

# ---------- Defaults ----------
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DRY_RUN=0
DO_VALIDATE=0
DO_FIX=0
DO_UPDATE_TOOLS=0
DO_UPDATE_GO=0
DO_UPDATE_PY=0
DO_UPDATE_DOCKER=0
DO_SUBMODULES=0
FAST=0

# Known Go tools to install/update
GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/tomnomnom/assetfinder@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/projectdiscovery/urldedupe/cmd/urldedupe@latest
  github.com/ffuf/ffuf@latest
  github.com/tomnomnom/gf@latest
  github.com/hahwul/dalfox/v2@latest
  github.com/Emoe/kxss@latest
  github.com/KathanP19/Gxss@latest
)

# Suggested apt tools
APT_TOOLS=(shellcheck shfmt parallel jq nmap git curl wget)

# Python libs commonly used across tools
PY_LIBS=(
  aiohttp aiofiles requests pyyaml bs4 colorama rich shodan
  playwright
)

# Docker images to refresh
DOCKER_IMAGES=(
  projectdiscovery/subfinder:latest
  projectdiscovery/httpx:latest
  projectdiscovery/nuclei:latest
)

usage() {
  cat <<EOF
Toolkit Maintainer — validate, fix, and update the toolkit

Usage: $(basename "$0") [options]

Options:
  --validate         Run validators (bash -n, python compile, shellcheck if present)
  --fix              Apply safe fixes (exec bits, optional shfmt if available)
  --update-tools     High-level: perform submodules, go, python, docker updates
  --update-go        Update Go-based CLI tools (@latest)
  --update-python    Install/update common Python libs (user scope)
  --update-docker    Pull latest docker images (projectdiscovery)
  --submodules       git submodule init/update (e.g., wordlists)
  --fast             Skip slower checks (shellcheck, docker pulls) where possible
  --dry-run          Show what would be done without changing the system
  --all              Equivalent to: --validate --fix --update-tools --submodules
  -h, --help         Show this help

Examples:
  $(basename "$0") --validate --fix
  $(basename "$0") --update-tools --submodules
  $(basename "$0") --all --fast
EOF
}

# ---------- Helpers ----------
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf "DRY-RUN: %s\n" "$*"
  else
    eval "$*"
  fi
}

has() { command -v "$1" >/dev/null 2>&1; }

ensure_exec_bits() {
  headline "Fix: ensure executable bits on scripts"
  local count=0
  while IFS= read -r -d '' f; do
    if [[ ! -x "$f" ]]; then
      run "chmod +x \"$f\""
      ((count++)) || true
    fi
  done < <(find "$ROOT_DIR" -type f \( -name "*.sh" -o -name "*.py" \) -print0)
  ok "Ensured exec bits on $count files"
}

validate_shell() {
  headline "Validate: bash syntax (bash -n)"
  local bad=0 total=0
  while IFS= read -r -d '' f; do
    ((total++)) || true
    if ! bash -n "$f" 2>/tmp/maintain_bash_err; then
      err "bash -n failed: $f"
      sed -e 's/^/  /' /tmp/maintain_bash_err || true
      ((bad++)) || true
    fi
  done < <(find "$ROOT_DIR" -type f -name "*.sh" -print0)
  if (( bad == 0 )); then ok "bash -n OK on $total shell files"; else warn "$bad shell files failed syntax"; fi
}

validate_shellcheck() {
  if ! has shellcheck; then warn "shellcheck not installed; skipping"; return 0; fi
  if (( FAST == 1 )); then warn "--fast set: skipping shellcheck"; return 0; fi
  headline "Validate: shellcheck"
  local bad=0 total=0
  while IFS= read -r -d '' f; do
    ((total++)) || true
    if ! shellcheck -x "$f"; then ((bad++)) || true; fi
  done < <(find "$ROOT_DIR" -type f -name "*.sh" -print0)
  if (( bad == 0 )); then ok "shellcheck OK on $total files"; else warn "$bad shell files need attention"; fi
}

validate_python() {
  headline "Validate: python compile"
  local bad=0 total=0
  while IFS= read -r -d '' f; do
    ((total++)) || true
    if ! python3 -m py_compile "$f" 2>/tmp/maintain_py_err; then
      err "python compile failed: $f"
      sed -e 's/^/  /' /tmp/maintain_py_err || true
      ((bad++)) || true
    fi
  done < <(find "$ROOT_DIR" -type f -name "*.py" -print0)
  if (( bad == 0 )); then ok "Python compile OK on $total files"; else warn "$bad python files failed compilation"; fi
}

optional_shfmt() {
  if ! has shfmt; then warn "shfmt not installed; skipping format"; return 0; fi
  headline "Fix: shfmt formatting (idempotent)"
  while IFS= read -r -d '' f; do
    run "shfmt -w -i 2 -ci -sr \"$f\""
  done < <(find "$ROOT_DIR" -type f -name "*.sh" -print0)
  ok "shfmt applied"
}

update_submodules() {
  headline "Update: git submodules"
  run "git submodule update --init --recursive"
  run "git submodule foreach --recursive git reset --hard || true"
  run "git submodule foreach --recursive git pull --ff-only || true"
  ok "Submodules updated"
}

update_go() {
  headline "Update: Go tools (@latest)"
  if ! has go; then err "Go is not installed"; return 1; fi
  for mod in "${GO_TOOLS[@]}"; do
    log "go install $mod"
    run "GO111MODULE=on go install -v $mod"
  done
  ok "Go tools updated"
}

update_python() {
  headline "Update: Python libraries (user scope)"
  if ! has pip3; then err "pip3 not found"; return 1; fi
  for lib in "${PY_LIBS[@]}"; do
    log "pip3 install --user -U $lib"
    run "pip3 install --user -U $lib"
  done
  # Special: playwright browser binaries
  if has playwright; then
    log "Ensuring Playwright browsers"
    run "playwright install --with-deps || true"
  fi
  ok "Python libraries updated"
}

update_docker() {
  if ! has docker; then warn "docker not installed; skipping"; return 0; fi
  if (( FAST == 1 )); then warn "--fast set: skipping docker pulls"; return 0; fi
  headline "Update: docker images"
  for img in "${DOCKER_IMAGES[@]}"; do
    log "docker pull $img"
    run "docker pull $img"
  done
  ok "Docker images refreshed"
}

update_tools_bundle() {
  headline "Update: toolchain bundle"
  update_submodules || true
  update_go || true
  update_python || true
  update_docker || true
  ok "Toolchain bundle updated"
}

check_binaries() {
  headline "Validate: required/common binaries presence"
  local missing=()
  local need=( subfinder httpx nuclei katana gau waybackurls ffuf gf qsreplace urldedupe naabu parallel jq )
  for b in "${need[@]}"; do
    if ! has "$b"; then missing+=("$b"); fi
  done
  if ((${#missing[@]}==0)); then ok "All common binaries found"; else warn "Missing: ${missing[*]}"; fi
}

print_summary() {
  echo
  headline "Summary"
  check_binaries || true
  ok "Done"
}

# ---------- Argparse ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --validate) DO_VALIDATE=1; shift ;;
    --fix) DO_FIX=1; shift ;;
    --update-tools) DO_UPDATE_TOOLS=1; shift ;;
    --update-go) DO_UPDATE_GO=1; shift ;;
    --update-python) DO_UPDATE_PY=1; shift ;;
    --update-docker) DO_UPDATE_DOCKER=1; shift ;;
    --submodules) DO_SUBMODULES=1; shift ;;
    --fast) FAST=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --all) DO_VALIDATE=1; DO_FIX=1; DO_UPDATE_TOOLS=1; DO_SUBMODULES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) warn "Unknown option: $1"; usage; exit 1 ;;
  esac
done

headline "Toolkit Maintainer"
log "Root: $ROOT_DIR"
log "Dry run: $DRY_RUN | Fast: $FAST"

cd "$ROOT_DIR"

# Validation
if (( DO_VALIDATE == 1 )); then
  validate_shell || true
  validate_shellcheck || true
  validate_python || true
fi

# Fixers
if (( DO_FIX == 1 )); then
  ensure_exec_bits || true
  optional_shfmt || true
fi

# Updaters
if (( DO_SUBMODULES == 1 )); then update_submodules || true; fi
if (( DO_UPDATE_GO == 1 )); then update_go || true; fi
if (( DO_UPDATE_PY == 1 )); then update_python || true; fi
if (( DO_UPDATE_DOCKER == 1 )); then update_docker || true; fi
if (( DO_UPDATE_TOOLS == 1 )); then update_tools_bundle || true; fi

print_summary
