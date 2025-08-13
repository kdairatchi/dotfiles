#!/usr/bin/env bash
# Unified installer: sets up dotfiles, tools, and portable aliases in one go.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log(){ printf "\033[32m[install]\033[0m %s\n" "$*"; }
warn(){ printf "\033[33m[warn]\033[0m %s\n" "$*"; }

main(){
  cd "$ROOT_DIR"
  log "Running base setup..."
  bash "$ROOT_DIR/install/setup.sh"

  if [ -f "$ROOT_DIR/install/tools.sh" ]; then
    log "Installing advanced tools..."
    bash "$ROOT_DIR/install/tools.sh" || warn "Advanced tools finished with warnings"
  fi

  if [ -f "$ROOT_DIR/kda-bootstrap.sh" ]; then
    log "Configuring portable aliases..."
    bash "$ROOT_DIR/kda-bootstrap.sh" --install --yes || warn "Bootstrap finished with warnings"
  fi

  log "All done. Restart your terminal or run: source ~/.kda/aliases/loader.sh"
}

main "$@"
