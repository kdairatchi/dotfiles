#!/usr/bin/env bash
# secure_comms.sh
# All-in-One Secure Communications Installer/Configurator (idempotent)

set -Eeuo pipefail
IFS=$'\n\t'

log()   { printf "\033[0;32m[+]\033[0m %s\n" "$*"; }
warn()  { printf "\033[0;33m[!]\033[0m %s\n" "$*"; }
err()   { printf "\033[0;31m[-]\033[0m %s\n" "$*" 1>&2; }
die()   { err "$*"; exit 1; }

usage() {
  cat <<USAGE
Secure Communications Setup

Environment toggles (set to 1 to skip):
  SKIP_SIGNAL, SKIP_ELEMENT, SKIP_GPG, SKIP_TOR, SKIP_PROXYCHAINS
Extras:
  VERIFY_TOR=1   Verify Tor connectivity after install
  VERBOSE=1      Verbose execution (set -x)

Examples:
  SKIP_SIGNAL=1 VERIFY_TOR=1 bash secure_comms.sh
USAGE
}

require_sudo() {
  command -v sudo >/dev/null 2>&1 || die "sudo is required. Install and re-run."
  if ! sudo -n true 2>/dev/null; then
    warn "Elevated privileges required. You may be prompted for your password."
  fi
}

is_wsl() {
  grep -qi 'microsoft' /proc/version 2>/dev/null || grep -qi 'WSL' /proc/sys/kernel/osrelease 2>/dev/null || return 1
}

wait_for_apt() {
  log "Waiting for package manager locks to be released..."
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
  local waited=0
  while :; do
    local busy=false
    for l in "${locks[@]}"; do
      if sudo fuser "$l" >/dev/null 2>&1; then busy=true; fi
    done
    if ! $busy; then break; fi
    sleep 2
    waited=$((waited+2))
    if (( waited > 300 )); then warn "Still waiting for locks after ${waited}s..."; fi
  done
}

apt_update_needed=false

apt_install_if_missing() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    log "$pkg already installed"
  else
    wait_for_apt
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends "$pkg"
  fi
}

install_prereqs() {
  wait_for_apt
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg gpg apt-transport-https lsb-release
}

add_signal_repo_if_needed() {
  # Signal currently ships amd64 builds. Skip on non-amd64.
  local arch
  arch="$(dpkg --print-architecture)"
  if [[ "$arch" != "amd64" ]]; then
    warn "Signal apt repo is only available for amd64. Skipping (arch=$arch)."
    return 1
  fi

  local keyring="/usr/share/keyrings/signal-desktop-archive-keyring.gpg"
  local listfile="/etc/apt/sources.list.d/signal-desktop.list"
  local repo_line="deb [arch=amd64 signed-by=${keyring}] https://updates.signal.org/desktop/apt xenial main"

  if [[ ! -s "$keyring" ]]; then
    log "Adding Signal keyring"
    curl -fsSL https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor | sudo tee "$keyring" >/dev/null
    sudo chmod 0644 "$keyring"
    apt_update_needed=true
  fi

  if [[ ! -s "$listfile" ]] || ! grep -Fq "updates.signal.org" "$listfile" 2>/dev/null; then
    log "Adding Signal apt source"
    echo "$repo_line" | sudo tee "$listfile" >/dev/null
    sudo chmod 0644 "$listfile"
    apt_update_needed=true
  fi
}

add_element_repo_if_needed() {
  local keyring="/usr/share/keyrings/element-io-archive-keyring.gpg"
  local listfile="/etc/apt/sources.list.d/element-io.list"
  local repo_line="deb [signed-by=${keyring}] https://packages.element.io/debian/ default main"

  if [[ ! -s "$keyring" ]]; then
    log "Adding Element keyring"
    sudo curl -fsSL -o "$keyring" https://packages.element.io/debian/element-io-archive-keyring.gpg
    sudo chmod 0644 "$keyring"
    apt_update_needed=true
  fi

  if [[ ! -s "$listfile" ]] || ! grep -Fq "packages.element.io" "$listfile" 2>/dev/null; then
    log "Adding Element apt source"
    echo "$repo_line" | sudo tee "$listfile" >/dev/null
    sudo chmod 0644 "$listfile"
    apt_update_needed=true
  fi
}

configure_gpg_hardened() {
  log "Configuring hardened GnuPG settings"
  umask 077
  mkdir -p "$HOME/.gnupg"
  chmod 700 "$HOME/.gnupg"

  local gpg_conf="$HOME/.gnupg/gpg.conf"

  if [[ -f "$gpg_conf" && ! -f "$gpg_conf.bak" ]]; then
    cp -f "$gpg_conf" "$gpg_conf.bak"
    warn "Existing gpg.conf backed up to gpg.conf.bak"
  fi

  cat > "$gpg_conf" << 'GPGEOF'
# Hardened preferences for new operations. Does not alter existing keys.
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
s2k-mode 3
# A conservative S2K count. Modern defaults may be higher; this is a floor.
s2k-count 65536

# Reduce metadata
no-emit-version
no-comments
armor

# Disable legacy/weak algorithms
disable-cipher-algo 3DES
GPGEOF

  chmod 600 "$gpg_conf"
}

file_backup_once() {
  # Usage: file_backup_once /path/to/file
  local target="$1"
  if [[ -f "$target" && ! -f "${target}.bak" ]]; then
    sudo cp -f "$target" "${target}.bak"
    warn "Backed up $(basename "$target") to $(basename "$target").bak"
  fi
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]
}

install_and_configure_tor() {
  log "Installing Tor"
  apt_install_if_missing tor

  local torrc="/etc/tor/torrc"
  if [[ -f "$torrc" ]]; then
    file_backup_once "$torrc"
  fi

  # Try to enable and start Tor service if systemd is available; otherwise use service
  if has_systemd; then
    log "Enabling Tor service (systemd)"
    sudo systemctl enable tor >/dev/null 2>&1 || true
    sudo systemctl restart tor >/dev/null 2>&1 || sudo systemctl start tor >/dev/null 2>&1 || true
    sudo systemctl --no-pager --full status tor >/dev/null 2>&1 || warn "Tor service status not available"
  else
    if command -v service >/dev/null 2>&1; then
      log "Starting Tor via service"
      sudo service tor restart >/dev/null 2>&1 || sudo service tor start >/dev/null 2>&1 || true
    else
      warn "No service manager detected. Tor installed but not started."
    fi
  fi

  log "Tor setup completed. Default SOCKS at 127.0.0.1:9050"
}

install_and_configure_proxychains() {
  log "Installing proxychains"
  # Debian/Kali typically package as proxychains4
  if ! dpkg -s proxychains4 >/dev/null 2>&1; then
    # Fallback to proxychains if proxychains4 is unavailable
    if ! apt_install_if_missing proxychains4; then
      apt_install_if_missing proxychains || true
    fi
  else
    log "proxychains4 already installed"
  fi

  local conf=""
  if [[ -f "/etc/proxychains4.conf" ]]; then
    conf="/etc/proxychains4.conf"
  elif [[ -f "/etc/proxychains.conf" ]]; then
    conf="/etc/proxychains.conf"
  else
    warn "No proxychains config file found. Skipping configuration."
    return 0
  fi

  file_backup_once "$conf"

  log "Configuring $conf for Tor at 127.0.0.1:9050"
  # Prefer dynamic_chain, enable proxy_dns, and ensure socks5 entry
  sudo sed -ri \
    -e 's/^[[:space:]]*#?dynamic_chain.*/dynamic_chain/' \
    -e 's/^[[:space:]]*(strict_chain|random_chain).*/# \1/' \
    -e 's/^[[:space:]]*#?proxy_dns.*/proxy_dns/' \
    "$conf"

  # Remove duplicate localhost 9050 entries (any socks4/5)
  if grep -Eq '^[[:space:]]*socks(4|5)[[:space:]]+127\.0\.0\.1[[:space:]]+9050([[:space:]]|$)' "$conf"; then
    # Keep the first occurrence; delete subsequent ones
    # Use awk to deduplicate lines matching the socks proxy
    sudo awk 'BEGIN{IGNORECASE=1} {
      line=$0; if (match(line, /^[[:space:]]*socks(4|5)[[:space:]]+127\.0\.0\.1[[:space:]]+9050([[:space:]]|$)/)) { if(seen++) next }
      print $0
    }' "$conf" | sudo tee "$conf.tmp" >/dev/null && sudo mv "$conf.tmp" "$conf"
  fi

  if ! grep -Eq '^[[:space:]]*socks5[[:space:]]+127\.0\.0\.1[[:space:]]+9050([[:space:]]|$)' "$conf"; then
    printf "\n# Added by secure_comms.sh\nsocks5 127.0.0.1 9050\n" | sudo tee -a "$conf" >/dev/null
  fi

  sudo chmod 0644 "$conf"
  log "proxychains configured. Usage: proxychains <command>"
}

verify_tor_connectivity() {
  if [[ "${VERIFY_TOR:-0}" != "1" ]]; then
    return 0
  fi
  log "Verifying Tor connectivity via curl --socks5-hostname 127.0.0.1:9050"
  if command -v curl >/dev/null 2>&1; then
    if curl --max-time 15 --fail -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip | grep -q 'IsTor"\s*:\s*true'; then
      log "Tor connectivity verified"
    else
      warn "Unable to verify Tor connectivity. Tor may be initializing or blocked."
    fi
  else
    warn "curl not found; skipping Tor verification"
  fi
}

main() {
  log "Starting Secure Communications Suite setup"

  if [[ "${VERBOSE:-0}" == "1" ]]; then set -x; fi

  if is_wsl; then
    warn "Running under WSL. GUI apps require WSLg or an X server."
  fi

  require_sudo
  install_prereqs

  # Toggles via environment variables: set to 1 to skip a section
  : "${SKIP_SIGNAL:=0}"
  : "${SKIP_ELEMENT:=0}"
  : "${SKIP_GPG:=0}"
  : "${SKIP_TOR:=0}"
  : "${SKIP_PROXYCHAINS:=0}"

  if [[ "$SKIP_SIGNAL" != "1" ]]; then
    add_signal_repo_if_needed || true
  else
    warn "Skipping Signal setup due to SKIP_SIGNAL=1"
  fi

  if [[ "$SKIP_ELEMENT" != "1" ]]; then
    add_element_repo_if_needed || true
  else
    warn "Skipping Element setup due to SKIP_ELEMENT=1"
  fi

  if $apt_update_needed; then
    wait_for_apt
    sudo apt-get update -qq
  fi

  if [[ "$SKIP_SIGNAL" != "1" ]]; then
    apt_install_if_missing signal-desktop || true
  fi

  if [[ "$SKIP_ELEMENT" != "1" ]]; then
    apt_install_if_missing element-desktop || true
  fi

  if [[ "$SKIP_GPG" != "1" ]]; then
    configure_gpg_hardened
  else
    warn "Skipping GPG configuration due to SKIP_GPG=1"
  fi

  if [[ "$SKIP_TOR" != "1" ]]; then
    install_and_configure_tor || warn "Tor install/config encountered an issue"
  else
    warn "Skipping Tor setup due to SKIP_TOR=1"
  fi

  if [[ "$SKIP_PROXYCHAINS" != "1" ]]; then
    install_and_configure_proxychains || warn "Proxychains install/config encountered an issue"
  else
    warn "Skipping proxychains setup due to SKIP_PROXYCHAINS=1"
  fi

  verify_tor_connectivity

  log "Setup complete. Installed/updated: Signal (if supported), Element, Tor, proxychains, and hardened GPG config."
}

main "$@"

exit 0
