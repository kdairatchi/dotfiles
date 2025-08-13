#!/usr/bin/env bash
# smartcli-ultra.sh — AI-enhanced CLI for managing & fixing oneliners
# Author: Kdairatchi edition (Ultra)
# Version: 3.1.0
# License: MIT

set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# Paths & Constants
# ────────────────────────────────────────────────────────────────────────────────
APP_NAME="smartcli-ultra"
HOME_DIR="${SMARTCLI_HOME:-$HOME/.smartcli_ultra}"
ONE_DIR="$HOME_DIR/oneliners"          # stores categorized *.sh files
DB_JSON="$HOME_DIR/oneliners.json"     # alternative JSON DB (array of objects)
SRC_JSON="$HOME_DIR/sources.json"      # { "sources":[{"name":"","url":"","enabled":true}] }
NOTES_DIR="$HOME_DIR/notes"            # run logs + generated notes
CACHE_DIR="$HOME_DIR/cache"
AI_CACHE="$HOME_DIR/ai_cache"
DISCOVERY_CACHE="$HOME_DIR/system_notes.cache"
CFG_JSON="$HOME_DIR/config.json"
HIST_FILE="$HOME_DIR/history.log"
API_KEYS="$HOME_DIR/.api_keys"

: "${EDITOR:=vi}"

# Default categories (including Bug Bounty and general Linux)
DEFAULT_CATEGORIES=(
  BugBounty Recon Web Network System Files Git Docker DevOps Security Cloud
  OSINT Databases Pentest WiFi Windows WSL Misc Custom
)

# API endpoints
OPENROUTER_URL="https://openrouter.ai/api/v1/chat/completions"
GROK_URL="https://api.x.ai/v1/chat/completions"
# Gemini: supply model suffix yourself (e.g., gemini-1.5-flash, gemini-1.5-pro)
GEMINI_BASE="https://generativelanguage.googleapis.com/v1beta/models"

# Colors
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'
MAG='\033[0;35m'; CYN='\033[0;36m'; WHT='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'

# Icons
CHK="✓"; X="✗"; BOT="🤖"; SRCH="🔍"; GEAR="⚙️"; ROCKET="🚀"; BOOK="📚"; STAR="★"

# Optional tools
has() { command -v "$1" >/dev/null 2>&1; }
HAS_JQ=$(has jq && echo 1 || echo 0)
HAS_FZF=$(has fzf && echo 1 || echo 0)
HAS_GUM=$(has gum && echo 1 || echo 0)
HAS_BAT=$(has bat && echo 1 || echo 0)
HAS_PANDOC=$(has pandoc && echo 1 || echo 0)
HAS_CURL=$(has curl && echo 1 || echo 0)

# ────────────────────────────────────────────────────────────────────────────────
# Utils
# ────────────────────────────────────────────────────────────────────────────────
die(){ printf "${RED}[ERR]${NC} %s\n" "$*" >&2; exit 1; }
note(){ printf "${CYN}[${APP_NAME}]${NC} %s\n" "$*"; }
ok(){ printf "${GRN}[ok]${NC} %s\n" "$*"; }
line(){ printf -- "────────────────────────────────────────────────────────────\n"; }

sed_inplace(){
  # BSD+GNU sed safe in-place
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

req(){
  for b in "$@"; do has "$b" || die "Missing dependency: $b"
  done
}

json_read(){
  [ "$HAS_JQ" -eq 1 ] || die "jq required"
  jq -r "$1" "$2"
}

json_write(){
  [ "$HAS_JQ" -eq 1 ] || die "jq required"
  local filter="$1"; local file="$2"; local tmp; tmp="$(mktemp)"
  jq "$filter" "$file" > "$tmp" && mv "$tmp" "$file"
}

stat_size(){
  # cross-platform stat for size
  stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo "0"
}

stat_mtime(){
  stat -c%y "$1" 2>/dev/null | cut -d' ' -f1 || stat -f%Sm -t "%Y-%m-%d" "$1" 2>/dev/null || date +%F
}

# ────────────────────────────────────────────────────────────────────────────────
# First-run init
# ────────────────────────────────────────────────────────────────────────────────
init_dirs(){
  mkdir -p "$HOME_DIR" "$ONE_DIR" "$NOTES_DIR" "$CACHE_DIR" "$AI_CACHE"
  [ -f "$DB_JSON" ] || printf '[]' > "$DB_JSON"
  [ -f "$SRC_JSON" ] || printf '{ "sources": [] }' > "$SRC_JSON"
  if [ ! -f "$CFG_JSON" ]; then
    cat >"$CFG_JSON" <<'JSON'
{
  "ai_enabled": true,
  "ai_provider": "openrouter",
  "ai_model": "anthropic/claude-3.5-sonnet",
  "fallback_providers": ["grok","google"],
  "gemini_model": "gemini-1.5-flash",
  "theme": "dark",
  "auto_correct": true,
  "auto_validate": true,
  "smart_suggestions": true,
  "history_size": 5000,
  "note_discovery": {
    "enabled": true,
    "paths": ["~/Documents","~/Notes","~/Obsidian","~/Desktop","~/.local/share","/usr/share/doc"],
    "extensions": ["md","txt","org","rst","adoc"]
  },
  "command_validation": {
    "syntax_check": true,
    "dependency_check": true,
    "security_scan": true,
    "optimization": true
  },
  "pdf_export": true
}
JSON
  fi
  if [ ! -f "$API_KEYS" ]; then
    cat >"$API_KEYS" <<'ENV'
# Populate as needed and remove leading '#'
# OPENROUTER_API_KEY=sk-or-v1-...
# GROK_API_KEY=xai-...
# GOOGLE_API_KEY=AIza...
# GITHUB_TOKEN=ghp_...
ENV
    chmod 600 "$API_KEYS"
    note "Configure API keys in $API_KEYS"
  fi
}

load_keys(){ [ -f "$API_KEYS" ] && . "$API_KEYS" || true; }

# Ensure default category directories exist
ensure_categories(){
  local cat
  for cat in "${DEFAULT_CATEGORIES[@]}"; do
    mkdir -p "$ONE_DIR/${cat,,}"
  done
}

# Automated install/setup
install_self(){
  init_dirs
  ensure_categories
  local bin_dir="$HOME/.local/bin"
  mkdir -p "$bin_dir"
  # Symlink unified entrypoint 'smartcli'
  if ln -sf "$(readlink -f "$0")" "$bin_dir/smartcli" 2>/dev/null; then
    ok "Linked → $bin_dir/smartcli"
  else
    note "Could not create symlink automatically; run: ln -sf \"$(readlink -f "$0")\" \"$bin_dir/smartcli\""
  fi
  # Add PATH if missing
  if ! printf '%s' "$PATH" | grep -q "$HOME/.local/bin"; then
    local shell_rc
    if [ -n "$BASH_VERSION" ]; then shell_rc="$HOME/.bashrc"; else shell_rc="$HOME/.profile"; fi
    if ! grep -qs "\.local/bin" "$shell_rc" 2>/dev/null; then
      printf '\n# smartcli-ultra PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$shell_rc"
      ok "Updated PATH in $shell_rc (restart shell)"
    fi
  fi
  # Optional daily notes scan cron
  if confirm "Add daily system notes scan at 9:00?"; then
    local cron_line="0 9 * * * $bin_dir/smartcli notes scan # smartcli-ultra"
    (crontab -l 2>/dev/null | grep -v 'smartcli-ultra' ; echo "$cron_line") | crontab -
    ok "Cron installed"
  fi
  ok "Install complete"
}

# ────────────────────────────────────────────────────────────────────────────────
# UI helpers
# ────────────────────────────────────────────────────────────────────────────────
title(){
  if [ "$HAS_GUM" -eq 1 ]; then gum style --bold --foreground 201 "$*"
  else printf "${MAG}%s${NC}\n" "$*"; fi
}

prompt(){
  local msg="$1"; shift || true
  if [ "$HAS_GUM" -eq 1 ]; then gum input --placeholder "$msg" "$@"
  else read -r -p "$msg: " REPLY; printf "%s" "$REPLY"; fi
}

confirm(){
  local msg="${1:-Proceed?}"
  if [ "$HAS_GUM" -eq 1 ]; then gum confirm "$msg"
  else read -r -p "$msg [y/N]: " yn; case "$yn" in [yY]|[yY][eE][sS]) return 0;; *) return 1;; esac; fi
}

picker(){
  # stdin list -> stdout chosen
  if [ "$HAS_FZF" -eq 1 ]; then
    fzf --height=85% --reverse --border --ansi --prompt="pick ▶ "
  else
    mapfile -t L; local i=1
    for it in "${L[@]}"; do printf "%2d) %s\n" "$i" "$it"; i=$((i+1)); done
    read -r -p "Select #: " n; [ -n "${L[$((n-1))]:-}" ] && echo "${L[$((n-1))]}"
  fi
}

# ────────────────────────────────────────────────────────────────────────────────
# Placeholder engine: {{var}} or {{var:default}}
# ────────────────────────────────────────────────────────────────────────────────
fill_placeholders(){
  local cmd="$1" out="$1"
  local keys
  keys=$(echo "$cmd" | grep -o '{{[^}]\+}}' || true)
  [ -z "$keys" ] && { printf '%s' "$cmd"; return; }
  local ph; while IFS= read -r ph; do
    local inner="${ph#{{}"; inner="${inner%}}"
    local key="${inner%%:*}"; local def=""
    [ "$inner" != "${inner#*:}" ] && def="${inner#*:}"
    local val; val="$(prompt "Value for $key" --value "$def")"; [ -z "$val" ] && val="$def"
    local e_ph e_val
    e_ph=$(printf '%s' "$ph" | sed 's/[.[\*^$(){}+?\/|]/\\&/g')
    e_val=$(printf '%s' "$val" | sed 's/[&/]/\\&/g')
    out=$(printf '%s' "$out" | sed "s/$e_ph/$e_val/g")
  done <<< "$keys"
  printf '%s' "$out"
}

# ────────────────────────────────────────────────────────────────────────────────
# Notes & PDF
# ────────────────────────────────────────────────────────────────────────────────
write_note(){
  local name="$1" cmd="$2" status="$3" out_f="$4" err_f="$5"
  local day="$NOTES_DIR/$(date +%F).md"
  {
    echo "## $name"
    echo ""
    echo "- **When:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "- **Status:** $status"
    echo ""
    echo "### Command"
    echo '```bash'; echo "$cmd"; echo '```'
    echo ""
    echo "### Output"
    echo '```'; cat "$out_f"; echo '```'
    echo ""
    echo "### Errors"
    echo '```'; cat "$err_f"; echo '```'
    echo ""
  } >> "$day"
  ok "Logged → $day"
  # Optional PDF export
  if [ "$HAS_PANDOC" -eq 1 ] && [ "$(json_read '.pdf_export' "$CFG_JSON")" = "true" ]; then
    local pdf="$NOTES_DIR/$(date +%F).pdf"
    pandoc "$day" -o "$pdf" 2>/dev/null && note "PDF updated → $pdf" || true
  fi
}

view_today_notes(){
  local f="$NOTES_DIR/$(date +%F).md"
  [ -f "$f" ] || die "No notes for today yet."
  if [ "$HAS_BAT" -eq 1 ]; then bat "$f"; else ${PAGER:-less} "$f"; fi
}

# ────────────────────────────────────────────────────────────────────────────────
# AI Providers (OpenRouter, Grok, Google Gemini)
# ────────────────────────────────────────────────────────────────────────────────
ai_openrouter(){
  local prompt="$1" model="${2:-$(json_read '.ai_model' "$CFG_JSON")}"
  load_keys; [ -n "${OPENROUTER_API_KEY:-}" ] || { echo "OpenRouter not configured"; return 1; }
  [ "$HAS_CURL" -eq 1 ] || die "curl required"

  local payload; payload=$(jq -n \
    --arg model "$model" \
    --arg sys "You are a shell expert. Reply in JSON unless asked otherwise." \
    --arg usr "$prompt" \
    '{model:$model,messages:[{role:"system",content:$sys},{role:"user",content:$usr}],temperature:0.2,max_tokens:800}')

  curl -sS "$OPENROUTER_URL" \
    -H "Authorization: Bearer $OPENROUTER_API_KEY" \
    -H "HTTP-Referer: https://github.com/kdairatchi" \
    -H "X-Title: smartcli-ultra" \
    -H "Content-Type: application/json" \
    -d "$payload" | jq -r '.choices[0].message.content // empty'
}

ai_grok(){
  local prompt="$1"
  load_keys; [ -n "${GROK_API_KEY:-}" ] || { echo "Grok not configured"; return 1; }
  [ "$HAS_CURL" -eq 1 ] || die "curl required"

  local payload; payload=$(jq -n \
    --arg sys "You are a CLI fixer. Return JSON with fields as requested." \
    --arg usr "$prompt" \
    '{model:"grok-beta",messages:[{role:"system",content:$sys},{role:"user",content:$usr}],temperature:0.2}')

  curl -sS "$GROK_URL" \
    -H "Authorization: Bearer $GROK_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$payload" | jq -r '.choices[0].message.content // empty'
}

ai_gemini(){
  local prompt="$1" model="${2:-$(json_read '.gemini_model' "$CFG_JSON")}"
  load_keys; [ -n "${GOOGLE_API_KEY:-}" ] || { echo "Google not configured"; return 1; }
  [ "$HAS_CURL" -eq 1 ] || die "curl required"

  local url="${GEMINI_BASE}/${model}:generateContent?key=${GOOGLE_API_KEY}"
  local payload; payload=$(jq -n \
    --arg t "$prompt" \
    '{contents:[{parts:[{text:$t}]}],generationConfig:{temperature:0.2,maxOutputTokens:800}}')

  curl -sS -H "Content-Type: application/json" -X POST "$url" -d "$payload" \
    | jq -r '.candidates[0].content.parts[0].text // empty'
}

ai_query(){
  local prompt="$1"
  [ "$(json_read '.ai_enabled' "$CFG_JSON")" = "true" ] || { echo "AI disabled"; return 1; }
  local primary; primary="$(json_read '.ai_provider' "$CFG_JSON")"
  local res=""
  case "$primary" in
    openrouter) res="$(ai_openrouter "$prompt" || true)";;
    grok)       res="$(ai_grok "$prompt" || true)";;
    google)     res="$(ai_gemini "$prompt" || true)";;
    *)          res="";;
  esac

  if [ -n "$res" ]; then echo "$res"; return 0; fi

  # fallbacks
  local fb; while read -r fb; do
    [ -z "$fb" ] && continue
    case "$fb" in
      openrouter) res="$(ai_openrouter "$prompt" || true)";;
      grok)       res="$(ai_grok "$prompt" || true)";;
      google)     res="$(ai_gemini "$prompt" || true)";;
    esac
    [ -n "$res" ] && { echo "$res"; return 0; }
  done < <(jq -r '.fallback_providers[]?' "$CFG_JSON" 2>/dev/null || true)

  echo "No AI provider available"; return 1
}

# ────────────────────────────────────────────────────────────────────────────────
# Security guardrails & validation
# ────────────────────────────────────────────────────────────────────────────────
dangerous_patterns=(
  'rm -rf /' ' :(){ :|:& };:'
  'dd if=' ' of=/dev/' 'mkfs.' '> /dev/sd' 'chmod -R 777 ' 'chown -R root: /'
)

validate_and_rewrite(){
  local command="$1" context="${2:-general}"
  line; title "$BOT  AI Command Validator"; line

  # Static syntax check
  local tf; tf="$(mktemp)"; printf '%s\n' "$command" > "$tf"
  local syntax=""; if ! bash -n "$tf" 2>/dev/null; then
    syntax="$(bash -n "$tf" 2>&1 || true)"
    printf "${YLW}⚠ Syntax issues detected${NC}\n${DIM}%s${NC}\n" "$syntax"
  fi
  rm -f "$tf"

  # Dangerous patterns
  for p in "${dangerous_patterns[@]}"; do
    if printf '%s' "$command" | grep -qE "$p"; then
      printf "${RED}!! Dangerous pattern detected:${NC} %s\n" "$p"
      confirm "I understand the risk and want to continue" || return 2
    fi
  done

  # AI optimization/repair to JSON
  local prompt_json
  prompt_json=$(cat <<'EOF'
Analyze and improve this bash command. Return STRICT JSON:
{
 "improved_command": "<fixed or optimized command>",
 "explanation": "<brief>",
 "warnings": ["..."],
 "dependencies": ["..."]
}
EOF
)
  local ask="Command:\n$command\nContext: $context\n\n$prompt_json"
  local resp; resp="$(ai_query "$ask" || true)"

  # Cache by md5 of command
  local key; key="$(printf '%s' "$command" | md5sum | awk '{print $1}')"
  printf '%s' "${resp:-}" > "$AI_CACHE/$key.json" 2>/dev/null || true

  if [ "$HAS_JQ" -eq 1 ] && [ -n "${resp:-}" ]; then
    local improved expl
    improved="$(printf '%s' "$resp" | jq -r '.improved_command // empty' 2>/dev/null || true)"
    expl="$(printf '%s' "$resp" | jq -r '.explanation // empty' 2>/dev/null || true)"
    if [ -n "$improved" ]; then
      printf "${GRN}${CHK} Improved Command:${NC}\n%s\n\n" "$improved"
      [ -n "$expl" ] && printf "${CYN}Explanation:${NC}\n${DIM}%s${NC}\n\n" "$expl"
      printf "${YLW}Dependencies:${NC}\n"
      printf '%s' "$resp" | jq -r '.dependencies[]?' 2>/dev/null | while read -r d; do
        [ -z "$d" ] && continue
        if has "$d"; then printf "  ${GRN}${CHK}${NC} %s\n" "$d"; else printf "  ${RED}${X}${NC} %s (missing)\n" "$d"; fi
      done
      echo
      printf "%s" "$improved"
      return 0
    fi
  fi
  echo "$command"
  return 0
}

# ────────────────────────────────────────────────────────────────────────────────
# Importers (file/url). Supported: JSON array of objects or pipe: name|cmd|tags|desc
# ────────────────────────────────────────────────────────────────────────────────
add_oneliner_json(){
  local name="$1" cmd="$2" tags="${3:-}" desc="${4:-}" cat="${5:-Custom}"
  local cat_dir="$ONE_DIR/${cat,,}"; mkdir -p "$cat_dir"
  local path="$cat_dir/$(echo "$name" | tr ' ' '_' | tr -cd '[:alnum:]_-').sh"
  {
    echo "#!/usr/bin/env bash"
    echo "# Description: ${desc}"
    echo "# Category: ${cat}"
    echo "# Tags: ${tags}"
    echo "# Created: $(date '+%F %T')"
    echo
    echo "$cmd"
  } > "$path"
  chmod +x "$path"
}

import_file(){
  local f="$1"; [ -f "$f" ] || die "Not found: $f"
  if [ "$HAS_JQ" -eq 1 ] && jq -e . >/dev/null 2>&1 < "$f"; then
    local count=0
    while IFS= read -r row; do
      local name cmd tags desc cat
      name="$(printf '%s' "$row" | jq -r '.name // empty')"
      cmd="$(printf '%s' "$row" | jq -r '.cmd // empty')"
      tags="$(printf '%s' "$row" | jq -r '.tags // ""')"
      desc="$(printf '%s' "$row" | jq -r '.desc // ""')"
      cat="$(printf  '%s' "$row" | jq -r '.category // "Custom"')"
      [ -n "$name" ] && [ -n "$cmd" ] && { add_oneliner_json "$name" "$cmd" "$tags" "$desc" "$cat"; count=$((count+1)); }
    done < <(jq -c '.[]' "$f")
    ok "Imported $count items from JSON."
  else
    local count=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      IFS='|' read -r name cmd tags desc cat <<< "$line"
      [ -n "${name:-}" ] && [ -n "${cmd:-}" ] && { add_oneliner_json "$name" "$cmd" "${tags:-}" "${desc:-}" "${cat:-Custom}"; count=$((count+1)); }
    done < "$f"
    ok "Imported $count items from pipe file."
  fi
}

import_url(){
  req curl
  local url="$1"; local tmp; tmp="$(mktemp)"
  curl -fsSL "$url" -o "$tmp" || die "Fetch failed: $url"
  import_file "$tmp"; rm -f "$tmp"
}

add_source(){ # name url
  [ "$HAS_JQ" -eq 1 ] || die "jq required"
  local name="$1" url="$2"
  json_write ".sources += [{\"name\":$(jq -Rn --arg v "$name" '$v'),\"url\":$(jq -Rn --arg v "$url" '$v'),\"enabled\":true}]" "$SRC_JSON"
  ok "Added source '$name'"
}

pull_sources(){
  [ "$HAS_JQ" -eq 1 ] || die "jq required"
  jq -r '.sources[] | select(.enabled==true) | "\(.name)\t\(.url)"' "$SRC_JSON" | \
  while IFS=$'\t' read -r n u; do
    note "Sync: $n ← $u"; import_url "$u" || note "Skip $n (failed)"
  done
}

# ────────────────────────────────────────────────────────────────────────────────
# Notes discovery & extraction
# ────────────────────────────────────────────────────────────────────────────────
scan_notes(){
  title "$SRCH System Notes Scan"
  : > "$DISCOVERY_CACHE"
  local enabled; enabled="$(json_read '.note_discovery.enabled' "$CFG_JSON")"
  [ "$enabled" = "true" ] || { note "Note discovery disabled in config"; return 0; }
  local paths; paths="$(jq -r '.note_discovery.paths[]' "$CFG_JSON")"
  local exts; exts="$(jq -r '.note_discovery.extensions[]' "$CFG_JSON")"

  local cnt=0
  while read -r p; do
    p=$(eval echo "$p")
    [ -d "$p" ] || continue
    while read -r ext; do
      while IFS= read -r -d '' f; do
        local title; title="$(head -n1 "$f" 2>/dev/null | sed 's/^#\+\s*//')"
        local sz; sz="$(stat_size "$f")"
        local mt; mt="$(stat_mtime "$f")"
        if grep -qE '```(bash|sh|shell)' "$f" 2>/dev/null || grep -qiE '\b(command|bash|shell|cli|script)\b' "$f" 2>/dev/null; then
          echo "$f|$title|$sz|$mt|has-code" >> "$DISCOVERY_CACHE"; cnt=$((cnt+1))
        fi
      done < <(find "$p" -maxdepth 4 -type f -name "*.$ext" -print0 2>/dev/null)
    done <<< "$exts"
  done <<< "$paths"
  ok "Found $cnt relevant notes → $DISCOVERY_CACHE"
}

extract_from_notes(){
  [ -f "$DISCOVERY_CACHE" ] || { scan_notes; }
  local out_count=0
  mkdir -p "$ONE_DIR/extracted"
  while IFS='|' read -r file _ _ _ tags; do
    [ -f "$file" ] || continue
    if echo "$tags" | grep -q "has-code"; then
      awk '/```(bash|sh|shell)/{flag=1;next}/```/{flag=0}flag' "$file" | \
      while read -r line; do
        [ -z "$line" ] && continue
        # validate/repair via AI
        local fixed; fixed="$(validate_and_rewrite "$line" "extracted" 2>/dev/null || echo "$line")"
        local name="extracted_$(date +%s)_$RANDOM"
        local path="$ONE_DIR/extracted/${name}.sh"
        printf '#!/usr/bin/env bash\n# Extracted from: %s\n\n%s\n' "$file" "$fixed" > "$path"
        chmod +x "$path"
        out_count=$((out_count+1))
      done
    fi
  done < "$DISCOVERY_CACHE"
  ok "Extracted $out_count commands into $ONE_DIR/extracted"
}

# ────────────────────────────────────────────────────────────────────────────────
# Runner
# ────────────────────────────────────────────────────────────────────────────────
list_oneliners(){
  find "$ONE_DIR" -type f -name "*.sh" | sort
}

run_from_menu(){
  local items; items="$(list_oneliners)"
  [ -n "$items" ] || die "No oneliners yet. Use: $APP_NAME add or import/sync."
  local choice
  choice="$(echo "$items" | awk '{print NR") "$0}' | picker | awk '{print $2}')" || return 0
  [ -n "$choice" ] || return 0
  execute_script "$choice"
}

execute_script(){
  local path="$1"
  [ -f "$path" ] || die "Missing: $path"
  local cmd; cmd="$(grep -v '^\s*#' "$path" | sed '/^\s*$/d' | head -n1)"
  title "Command"
  printf "%s\n" "$cmd"
  # placeholder fill
  local filled; filled="$(fill_placeholders "$cmd")"
  if [ "$filled" != "$cmd" ]; then
    note "Final command:"; line; printf "%s\n" "$filled"; line
  fi
  # validate/optimize (optional)
  if [ "$(json_read '.command_validation.syntax_check' "$CFG_JSON")" = "true" ] || \
     [ "$(json_read '.command_validation.optimization' "$CFG_JSON")" = "true" ]; then
    local improved; improved="$(validate_and_rewrite "$filled" "execution" || echo "$filled")"
    [ -n "$improved" ] && filled="$improved"
  fi
  confirm "Execute?" || return 0

  local out err; out="$(mktemp)"; err="$(mktemp)"
  set +e
  bash -o pipefail -c "$filled" >"$out" 2>"$err"
  local rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    ok "Success (exit $rc)"
    write_note "$(basename "$path")" "$filled" "success ($rc)" "$out" "$err"
  else
    printf "${YLW}Command failed (exit %d)${NC}\n" "$rc"
    printf "${DIM}stderr:${NC}\n"; sed -e 's/^/  /' "$err" | head -200
    write_note "$(basename "$path")" "$filled" "failure ($rc)" "$out" "$err"
    if [ "$(json_read '.auto_correct' "$CFG_JSON")" = "true" ]; then
      auto_fix "$filled" "$(cat "$err")"
    fi
  fi
  rm -f "$out" "$err"
  echo "$(date '+%F %T') | $filled | rc=$rc" >> "$HIST_FILE"
}

auto_fix(){
  local failed="$1" err="$2"
  title "$BOT AI Command Fixer"
  echo -e "${RED}Failed:${NC} $failed"
  echo -e "${RED}Error:${NC}  $(echo "$err" | head -1)"
  local recent; recent="$(tail -20 "$HIST_FILE" 2>/dev/null | tail -5)"
  local ask=$(cat <<EOF
Fix this failed bash command. Return STRICT JSON:
{
 "fixed_command": "<corrected>",
 "explanation": "<brief>",
 "alternatives": ["alt1","alt2"]
}
Command: $failed
Error: $err
Recent context:
$recent
EOF
)
  local resp; resp="$(ai_query "$ask" || true)"
  if [ "$HAS_JQ" -eq 1 ] && [ -n "$resp" ]; then
    local fixed; fixed="$(printf '%s' "$resp" | jq -r '.fixed_command // empty')"
    local expl; expl="$(printf '%s' "$resp" | jq -r '.explanation // empty')"
    if [ -n "$fixed" ]; then
      printf "${GRN}${CHK} Fixed:${NC}\n%s\n\n" "$fixed"
      [ -n "$expl" ] && printf "${CYN}Why:${NC} %s\n\n" "$expl"
      if confirm "Run fixed command?"; then
        bash -o pipefail -c "$fixed" && ok "Fix worked" || printf "${RED}Fix failed${NC}\n"
      fi
    else
      note "No usable fix from AI."
    fi
  else
    note "AI not available for auto-fix."
  fi
}

# ────────────────────────────────────────────────────────────────────────────────
# Add new oneliner (with AI polish)
# ────────────────────────────────────────────────────────────────────────────────
add_oneliner(){
  title "${STAR} Add New Oneliner"
  local name cat desc tags cmd
  name="$(prompt 'Name')" || die "Name required"
  cat="$(prompt 'Category (System/Network/Files/Git/Docker/DevOps/Security/Custom)')" ; [ -z "$cat" ] && cat="Custom"
  desc="$(prompt 'Description')" || true
  tags="$(prompt 'Tags (comma-separated)')" || true
  cmd="$(prompt 'Command (use {{var}} placeholders if needed)')" || die "Command required"

  # AI assist
  local ask=$(cat <<EOF
Analyze this bash command and produce STRICT JSON:
{
 "optimized": "<optimized command>",
 "with_error_handling": "<command with reasonable set -e etc.>",
 "security_notes": "short",
 "suggestions": ["tip1","tip2"]
}
Command: $cmd
Purpose: $desc
Category: $cat
EOF
)
  local resp; resp="$(ai_query "$ask" || true)"
  local final="$cmd"
  if [ -n "$resp" ] && [ "$HAS_JQ" -eq 1 ]; then
    local oh; oh="$(printf '%s' "$resp" | jq -r '.with_error_handling // empty')"
    [ -n "$oh" ] && { printf "${CYN}AI suggests:${NC}\n%s\n\n" "$oh"; if confirm "Use AI-improved version?"; then final="$oh"; fi; }
  fi

  add_oneliner_json "$name" "$final" "$tags" "$desc" "$cat"
  # Create enhanced note
  local nf="$NOTES_DIR/$(echo "$name" | tr ' ' '_' ).md"
  {
    echo "# $name"
    echo ""; echo "## Overview"; echo "$desc"
    echo ""; echo "## Category"; echo "$cat"
    echo ""; echo "## Command"; echo '```bash'; echo "$final"; echo '```'
    echo ""; echo "## Tags"; echo "\`$tags\`"
    echo ""; echo "## Common Issues"; echo "- Fill after usage."
  } > "$nf"
  ok "Note created → $nf"
}

# ────────────────────────────────────────────────────────────────────────────────
# Smart search
# ────────────────────────────────────────────────────────────────────────────────
smart_search(){
  local q="$1"
  title "$SRCH Smart Search"
  echo -e "${DIM}Query: $q${NC}\n"
  echo -e "${CYN}Local Oneliners:${NC}"
  list_oneliners | while read -r f; do
    if grep -qi -- "$q" "$f"; then
      local nm; nm="$(basename "$f" .sh)"; local cat; cat="$(basename "$(dirname "$f")")"
      echo "  ${GRN}[hit]${NC} $nm ${DIM}($cat)${NC}"
    fi
  done
  echo -e "\n${CYN}System Notes:${NC}"
  [ -f "$DISCOVERY_CACHE" ] && grep -i -- "$q" "$DISCOVERY_CACHE" | head -5 | \
    awk -F'|' '{printf "  %s %s\n      %s\n", "📄", $1, $2}'
  echo -e "\n${BOT} ${CYN}AI suggestions:${NC}"
  local ask="Suggest 3 related commands, alt search terms, and 3 common use-cases for: '$q'. Return a small Markdown list."
  ai_query "$ask" || echo "${DIM}(AI unavailable)${NC}"
}

# ────────────────────────────────────────────────────────────────────────────────
# Config / Doctor
# ────────────────────────────────────────────────────────────────────────────────
doctor(){
  title "$GEAR Doctor"
  for b in jq curl; do has "$b" && echo "  ${GRN}${CHK}${NC} $b" || echo "  ${RED}${X}${NC} $b (install recommended)"; done
  for b in fzf gum bat pandoc; do has "$b" && echo "  ${CYN}opt:${NC} $b ✓"; done
  echo; echo "HOME_DIR: $HOME_DIR"
  echo "ONE_DIR : $ONE_DIR"
  echo "NOTES   : $NOTES_DIR"
  echo "AI prov : $(json_read '.ai_provider' "$CFG_JSON")"
  load_keys
  [ -n "${OPENROUTER_API_KEY:-}" ] && echo "OpenRouter: ${GRN}set${NC}" || echo "OpenRouter: ${RED}unset${NC}"
  [ -n "${GROK_API_KEY:-}" ] && echo "Grok     : ${GRN}set${NC}" || echo "Grok     : ${RED}unset${NC}"
  [ -n "${GOOGLE_API_KEY:-}" ] && echo "Google   : ${GRN}set${NC}" || echo "Google   : ${RED}unset${NC}"
}

header(){
  clear
  local total="$(list_oneliners | wc -l | tr -d ' ')"
  local notes="$(find "$NOTES_DIR" -type f -name '*.md' | wc -l | tr -d ' ')"
  local prov; prov="$(json_read '.ai_provider' "$CFG_JSON")"
  echo -e "${CYN}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYN}║${NC}  ${WHT}${APP_NAME} ${STAR} AI-Enhanced CLI${NC}   ${DIM}Prov:${NC} ${prov}   ${DIM}Cmds:${NC} $total  ${DIM}Notes:${NC} $notes  ${CYN}║${NC}"
  echo -e "${CYN}╚══════════════════════════════════════════════════════════╝${NC}"
}

menu(){
  echo -e "${WHT}Main Menu:${NC}
  ${CYN}1${NC} → Browse & Run
  ${CYN}2${NC} → Add New Oneliner
  ${CYN}3${NC} → Smart Search
  ${CYN}4${NC} → AI Command Assistant
  ${CYN}5${NC} → Validate & Rewrite
  ${CYN}6${NC} → Notes Discovery
  ${CYN}7${NC} → GitHub Sources Sync
  ${CYN}8${NC} → View Today Notes / Export PDF
  ${CYN}9${NC} → Doctor / Settings
  ${CYN}0${NC} → Exit"
}

assistant_menu(){
  echo -e "\n${BOT} ${WHT}AI Command Assistant:${NC}
  ${CYN}1${NC} → Generate from description
  ${CYN}2${NC} → Fix a broken command
  ${CYN}3${NC} → Optimize an existing command
  ${CYN}4${NC} → Explain complex command"
  read -r -p "> " c
  case "$c" in
    1) local d; d="$(prompt 'Describe the task')" || return
       local ask="Generate a robust bash command for: $d. Return STRICT JSON {\"command\":\"...\",\"explanation\":\"...\",\"dependencies\":[...]}"
       local r; r="$(ai_query "$ask" || true)"
       if [ -n "$r" ] && [ "$HAS_JQ" -eq 1 ]; then
         local cmd expl; cmd="$(printf '%s' "$r" | jq -r '.command // empty')"
         expl="$(printf '%s' "$r" | jq -r '.explanation // empty')"
         [ -n "$cmd" ] && { printf "${GRN}Command:${NC}\n%s\n\n" "$cmd"; [ -n "$expl" ] && printf "${DIM}%s${NC}\n" "$expl"; }
       fi;;
    2) local fc; fc="$(prompt 'Paste failed command')" || return
       local fe; fe="$(prompt 'Paste error message')" || true
       auto_fix "$fc" "$fe";;
    3) local ex; ex="$(prompt 'Command to optimize')" || return
       validate_and_rewrite "$ex" "optimize" >/dev/null || true ;;
    4) local cc; cc="$(prompt 'Command to explain')" || return
       local ask="Explain this shell command briefly and safely in Markdown: $cc"
       ai_query "$ask" || true ;;
  esac
}

sync_sources(){
  title "$ROCKET GitHub Sources"
  pull_sources
}

notes_discovery_menu(){
  echo -e "
  ${CYN}1${NC} → Scan for notes now
  ${CYN}2${NC} → Extract commands from notes"
  read -r -p "> " c
  case "$c" in
    1) scan_notes ;;
    2) extract_from_notes ;;
  esac
}

export_notes_pdf(){
  view_today_notes
  if [ "$HAS_PANDOC" -eq 1 ]; then
    local md="$NOTES_DIR/$(date +%F).md"; local pdf="$NOTES_DIR/$(date +%F).pdf"
    if confirm "Export/update PDF?"; then pandoc "$md" -o "$pdf" && ok "Exported $pdf"; fi
  else
    note "Install pandoc to enable PDF export."
  fi
}

interactive(){
  while true; do
    header; menu
    read -r -p "${WHT}Choose:${NC} " ch
    case "$ch" in
      1) run_from_menu ;;
      2) add_oneliner ;;
      3) local q; q="$(prompt 'Search query')" ; smart_search "$q" ;;
      4) assistant_menu ;;
      5) local c; c="$(prompt 'Enter command to validate')" ; validate_and_rewrite "$c" >/dev/null || true ;;
      6) notes_discovery_menu ;;
      7) sync_sources ;;
      8) export_notes_pdf ;;
      9) doctor ;;
      0) echo -e "\n${GRN}${STAR} bye${NC}"; exit 0 ;;
      *) echo -e "${RED}Invalid${NC}" ;;
    esac
    echo -e "\n${WHT}Press Enter...${NC}"; read -r _
  done
}

usage(){
  cat <<EOF
${APP_NAME} — AI-enhanced oneliner manager
Usage:
  $APP_NAME                 # interactive mode
  $APP_NAME run             # pick & run from menu
  $APP_NAME add             # add a new oneliner
  $APP_NAME import <path|url>
  $APP_NAME sources add <name> <url>
  $APP_NAME sources pull
  $APP_NAME validate "<cmd>"
  $APP_NAME fix "<failed_cmd>" "<stderr>"
  $APP_NAME search "<query>"
  $APP_NAME notes           # show today's notes (and export pdf if pandoc)
  $APP_NAME notes scan      # scan system for docs with bash blocks
  $APP_NAME notes extract   # extract bash blocks into oneliners
  $APP_NAME categories list # list categories
  $APP_NAME categories add <name>
  $APP_NAME install         # set up PATH, symlink, cron, categories
  $APP_NAME doctor
EOF
}

main(){
  init_dirs
  ensure_categories
  local sub="${1:-}"
  case "$sub" in
    run) run_from_menu;;
    add) add_oneliner;;
    import)
      shift || true
      [ -n "${1:-}" ] || die "Provide file or URL"
      case "$1" in http*) import_url "$1";; *) import_file "$1";; esac
      ;;
    sources)
      shift || true
      case "${1:-}" in
        add) shift; [ -n "${1:-}" ] && [ -n "${2:-}" ] || die "Usage: sources add <name> <url>"; add_source "$1" "$2";;
        pull) pull_sources;;
        *) die "Usage: sources {add|pull}";;
      esac
      ;;
    validate) shift || true; [ -n "${1:-}" ] || die "Pass a command string"; validate_and_rewrite "$1" >/dev/null || true ;;
    fix) shift || true; [ -n "${1:-}" ] || die "Provide failed_cmd and stderr"; auto_fix "$1" "${2:-}";;
    search) shift || true; [ -n "${1:-}" ] || die "Provide query"; smart_search "$1";;
    notes)
      case "${2:-view}" in
        scan) scan_notes ;;
        extract) extract_from_notes ;;
        view|"") export_notes_pdf ;;
        *) die "Usage: notes {scan|extract|view}" ;;
      esac
      ;;
    categories)
      case "${2:-list}" in
        list)
          find "$ONE_DIR" -maxdepth 1 -type d | tail -n +2 | while read -r d; do
            c="$(basename "$d")"; n="$(find "$d" -type f -name '*.sh' | wc -l | tr -d ' ')"
            printf '%-12s %s\n' "$c" "$n"
          done
          ;;
        add)
          [ -n "${3:-}" ] || die "Usage: categories add <name>"
          mkdir -p "$ONE_DIR/${3,,}" && ok "Added category ${3}"
          ;;
        *) die "Usage: categories {list|add <name>}" ;;
      esac
      ;;
    install) install_self;;
    doctor) doctor;;
    "" ) interactive;;
    *  ) usage;;
  esac
}

trap 'echo -e "\n${YLW}Exiting ${APP_NAME}…${NC}"' EXIT
main "$@"