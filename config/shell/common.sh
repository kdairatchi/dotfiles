# Common shell settings, PATHs, and aliases for both bash and zsh

# Safely set PATH and language/runtime env
export PATH="$HOME/.local/bin:$PATH"
export PATH="$HOME/.cargo/bin:$PATH"
export PATH="/usr/local/go/bin:$PATH"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"

# Helper to define an alias only if a target exists
alias_if_exists() {
  local name="$1"
  local target="$2"
  if [ -e "$target" ]; then
    alias "$name"="$target"
  fi
}

# Helper to define a python alias if script exists
py_alias_if_exists() {
  local name="$1"
  local script="$2"
  if [ -f "$script" ]; then
    alias "$name"="python3 $script"
  fi
}

# Tool aliases (guarded)
py_alias_if_exists blackwidow "$HOME/tools/BlackWidow/blackwidow"
py_alias_if_exists corsy "$HOME/tools/Corsy/corsy.py"
py_alias_if_exists eyewitness "$HOME/tools/EyeWitness/Python/EyeWitness.py"
alias_if_exists gobuster "$HOME/tools/gobuster/gobuster"
py_alias_if_exists gitdorker "$HOME/tools/GitDorker/GitDorker.py"
py_alias_if_exists gsec "$HOME/tools/Gsec/gsec.py"
py_alias_if_exists jsfinder "$HOME/tools/JSFinder/jsfinder.py"
py_alias_if_exists loxs "$HOME/tools/loxs/loxs.py"
alias_if_exists sniper "sudo $HOME/tools/Sn1per/sniper"
py_alias_if_exists spiderfoot "$HOME/tools/spiderfoot/sf.py"
py_alias_if_exists ufx "$HOME/tools/UFX/ufx.py"
py_alias_if_exists xsstrike "$HOME/tools/XSStrike/xsstrike.py"
py_alias_if_exists lazyxss "$HOME/tools/Lazyxss/main.py"
alias_if_exists jsscan "$HOME/tools/JSFScan.sh"
py_alias_if_exists domsink "$HOME/gov/domsink_scanner.py"
py_alias_if_exists domsinkscan "$HOME/gov/enhanced_domsink_scanner.py"
alias_if_exists rustscan "$HOME/tools/RustScan/target/release/rustscan"

# Scripts: create simple aliases for executables in ~/scripts
if [ -d "$HOME/scripts" ]; then
  for f in "$HOME/scripts"/*; do
    if [ -f "$f" ] && [ -x "$f" ]; then
      base="$(basename "$f")"
      name="${base%.*}"
      # avoid clobbering existing commands
      if ! command -v "$name" >/dev/null 2>&1; then
        alias "$name"="$f"
      fi
    fi
  done
fi

# Convenience ls/grep aliases
if command -v ls >/dev/null 2>&1; then
  alias ll='ls -alF'
  alias la='ls -A'
  alias l='ls -CF'
fi
if command -v grep >/dev/null 2>&1; then
  alias grep='grep --color=auto'
  alias egrep='egrep --color=auto'
  alias fgrep='fgrep --color=auto'
fi

# Quality-of-life
alias ..='cd ..'
alias ...='cd ../..'
