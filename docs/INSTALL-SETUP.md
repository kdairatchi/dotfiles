## Install and Setup Guide

This guide explains what the installers do, what gets installed, and how to customize the environment.

### Quick start

- Debian/Kali/Ubuntu recommended (APT present). WSL2 works.
- Run the unified installer:
```bash
bash install/install.sh
```
- Or run the base setup directly:
```bash
bash install/setup.sh
```
- After it finishes, reload your shell:
```bash
source ~/.zshrc
```

### What the base setup installs (install/setup.sh)

- System packages via APT:
  - curl, wget, git, python3, python3-pip, golang-go, nodejs, npm, GNU parallel, jq, lynx, zsh, fonts-powerline
- Zsh + Oh My Zsh + Powerlevel10k
  - Installs Oh My Zsh (unattended), theme `powerlevel10k`, plugins: `zsh-autosuggestions`, `zsh-syntax-highlighting`, `zsh-completions`
- Go environment + core security tools
  - Exports `GOPATH=$HOME/go` and `PATH=$GOPATH/bin:$PATH`
  - Installs: subfinder, httpx, nuclei, waybackurls, assetfinder, ffuf, dalfox
- Python libraries (user site)
  - requests, beautifulsoup4, colorama, urllib3, lxml, pyyaml
- Creates directories
  - `~/tools`, `~/scripts`, `~/wordlists`, `~/results`, and `~/tools/payloads`
- Links configuration files (backs up existing first)
  - `config/shell/bashrc -> ~/.bashrc`
  - `config/shell/zshrc -> ~/.zshrc`
  - `config/shell/p10k.zsh -> ~/.p10k.zsh`
  - `config/git/gitconfig -> ~/.gitconfig`
  - `config/shell/common.sh -> ~/.shell_common`
- Copies repo assets into your home
  - `scripts/* -> ~/scripts/`
  - `tools/tools/* -> ~/tools/` (flattened)
  - `tools/wordlists/* -> ~/wordlists/`
  - `tools/payloads/* -> ~/tools/payloads/`
  - Marks shell and python scripts executable under `~/scripts` and `~/tools`
- Nuclei templates
  - Updates templates with `nuclei -update-templates`
- Optional integrations (auto-detected)
  - If present, runs `install/tools.sh` for advanced tools
  - If present, runs `kda-bootstrap.sh --install --yes` to enable portable aliases and per-host overrides

### Advanced tools (install/tools.sh)

- Extra Go tools
  - katana, naabu, uncover, gf, anew, unfurl, qsreplace, gau, hakrawler, getJS, urldedupe
- Specialized Python tools (cloned into `~/tools`)
  - XSStrike, Corsy, GitDorker, sqlmap, Arjun (with their requirements)
- Wordlists
  - SecLists (full clone), and common lists (e.g., `common.txt`, `subdomains-top1million-5000.txt`)
- GF patterns
  - Installs patterns to `~/.gf/`
- Utilities
  - `htmlq` via cargo (if Rust installed), `ripgrep` via apt

### Bug Hunting Arsenal (install/install_bug_hunting_arsenal.sh)

Sets up a Python virtual environment and project scaffolding under `scripts/recon/` for advanced recon workflows.

- Creates/updates `scripts/recon/requirements.txt` with pinned versions
- Creates and populates virtualenv `scripts/recon/venv`
- Checks/installs system tools (curl, wget, git, jq, parallel)
- Checks/installs Go tools (subfinder, httpx, nuclei, waybackurls, assetfinder, ffuf, dalfox, katana, gau, waymore)
- Optionally installs additional tools: `nmap`, `whatweb`, `whois`
- Creates project structure: `logs/`, `results/`, `tests/`, `config/`
- Adds `scripts/recon/activate.sh` helper to activate env and PATH

Usage:
```bash
bash install/install_bug_hunting_arsenal.sh
source scripts/recon/activate.sh
python scripts/recon/bug_hunting_arsenal.py --help
```

### Portable aliases and per-host overrides (kda-bootstrap.sh)

Adds a portable layer that loads global and host-specific aliases without modifying repo files.

- Installs loader to `~/.kda/aliases/loader.sh`
- Creates `~/.kda/config.env` (global knobs) and `~/.kda/aliases/host/<hostname>.sh`
- Wires the loader into your `~/.zshrc` or `~/.bashrc`
- Auto-detects tool paths and writes them to `~/.kda/config.env`

Commands:
```bash
# Install
bash ./kda-bootstrap.sh --install --yes

# Choose shell and set custom templates/tool roots
bash ./kda-bootstrap.sh --install --shell zsh \
  --nuclei-templates "$HOME/nuclei-templates/customs" \
  --tool-root "$HOME/tools"

# Doctor/uninstall
bash ./kda-bootstrap.sh --doctor
bash ./kda-bootstrap.sh --uninstall
```

Edit `~/.kda/config.env` to override paths or set defaults like `J` (parallel jobs), `GOPATH`, `NUCLEI_CUSTOM_TEMPLATES`, and tool-specific variables (e.g., `XSSTRIKE_PATH`). Add host-specific aliases in `~/.kda/aliases/host/<short-hostname>.sh`.

### Shell config and aliases

- Main Zsh config: `config/shell/zshrc` (linked to `~/.zshrc`)
  - Theme: powerlevel10k; plugins: git, zsh-autosuggestions, zsh-syntax-highlighting, zsh-completions
  - Adds PATHs for local bins, cargo, Go, `~/tools/*/bin`, and `~/scripts/*/bin`
  - Handy aliases for recon and utils (e.g., `recon`, `luckyspin`, `fuzz`, `sqli`, `swagger`, `menu`, `rustscan`)
  - Parallel helpers: `nuclei-par`, `httpx-par`, `wayback-par`, `gf-par`, `jsfinder-par`, `rustscan-par`, `xsstrike-par`
- Shared settings: `config/shell/common.sh` (linked to `~/.shell_common`)
  - Safe PATH setup and guarded aliases that only enable when targets exist
- Powerlevel10k prompt: `config/shell/p10k.zsh` (linked to `~/.p10k.zsh`)

Reload after edits:
```bash
source ~/.zshrc
```

### Customization guide

- Git identity
  - Edit `~/.gitconfig` to set your name and email
- API keys and tokens
  - Export sensitive keys via your shell profile or secrets manager:
```bash
export SHODAN_API_KEY=...
export VIRUSTOTAL_API_KEY=...
export GITHUB_TOKEN=...
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
```
- Nuclei templates
  - Keep templates updated: `nuclei -update-templates`
  - Store custom templates and set path in `~/.kda/config.env`:
```bash
export NUCLEI_CUSTOM_TEMPLATES="$HOME/nuclei-templates/customs"
```
- Go tools versioning
  - Tools are installed with `@latest`. Pin a version by editing installers:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8
```
- Tool paths
  - If a tool lives outside defaults, set explicit paths in `~/.kda/config.env` (e.g., `XSSTRIKE_PATH`, `JSFINDER_PATH`, `RUSTSCAN_BIN`)
- Directories
  - Change default destinations by editing `install/setup.sh` (function `create_directories` and `copy_tools`)
- NodeJS
  - `~/.zshrc` initializes NVM if present; install and select your desired node version using NVM

### Re-running or partial installs

- Base setup again:
```bash
bash install/setup.sh
```
- Only advanced tools:
```bash
bash install/tools.sh
```
- Only update Nuclei templates:
```bash
nuclei -update-templates
```
- Verify environment:
```bash
bash install/check_setup.sh
```

### Uninstall and restore

- Backups created on first link:
  - `~/.bashrc.backup.YYYYMMDD`, `~/.zshrc.backup.YYYYMMDD`, `~/.gitconfig.backup.YYYYMMDD`, `~/.p10k.zsh.backup.YYYYMMDD`
- To restore, move backups back into place and re-source your shell
- Remove optional layers and folders if undesired:
  - `rm -rf ~/.kda` (portable alias layer)
  - `rm -rf ~/tools ~/scripts ~/wordlists ~/results` (user data—be careful)
  - Remove `~/.oh-my-zsh` to uninstall Oh My Zsh (or reinstall Zsh defaults)

### Troubleshooting

- Go binaries not found
  - Ensure `GOPATH=$HOME/go` and PATH includes `$GOPATH/bin`. Reload shell.
- Command not found after copy
  - Make sure `~/scripts` and `~/tools` files are executable and in PATH. Re-run `install/setup.sh` or `chmod +x`.
- APT failures on WSL2
  - Check system clock, DNS, and `sudo apt update` output.
- htmlq missing
  - Requires Rust (`rustup`). Or skip; not critical.

### See also

- Tools usage details: `docs/TOOLS.md`
- Aliases/functions are loaded from `~/.zshrc`, `~/.shell_common`, and `~/.kda/aliases/`
