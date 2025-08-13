**ROLE / CONTEXT**

You are a senior Linux + Security tooling engineer. Your job is to **audit, fix, enhance, and standardize** a small toolkit of recon/security scripts for a bug-bounty–style workflow. The owner is **Kdairatchi**. All outputs must be clean, documented, and tested.

**TARGET FILES (relative to repo root)**

```
/dotfiles/scripts/recon/bug_bounty_framework/**/*
/dotfiles/scripts/recon/luckyspin.sh
/dotfiles/scripts/recon/recon.sh
/dotfiles/scripts/recon/swaggerdorker.py
/dotfiles/scripts/recon/ultibb.sh
/dotfiles/scripts/recon/wayback.sh
/dotfiles/scripts/recon/embed.py
/dotfiles/scripts/recon/idor_scanner.py
/dotfiles/scripts/recon/js_recon.sh
/dotfiles/scripts/recon/par-bounty.sh
/dotfiles/scripts/recon/sqry.sh
/dotfiles/scripts/recon/swagger.sh
/dotfiles/scripts/recon/vt.sh
/dotfiles/scripts/recon/xss.sh
/dotfiles/scripts/
```

---

## 1) Global goals (what to deliver)

* **Fix all errors** (syntax, runtime, edge cases).
* **Standardize** UX, flags, logging, exit codes, folder layout.
* **Harden** security: safe defaults, input validation, timeouts, least-privilege calls.
* **Test** everything: runnable smoke tests for bash, unit tests for Python.
* **Docs**: update/author README snippets per tool + a top-level overview.
* **Styling**: add **unique “Kdairatchi” banner** to **every script** (file header + runtime banner function).
* **Reports**: every tool supports structured output (`--json` and `--report <dir>`), timestamped.
* **No external network** unless the tool requires it; gate with flags and environment variables (e.g., API keys).
* **Idempotent**: safe to re-run; predictable exit codes.

---

## 2) Repo layout & conventions

* Put runtime outputs under `reports/YYYYMMDD/HHMMSS/<tool>/`

  * `summary.json`, `summary.txt`, and (where useful) `findings.csv`.
  * Always print the final path on success.
* Put logs under `logs/<tool>/YYYYMMDD_HHMMSS.log`.
* Shared helpers under `lib/`:

  * `lib/banner.sh` and `lib/log.sh` for shell
  * `lib/banner.py` and `lib/io.py` for Python
* Keep configs in `config/` (sample templates with comments).

---

## 3) CLI & UX standard

Every tool (bash or Python) must support:

* `-t/--targets <file|comma,sep|->` (read list or stdin)
* `-o/--output <dir>` (default `reports/<ts>/<tool>`)
* `--json` (write structured JSON summary)
* `-v/--verbose` (multi-level if easy)
* `--no-color` (disable ANSI)
* `--timeout <sec>` (per target/network op)
* `--threads <N>` (parallelism; GNU `xargs -P` or Python `concurrent.futures`)
* `--dry-run` (show actions, no network/process execution)
* `--banner` (print the Kdairatchi banner and exit 0)
* `--version` (tool name + semver + “Made by Kdairatchi”)
* Proper `--help` with examples.

Exit codes:

* `0` success; `1` user error (bad args); `2` runtime error; `3` partial results; `4` dependency missing.

---

## 4) Bash scripts requirements

* Shebang: `#!/usr/bin/env bash`
* Strict mode: `set -Eeuo pipefail; IFS=$'\n\t'`
* `trap` errors and print a red error line with file\:line + last command.
* Input validation; sanitize paths; quote all variables.
* Concurrency: batch targets via `xargs -P "$threads"` when safe.
* Use helper functions:

  * `log_info/log_warn/log_err/log_ok` (color aware)
  * `ensure_bin <cmd>` (fail with hint if missing)
  * `mkout <tool>` (creates output/report/log dirs + exports `OUT_DIR LOG_FILE`)
* Add `shellcheck`-clean code, and format with `shfmt`.

---

## 5) Python scripts requirements

* Shebang: `#!/usr/bin/env python3`
* Use `argparse` with the same flags as above.
* Logging: `logging` module, levels wired to `-v`.
* Networking: timeouts, retries with backoff; respect `--timeout`.
* Parallelism: `ThreadPoolExecutor` for I/O (safe), bounded workers from `--threads`.
* Output: write JSON via `json.dumps(..., indent=2, sort_keys=True)`; CSV via `csv` module.
* Lint/format: `ruff` + `black` + `isort`; security scan with `bandit -r`.

---

## 6) Unique Kdairatchi banner (file header + runtime)

**File header (top of every file, commented):**

```
# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  <TOOL_NAME>
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/<TOOL_NAME>
#  “real never lies.”  |  Support: buymeacoffee.com/kdairatchi
# =========================================================
```

**Runtime banner (printed only when `--banner` or at start unless `--quiet`):**

* Bash: call `kd_banner "<TOOL_NAME>" "<VERSION>"` from `lib/banner.sh`
* Python: call `from lib.banner import kd_banner; kd_banner("TOOL_NAME", VERSION, color=not args.no_color)`

Banner should be ASCII-safe (no Unicode box chars) and colorized with ANSI when color enabled.

---

## 7) Reporting & schema

* Each tool writes a `summary.json` with:

  ```json
  {
    "tool":"<name>",
    "version":"<semver>",
    "timestamp":"<ISO8601>",
    "targets":[...],
    "findings":[ { "target":..., "type":..., "severity":"low|med|high|info", "data":{...} } ],
    "stats":{ "processed":N, "errors":N, "duration_sec":N }
  }
  ```
* If `--json` is used, also print the same JSON to stdout.
* Save a human `summary.txt` with highlights and paths to artifacts.

---

## 8) Security & API keys

* Never hardcode secrets. Read from env (e.g., `VT_API_KEY`, etc.).
* Validate hostnames/IPs before scanning.
* Provide `--dry-run` and **clear warnings** before network activity.
* Respect robots/ToS where relevant. This toolkit is for **authorized testing** only.

---

## 9) Tests & quality gates

* **Bash**: add minimal **bats** tests in `tests/bash/` that:

  * run `--help`, `--version`, `--banner`
  * accept a tiny `targets.txt` w/ localhost and a sample domain (no live hitting by default; mock or `--dry-run`)
* **Python**: `pytest` in `tests/python/` covering arg parsing, small pure functions, and a mocked network flow.
* Provide a `Makefile`:

  * `make fmt` (black, isort, shfmt)
  * `make lint` (ruff, shellcheck, bandit)
  * `make test` (pytest + bats)
  * `make all` → fmt + lint + test

---

## 10) Deliverables (what you return)

1. **Patched files** (all target scripts), plus new `lib/` helpers.
2. **A short CHANGELOG** with the key fixes and features.
3. **README updates**: one top-level “Toolkit” README + per-tool usage blocks.
4. **A GitHub Actions workflow** (`.github/workflows/ci.yml`) running fmt/lint/test on push/PR.
5. **A runnable validation script** `dev/validate.sh` that:

   * installs local dev deps (shellcheck, shfmt, python deps) if missing
   * runs `make all`
   * runs each tool with `--help`, `--banner`, `--dry-run --targets -` pipe a single line
6. **Semantic version bump** per tool (e.g., `0.2.0`).

**Acceptance criteria**:

* No lint errors (shellcheck level “error”, ruff/bandit blocking issues fixed).
* All tests pass.
* Each tool: `--help`, `--banner`, `--json`, `--dry-run` work.
* Reports are created with timestamped directories.
* Headers + runtime banners present and ASCII-safe.

> Proceed now. Show diffs per file and a final summary.

---

## ✅ Drop-in banner helpers (ready to add)

**`lib/banner.sh`**

```bash
#!/usr/bin/env bash
# Kdairatchi banner (ASCII-safe)
kd_banner() {
  local tool="${1:-Kdairatchi Tool}"
  local ver="${2:-0.0.0}"
  local nocolor="${NO_COLOR:-0}"

  local c_reset="\033[0m"
  local c_cyan="\033[36m"
  local c_magenta="\033[35m"
  local c_yellow="\033[33m"

  if [[ "$nocolor" != "0" || "${NO_COLOR:-}" != "" ]]; then
    c_reset=""; c_cyan=""; c_magenta=""; c_yellow=""
  fi

  echo -e "${c_cyan}==============================================${c_reset}"
  echo -e "${c_magenta} KDAIRATCHI SECURITY TOOLKIT ${c_reset}— ${c_yellow}${tool}${c_reset} v${ver}"
  echo -e "${c_cyan}==============================================${c_reset}"
  echo    " Author: Kdairatchi | Repo: github.com/kdairatchi/dotfiles"
  echo    " Motto: \"real never lies.\" | Support: buymeacoffee.com/kdairatchi"
  echo
}
```

**`lib/banner.py`**

```python
#!/usr/bin/env python3
def kd_banner(tool: str, version: str, color: bool = True) -> None:
    CYAN = "\033[36m" if color else ""
    MAG = "\033[35m" if color else ""
    YEL = "\033[33m" if color else ""
    RST = "\033[0m" if color else ""
    print(f"{CYAN}=============================================={RST}")
    print(f"{MAG} KDAIRATCHI SECURITY TOOLKIT {RST}— {YEL}{tool}{RST} v{version}")
    print(f"{CYAN}=============================================={RST}")
    print(" Author: Kdairatchi | Repo: github.com/kdairatchi/dotfiles")
    print(' Motto: "real never lies." | Support: buymeacoffee.com/kdairatchi')
    print()
```

---

## 🧪 Quick validation commands (Linux/zsh)

```bash
# Install helpers (Debian/Kali)
sudo apt-get update
sudo apt-get install -y shellcheck shfmt bats
python3 -m pip install --user black ruff isort bandit pytest

# From repo root:
make fmt && make lint && make test

# Smoke-run each script without side effects:
for f in s/recon/*.sh; do bash "$f" --help || true; done
for f in s/recon/*.py; do python3 "$f" --help || true; done
```

---

## 🛡️ Optional: CI (drop into `.github/workflows/ci.yml`)

```yaml
name: ci
on: [push, pull_request]
jobs:
  lint-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: sudo apt-get update && sudo apt-get install -y shellcheck shfmt bats
      - run: pip install black ruff isort bandit pytest
      - run: |
          echo "FMT"
          black --check .
          isort --check-only .
          shfmt -d .
      - run: |
          echo "LINT"
          ruff check .
          bandit -r -x venv . || true  # warn only; fail if needed
      - run: |
          echo "TEST"
          pytest -q || true
          bats --tap tests/bash || true
```

---

## ⚡ Bonus: stamp headers on existing files (one-time helper)

```bash
add_header() {
  local file="$1"
  local tool
  tool="$(basename "$file")"
  local header="# =========================================================
#  KDAIRATCHI SECURITY TOOLKIT  —  ${tool}
#  Author: Kdairatchi  |  Repo: github.com/kdairatchi/dotfiles
#  \"real never lies.\"  |  Support: buymeacoffee.com/kdairatchi
# =========================================================
"
  grep -q "KDAIRATCHI SECURITY TOOLKIT" "$file" || {
    tmp="$(mktemp)"; printf "%s\n" "$header" >"$tmp"; cat "$file" >>"$tmp"; mv "$tmp" "$file"
  }
}
export -f add_header
find s/recon -type f \( -name "*.sh" -o -name "*.py" \) -exec bash -c 'add_header "$0"' {} \;
```
