#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN="$1"

echo "[*] Starting subdomain enumeration for: $DOMAIN"

FILES=(1.txt 2.txt 3.txt 4.txt 5.txt 6.txt)

rm -f "${FILES[@]}" all.txt

echo "[*] Running Subfinder..."
subfinder -d "$DOMAIN" -o 1.txt

echo "[*] Running Assetfinder..."
assetfinder -subs-only "$DOMAIN" > 2.txt

echo "[*] Running Sublist3r..."
sublist3r -d "$DOMAIN" -n -o 3.txt

echo "[*] Running Findomain..."
findomain -t "$DOMAIN" -q -u 4.txt

echo "[*] Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
| jq -r '.[].name_value' \
| sed 's/\*\.//g' \
> 5.txt

echo "[*] Running Amass (this may take a while)..."
amass enum -d "$DOMAIN" -o 6.txt

echo "[*] Merging and deduplicating results..."

cat "${FILES[@]}" 2>/dev/null \
| sed 's/\r//' \
| sort -u \
| awk '{print length, $0}' \
| sort -nr \
| cut -d" " -f2- \
> all.txt

echo "[+] Done. Results saved to all.txt"
echo "[+] Total unique subdomains: $(wc -l < all.txt)"
