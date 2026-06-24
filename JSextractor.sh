#!/usr/bin/env bash
set -uo pipefail   # no -e: one recon tool failing shouldn't kill the whole run

# Usage: JSextractor.sh -d <domain> [options]
log()  { echo -e "[*] $(date +%H:%M:%S) $1"; }
warn() { echo -e "[!] $1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
Usage: $0 -d <domain> [options]

Options:
  -d, --domain <domain>   Target domain (required)
  -o, --output <dir>      Output directory (default: ./js_recon_<domain>)
  -c, --concurrency <n>   Parallel threads for crawling/downloading (default: 10)
      --depth <n>         Crawl depth for katana/gospider/hakrawler (default: 5)
      --skip-headless     Skip the Puppeteer headless-browser pass
      --har <file>        Import a HAR file exported from Burp/ZAP/mitmproxy
      --install           Attempt 'go install' for missing Go-based tools
  -h, --help              Show this help

Examples:
  $0 -d target.com -c 20 --depth 6
  $0 -d target.com --har burp_export.har    # merge a manual-testing capture later
EOF
}

# Check for required dependencies and optionally install missing Go-based tools
check_deps() {
  log "Checking dependencies..."
  local tools=(subfinder assetfinder sublist3r findomain httpx gau waybackurls katana gospider hakrawler jq curl python3)
  local missing=()
  for t in "${tools[@]}"; do have "$t" || missing+=("$t"); done
 
  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing tools (their phases will be skipped): ${missing[*]}"
    cat <<EOF
Install hints:
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/tomnomnom/assetfinder@latest
  pip3 install sublist3r   # or: git clone https://github.com/aboul3la/Sublist3r
  # findomain: download prebuilt binary from https://github.com/Findomain/Findomain/releases
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/waybackurls@latest
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  go install -v github.com/jaeles-project/gospider@latest
  go install -v github.com/hakluke/hakrawler@latest
  sudo apt install -y jq curl python3
EOF
    if $DO_INSTALL && have go; then
      log "Attempting go install for missing tools..."
      go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null
      go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null
      go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
      go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
      go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null
      go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null
      go install -v github.com/jaeles-project/gospider@latest 2>/dev/null
      go install -v github.com/hakluke/hakrawler@latest 2>/dev/null
    fi
  fi
}

# Subdomain enumeration (subfinder + httpx)
phase_subdomains() {
  log "Phase 1: Subdomain enumeration"
  local SDIR="$OUTDIR/subdomains"
  echo "$DOMAIN" > "$SDIR/seed.txt"
 
  if have subfinder; then
    log "  subfinder"
    subfinder -d "$DOMAIN" -silent -o "$SDIR/subfinder.txt" 2>>"$OUTDIR/logs/subfinder.log"
  fi
 
  if have assetfinder; then
    log "  assetfinder"
    assetfinder --subs-only "$DOMAIN" > "$SDIR/assetfinder.txt" 2>>"$OUTDIR/logs/assetfinder.log"
  fi
 
  if have sublist3r; then
    log "  sublist3r (DNS brute force + search engines)"
    sublist3r -d "$DOMAIN" -n -o "$SDIR/sublist3r.txt" >>"$OUTDIR/logs/sublist3r.log" 2>&1
  fi
 
  if have findomain; then
    log "  findomain"
    findomain -t "$DOMAIN" -q -u "$SDIR/findomain.txt" 2>>"$OUTDIR/logs/findomain.log"
  fi
 
  if have curl && have jq; then
    log "  crt.sh (certificate transparency logs)"
    curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
      2>>"$OUTDIR/logs/crtsh.log" \
      | jq -r '.[].name_value' 2>>"$OUTDIR/logs/crtsh.log" \
      | sed 's/\*\.//g' > "$SDIR/crtsh.txt"
  fi
 
  # Merge every source, dedupe, longest-subdomain-first ordering (handy for
  # spotting deeply-nested or unusual hosts at a glance)
  cat "$SDIR"/seed.txt "$SDIR"/subfinder.txt "$SDIR"/assetfinder.txt \
      "$SDIR"/sublist3r.txt "$SDIR"/findomain.txt "$SDIR"/crtsh.txt 2>/dev/null \
    | sort -u | awk '{print length, $0}' | sort -nr | cut -d" " -f2- \
    > "$SDIR/subs.txt"
 
  log "Total unique subdomains (all sources merged): $(wc -l < "$SDIR/subs.txt")"
 
  # Status-code triage on the merged list — falls back to plain httpx if
  # httpx-toolkit isn't installed (same project, different binary name on
  # some distros/toolchains)
  local HX="httpx"
  have httpx-toolkit && HX="httpx-toolkit"
  if have "$HX"; then
    log "  status-code triage ($HX)"
    cat "$SDIR/subs.txt" | "$HX" -silent -mc 200     -o "$SDIR/200.txt"    2>>"$OUTDIR/logs/httpx_triage.log"
    cat "$SDIR/subs.txt" | "$HX" -silent -fc 400-499 -o "$SDIR/no_4xx.txt" 2>>"$OUTDIR/logs/httpx_triage.log"
    cat "$SDIR/subs.txt" | "$HX" -silent -mc 401,403 -o "$SDIR/bypass.txt" 2>>"$OUTDIR/logs/httpx_triage.log"
    log "    200 OK: $([[ -f "$SDIR/200.txt" ]] && wc -l < "$SDIR/200.txt" || echo 0)"
    log "    non-4xx: $([[ -f "$SDIR/no_4xx.txt" ]] && wc -l < "$SDIR/no_4xx.txt" || echo 0)"
    log "    401/403 (bypass candidates): $([[ -f "$SDIR/bypass.txt" ]] && wc -l < "$SDIR/bypass.txt" || echo 0)"
  else
    warn "neither httpx-toolkit nor httpx found — skipping status-code triage"
  fi
 
  if have httpx; then
    httpx -silent -l "$SDIR/subs.txt" -o "$SDIR/live_hosts.txt" 2>>"$OUTDIR/logs/httpx.log"
  else
    sed 's#^#https://#' "$SDIR/subs.txt" > "$SDIR/live_hosts.txt"
  fi
  log "Live hosts: $(wc -l < "$SDIR/live_hosts.txt")"
}

# Passive collection (gau + waybackurls)
phase_passive() {
  log "Phase 2: Passive JS collection (gau + waybackurls)"
  : > "$OUTDIR/urls/passive_raw.txt"
 
  if have gau; then
    gau --subs "$DOMAIN" --threads "$THREADS" 2>>"$OUTDIR/logs/gau.log" \
      >> "$OUTDIR/urls/passive_raw.txt" || warn "gau exited non-zero, continuing"
  fi
 
  if have waybackurls; then
    while read -r host; do
      [[ -z "$host" ]] && continue
      echo "$host" | waybackurls 2>>"$OUTDIR/logs/wayback.log"
    done < "$OUTDIR/subdomains/live_hosts.txt" >> "$OUTDIR/urls/passive_raw.txt"
  fi
 
  grep -Ei '\.js(\?|$)' "$OUTDIR/urls/passive_raw.txt" 2>/dev/null | sort -u \
    > "$OUTDIR/urls/passive_js.txt"
  log "Passive JS URLs: $(wc -l < "$OUTDIR/urls/passive_js.txt")"
}

# Active crawling — katana + hakrawler + gospider
phase_active() {
  log "Phase 3: Active crawling (katana + hakrawler + gospider)"
  : > "$OUTDIR/urls/active_raw.txt"
 
  while read -r host; do
    [[ -z "$host" ]] && continue
    if have katana; then
      katana -u "$host" -jc -d "$DEPTH" -silent 2>>"$OUTDIR/logs/katana.log" \
        >> "$OUTDIR/urls/active_raw.txt"
    fi
    if have hakrawler; then
      echo "$host" | hakrawler -d "$DEPTH" 2>>"$OUTDIR/logs/hakrawler.log" \
        >> "$OUTDIR/urls/active_raw.txt"
    fi
    curl -s --max-time 10 "$host/robots.txt"   >> "$OUTDIR/logs/robots_sitemap.txt" 2>/dev/null
    curl -s --max-time 10 "$host/sitemap.xml"  >> "$OUTDIR/logs/robots_sitemap.txt" 2>/dev/null
  done < "$OUTDIR/subdomains/live_hosts.txt"
 
  if have gospider; then
    gospider -S "$OUTDIR/subdomains/live_hosts.txt" -c "$THREADS" -d "$DEPTH" --js \
      -o "$OUTDIR/urls/gospider_out" 2>>"$OUTDIR/logs/gospider.log"
    find "$OUTDIR/urls/gospider_out" -type f -exec cat {} + 2>/dev/null \
      | grep -oE 'https?://[^][ "'"'"'<>]+' >> "$OUTDIR/urls/active_raw.txt"
  fi
 
  grep -Ei '\.js(\?|$)' "$OUTDIR/urls/active_raw.txt" 2>/dev/null | sort -u \
    > "$OUTDIR/urls/active_js.txt"
  log "Active-crawl JS URLs: $(wc -l < "$OUTDIR/urls/active_js.txt")"
}

# Headless browser pass (catches click/scroll-triggered chunks)
phase_headless() {
  if $SKIP_HEADLESS; then
    log "Phase 4: Skipped (--skip-headless)"
    return
  fi
  log "Phase 4: Headless browser pass"
 
  if ! have node; then
    warn "node not found — skipping headless phase (install Node.js + puppeteer to enable)"
    return
  fi
 
  mkdir -p "$OUTDIR/.headless"
  if [[ ! -d "$OUTDIR/.headless/node_modules/puppeteer" ]]; then
    log "Installing puppeteer locally (one-time, may take a minute)..."
    (cd "$OUTDIR/.headless" && npm init -y >/dev/null 2>&1 && npm install puppeteer --silent) \
      2>>"$OUTDIR/logs/npm.log"
  fi
 
  cat > "$OUTDIR/.headless/crawl.js" <<'NODE_EOF'
const puppeteer = require('puppeteer');
const target = process.argv[2];
const outFile = process.argv[3];
const seen = new Set();
 
(async () => {
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
 
  page.on('response', (res) => {
    const url = res.url();
    if (/\.js(\?|$)/i.test(url)) seen.add(url);
  });
 
  try {
    await page.goto(target, { waitUntil: 'networkidle2', timeout: 30000 });
 
    // Trigger lazy-loaded chunks behind nav/modals/buttons
    const clickable = await page.$$('a, button, [role="button"]');
    for (const el of clickable.slice(0, 25)) {
      try {
        await el.click({ delay: 50 });
        await new Promise(r => setTimeout(r, 800));
      } catch (e) { /* not clickable, skip */ }
    }
 
    // Trigger intersection-observer / infinite-scroll loads
    await page.evaluate(async () => {
      for (let i = 0; i < 5; i++) {
        window.scrollBy(0, window.innerHeight);
        await new Promise(r => setTimeout(r, 500));
      }
    });
 
    await new Promise(r => setTimeout(r, 2000));
  } catch (e) {
    console.error('nav issue:', e.message);
  }
 
  require('fs').writeFileSync(outFile, Array.from(seen).join('\n'));
  await browser.close();
})();
NODE_EOF
 
  : > "$OUTDIR/urls/headless_js.txt"
  while read -r host; do
    [[ -z "$host" ]] && continue
    log "  headless: $host"
    : > "$OUTDIR/.headless/tmp_out.txt"
    timeout 60 node "$OUTDIR/.headless/crawl.js" "$host" "$OUTDIR/.headless/tmp_out.txt" \
      2>>"$OUTDIR/logs/headless.log"
    cat "$OUTDIR/.headless/tmp_out.txt" >> "$OUTDIR/urls/headless_js.txt" 2>/dev/null
  done < "$OUTDIR/subdomains/live_hosts.txt"
 
  sort -u -o "$OUTDIR/urls/headless_js.txt" "$OUTDIR/urls/headless_js.txt"
  log "Headless-discovered JS URLs: $(wc -l < "$OUTDIR/urls/headless_js.txt")"
}

# Import manual proxy capture (Burp/ZAP/mitmproxy HAR export)
phase_proxy_import() {
  log "Phase 5: Proxy capture import"
  if [[ -z "$HAR_FILE" ]]; then
    cat <<EOF
[i] No --har supplied. For full coverage, run Burp/ZAP/mitmproxy in the
    background WHILE manually clicking through the app (login, search,
    pagination, etc.), export the session as HAR, then re-run:
        $0 -d $DOMAIN -o $OUTDIR --har capture.har
EOF
    return
  fi
  if ! have jq; then
    warn "jq not found — cannot parse HAR file"
    return
  fi
  jq -r '.log.entries[].request.url' "$HAR_FILE" 2>>"$OUTDIR/logs/har.log" \
    | grep -Ei '\.js(\?|$)' | sort -u > "$OUTDIR/urls/proxy_js.txt"
  log "Proxy-captured JS URLs: $(wc -l < "$OUTDIR/urls/proxy_js.txt")"
}

# Merge sources

merge_urls() {
  cat "$OUTDIR"/urls/*_js.txt 2>/dev/null | sort -u > "$OUTDIR/js_urls/all_js_urls.txt"
  log "Merged unique JS URLs so far: $(wc -l < "$OUTDIR/js_urls/all_js_urls.txt")"
}

# Download
download_pending() {
  if have httpx; then
    httpx -silent -mc 200 -l "$OUTDIR/js_urls/all_js_urls.txt" \
      -o "$OUTDIR/js_urls/live_js_urls.txt" 2>>"$OUTDIR/logs/httpx_filter.log"
  else
    cp "$OUTDIR/js_urls/all_js_urls.txt" "$OUTDIR/js_urls/live_js_urls.txt"
  fi
 
  mkdir -p "$OUTDIR/js_files"
  cat "$OUTDIR/js_urls/live_js_urls.txt" | xargs -P "$THREADS" -I{} bash -c '
    url="{}"
    fname=$(echo "$url" | sha256sum | cut -d" " -f1)
    out="'"$OUTDIR"'/js_files/${fname}.js"
    [[ -f "$out" ]] && exit 0
    curl -s -L --max-time 20 -A "Mozilla/5.0 (compatible; recon)" -o "$out" "$url"
    echo -e "${fname}.js\t${url}" >> "'"$OUTDIR"'/js_files/.manifest.tsv"
  ' 2>>"$OUTDIR/logs/download.log"
 
  # Best-effort source map grab — often unminified, reveals original file tree
  cat "$OUTDIR/js_urls/live_js_urls.txt" | sed 's/$/.map/' | xargs -P "$THREADS" -I{} bash -c '
    url="{}"
    fname=$(echo "$url" | sha256sum | cut -d" " -f1)
    out="'"$OUTDIR"'/js_files/${fname}.map"
    code=$(curl -s -o "$out" -w "%{http_code}" --max-time 15 "$url")
    [[ "$code" != "200" ]] && rm -f "$out"
  ' 2>>"$OUTDIR/logs/sourcemap.log"
}

# Recurse into downloaded JS for nested JS references

phase_recurse() {
  log "Phase 6: Recursing into JS for nested references (max $MAX_RECURSION rounds)"
  local round=0 before after
  while [[ $round -lt $MAX_RECURSION ]]; do
    round=$((round + 1))
    log "  round $round"
    before=$(wc -l < "$OUTDIR/js_urls/all_js_urls.txt")
 
    download_pending
 
    find "$OUTDIR/js_files" -type f -name '*.js' -print0 \
      | xargs -0 grep -ohE '[A-Za-z0-9_./-]+\.js' 2>/dev/null \
      | sed 's#^\./##' | sort -u > "$OUTDIR/js_urls/found_in_js.txt"
 
    : > "$OUTDIR/js_urls/resolved_new.txt"
    while read -r host; do
      [[ -z "$host" ]] && continue
      python3 - "$host" "$OUTDIR/js_urls/found_in_js.txt" >> "$OUTDIR/js_urls/resolved_new.txt" <<'PY'
import sys
from urllib.parse import urljoin
host, path_file = sys.argv[1], sys.argv[2]
with open(path_file) as f:
    for line in f:
        line = line.strip()
        if line:
            print(urljoin(host + "/", line))
PY
    done < "$OUTDIR/subdomains/live_hosts.txt"
 
    cat "$OUTDIR/js_urls/resolved_new.txt" >> "$OUTDIR/js_urls/all_js_urls.txt"
    sort -u -o "$OUTDIR/js_urls/all_js_urls.txt" "$OUTDIR/js_urls/all_js_urls.txt"
 
    after=$(wc -l < "$OUTDIR/js_urls/all_js_urls.txt")
    log "  total unique JS URLs: $after (was $before)"
    if [[ "$after" -eq "$before" ]]; then
      log "  no new URLs found — stopping recursion early"
      break
    fi
  done
}

# dedupe by content hash
phase_finalize() {
  log "Phase 7: Validation & dedupe"
  mkdir -p "$OUTDIR/review"

  # Flag SPA HTML-fallback pages that were saved as .js by mistake
  for f in "$OUTDIR"/js_files/*.js; do
    [[ -f "$f" ]] || continue
    if head -c 200 "$f" 2>/dev/null | grep -qi '<!doctype html\|<html'; then
      mv "$f" "$OUTDIR/review/"
    fi
  done

  # Dedupe by content hash — cache-busting filenames create false uniqueness
  phase_finalize() {
  log "Phase 7: Validation & dedupe"
  mkdir -p "$OUTDIR/review"
 
  # Flag SPA HTML-fallback pages that were saved as .js by mistake
  for f in "$OUTDIR"/js_files/*.js; do
    [[ -f "$f" ]] || continue
    if head -c 200 "$f" 2>/dev/null | grep -qi '<!doctype html\|<html'; then
      mv "$f" "$OUTDIR/review/"
    fi
  done
 
  # Dedupe by content hash — cache-busting filenames create false uniqueness
  declare -A seen_hash
  for f in "$OUTDIR"/js_files/*.js; do
    [[ -f "$f" ]] || continue
    h=$(sha256sum "$f" | cut -d' ' -f1)
    if [[ -n "${seen_hash[$h]:-}" ]]; then
      rm -f "$f"
    else
      seen_hash[$h]=1
    fi
  done
 
  local n_urls n_files n_maps n_review
  n_urls=$(wc -l < "$OUTDIR/js_urls/all_js_urls.txt")
  n_files=$(find "$OUTDIR/js_files" -name '*.js' 2>/dev/null | wc -l)
  n_maps=$(find "$OUTDIR/js_files" -name '*.map' 2>/dev/null | wc -l)
  n_review=$(find "$OUTDIR/review" -type f 2>/dev/null | wc -l)
 
  cat <<EOF
 
==================== SUMMARY ====================
Target domain:          $DOMAIN
Unique JS URLs found:    $n_urls
Unique JS files saved:   $n_files   (deduped by content hash)
Source maps saved:       $n_maps
Flagged for review:      $n_review  (HTML fallback, not real JS)
Output directory:        $OUTDIR
===================================================
 
Completeness check: diff a Burp/ZAP/mitmproxy capture from a manual
testing session against $OUTDIR/js_urls/all_js_urls.txt
Anything in the proxy capture but missing here is a tool gap — re-run
with --har <export.har> to fold it back in.
EOF
}

# Entry point
DOMAIN=""
OUTDIR=""
THREADS=10
DEPTH=5
SKIP_HEADLESS=false
HAR_FILE=""
DO_INSTALL=false
MAX_RECURSION=3
 
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2;;
    -o|--output) OUTDIR="$2"; shift 2;;
    -c|--concurrency) THREADS="$2"; shift 2;;
    --depth) DEPTH="$2"; shift 2;;
    --skip-headless) SKIP_HEADLESS=true; shift;;
    --har) HAR_FILE="$2"; shift 2;;
    --install) DO_INSTALL=true; shift;;
    -h|--help) usage; exit 0;;
    *) warn "Unknown argument: $1"; usage; exit 1;;
  esac
done
 
if [[ -z "$DOMAIN" ]]; then
  usage
  exit 1
fi
 
OUTDIR="${OUTDIR:-./js_recon_$DOMAIN}"
mkdir -p "$OUTDIR"/{subdomains,urls,js_urls,js_files,review,logs}
 
main() {
  check_deps
  phase_subdomains
  phase_passive
  phase_active
  phase_headless
  phase_proxy_import
  merge_urls
  phase_recurse
  phase_finalize
}
 
main
