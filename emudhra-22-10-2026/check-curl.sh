#!/bin/bash
# Probe the eMudhra checker hosts with curl: cert error = safe, connect = vulnerable.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--curl PATH] [-h]

Probe the incident checker hosts with curl. A TLS certificate error means curl
does NOT trust the compromised roots (PASS). A successful connection means it
still trusts them (FAIL). Tests whatever CA bundle this curl is configured to
use (including CURL_CA_BUNDLE / SSL_CERT_FILE if exported).

Options:
  --curl PATH   curl binary to test (default: curl on PATH)
  -h, --help    Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --curl /opt/homebrew/opt/curl/bin/curl
EOF
}

CURL_BIN="curl"

check_prereqs() {
  command -v "$CURL_BIN" &>/dev/null || { report "curl" "SKIP" "" "curl-not-found-$CURL_BIN"; exit 0; }
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --curl) CURL_BIN="${2:?--curl needs a value}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  local rc=0 url connected
  for url in "${EMUDHRA_URLS[@]}"; do
    # --max-time bounds the attempt; -sS keeps it quiet but shows errors on stderr.
    # curl exit 60/35/51 etc = TLS/cert failure (safe). Exit 0 = connected (bad).
    if "$CURL_BIN" -sS --max-time 15 -o /dev/null "$url" 2>/dev/null; then
      connected="yes"
    else
      connected="no"
    fi
    verdict_from_connect "curl" "$url" "$connected" || rc=1
  done

  return "$rc"
}

main "$@"
