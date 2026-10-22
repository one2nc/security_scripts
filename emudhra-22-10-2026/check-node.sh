#!/bin/bash
# Probe the eMudhra checker hosts with Node.js TLS: cert error = safe, connect = vulnerable.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--node PATH] [-h]

Probe the incident checker hosts using Node's own TLS stack (https.get). A
certificate verification error means Node does NOT trust the compromised roots
(PASS); a successful response means it still trusts them (FAIL). Reflects Node's
bundled root set plus any NODE_EXTRA_CA_CERTS.

Options:
  --node PATH   node binary to test (default: node on PATH)
  -h, --help    Show this help message

Examples:
  $(basename "$0")
EOF
}

NODE_BIN="node"

check_prereqs() {
  command -v "$NODE_BIN" &>/dev/null || { report "node" "SKIP" "" "node-not-found-$NODE_BIN"; exit 0; }
}

# Node one-liner: prints "connected" or "rejected" for a single URL.
probe_js() {
  cat <<'EOF'
const https = require('https');
const url = process.argv[1];
const req = https.get(url, { timeout: 15000 }, (res) => {
  res.resume();
  console.log('connected');
  process.exit(0);
});
req.on('timeout', () => { req.destroy(new Error('timeout')); });
req.on('error', (e) => {
  // Any TLS/cert verification failure lands here -> safe.
  console.log('rejected');
  process.exit(0);
});
EOF
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --node) NODE_BIN="${2:?--node needs a value}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  local rc=0 url out connected
  local js
  js="$(probe_js)"
  for url in "${EMUDHRA_URLS[@]}"; do
    out="$("$NODE_BIN" -e "$js" "$url" 2>/dev/null || true)"
    if [[ "$out" == "connected" ]]; then
      connected="yes"
    else
      connected="no"
    fi
    verdict_from_connect "node" "$url" "$connected" || rc=1
  done

  return "$rc"
}

main "$@"
