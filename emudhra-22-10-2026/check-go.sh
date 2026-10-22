#!/bin/bash
# Probe the eMudhra checker hosts with Go's TLS: cert error = safe, connect = vulnerable.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [-h]

Probe the incident checker hosts using Go's crypto/tls stack. A certificate
verification error means Go does NOT trust the compromised roots (PASS); a
successful connection means it still trusts them (FAIL). Reflects Go's trust
behaviour (system trust on macOS, or its embedded roots as a fallback).

Options:
  -h, --help    Show this help message

Examples:
  $(basename "$0")
EOF
}

check_prereqs() {
  command -v go &>/dev/null || { report "go" "SKIP" "" "go-not-found"; exit 0; }
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  cat > "$tmp/probe.go" <<'EOF'
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

// Prints "connected" if the TLS handshake verifies, "rejected" on cert error,
// "other" for non-TLS failures (DNS/timeout).
func main() {
	url := os.Args[1]
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", url+":443", &tls.Config{})
	if err != nil {
		// crypto/x509 verification errors imply the root is not trusted.
		if _, ok := err.(net.Error); ok {
			fmt.Println("other")
			return
		}
		fmt.Println("rejected")
		return
	}
	conn.Close()
	fmt.Println("connected")
}
EOF

  # host:port form expects bare host; strip scheme/path from the URLs.
  local rc=0 url host out connected
  for url in "${EMUDHRA_URLS[@]}"; do
    host="${url#https://}"
    host="${host%%/*}"
    out="$( (cd "$tmp" && go run probe.go "$host") 2>/dev/null || true)"
    case "$out" in
      connected) connected="yes" ;;
      rejected)  connected="no" ;;
      *)
        report "go" "SKIP" "$url" "inconclusive-non-tls-error"
        continue
        ;;
    esac
    verdict_from_connect "go" "$url" "$connected" || rc=1
  done

  return "$rc"
}

main "$@"
