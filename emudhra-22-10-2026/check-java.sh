#!/bin/bash
# Probe the eMudhra checker hosts with Java's TLS: cert error = safe, connect = vulnerable.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [-h]

Probe the incident checker hosts using Java's HttpsURLConnection, which uses the
JDK cacerts keystore (Java ignores SSL_CERT_FILE). A certificate validation
error means this JDK does NOT trust the compromised roots (PASS); a successful
connection means its cacerts still trusts them (FAIL).

Options:
  --all         Probe all 12 checker hosts (default).
  --root-only   Probe only 2 hosts, one per compromised root (quick check).
  -h, --help    Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --root-only
EOF
}

check_prereqs() {
  local missing=()
  for cmd in java javac; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    report "java" "SKIP" "" "missing-${missing[*]// /-}"
    exit 0
  fi
}

main() {
  parse_url_scope "$@"
  set -- ${REST_ARGS[@]+"${REST_ARGS[@]}"}
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

  cat > "$tmp/Probe.java" <<'EOF'
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

public class Probe {
    public static void main(String[] args) {
        try {
            HttpsURLConnection c = (HttpsURLConnection) new URL(args[0]).openConnection();
            c.setConnectTimeout(15000);
            c.setReadTimeout(15000);
            c.connect();
            c.getResponseCode();
            c.disconnect();
            System.out.println("connected");
        } catch (SSLHandshakeException e) {
            // Trust/validation failure -> root not trusted.
            System.out.println("rejected");
        } catch (Exception e) {
            // Could still be a wrapped validation error; treat cert-bearing
            // messages as rejected, otherwise inconclusive.
            String m = String.valueOf(e.getMessage()).toLowerCase();
            if (m.contains("certif") || m.contains("pkix") || m.contains("trust")) {
                System.out.println("rejected");
            } else {
                System.out.println("other");
            }
        }
    }
}
EOF

  if ! (cd "$tmp" && javac Probe.java 2>/dev/null); then
    report "java" "SKIP" "" "javac-compile-failed"
    exit 0
  fi

  local rc=0 url out connected
  for url in "${EMUDHRA_URLS[@]}"; do
    out="$( (cd "$tmp" && java Probe "$url") 2>/dev/null || true)"
    case "$out" in
      connected) connected="yes" ;;
      rejected)  connected="no" ;;
      *)
        report "java" "SKIP" "$url" "inconclusive-non-tls-error"
        continue
        ;;
    esac
    verdict_from_connect "java" "$url" "$connected" || rc=1
  done

  return "$rc"
}

main "$@"
