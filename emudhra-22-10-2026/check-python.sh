#!/bin/bash
# Probe the eMudhra checker hosts with Python urllib and requests: cert error = safe.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--python PATH] [-h]

Probe the incident checker hosts using Python, reported as two separate runtimes:
  python-urllib   -> urllib + ssl (uses the stdlib default CA bundle)
  python-requests -> requests library (uses certifi unless overridden)

A certificate verification error means that stack does NOT trust the compromised
roots (PASS); a successful response means it still trusts them (FAIL). The
requests probe is skipped if the requests library is not installed.

Options:
  --python PATH  python interpreter to test (default: python3)
  -h, --help     Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --python /opt/homebrew/bin/python3
EOF
}

PY="python3"

check_prereqs() {
  command -v "$PY" &>/dev/null || { report "python-urllib" "SKIP" "" "python-not-found-$PY"; exit 0; }
}

probe_urllib() {
  cat <<'EOF'
import sys, urllib.request, urllib.error, ssl
url = sys.argv[1]
try:
    urllib.request.urlopen(url, timeout=15)
    print("connected")
except ssl.SSLError:
    print("rejected")
except urllib.error.URLError as e:
    print("rejected" if isinstance(e.reason, ssl.SSLError) else "other")
except Exception:
    print("other")
EOF
}

probe_requests() {
  cat <<'EOF'
import sys
try:
    import requests
except ImportError:
    print("missing")
    sys.exit(0)
url = sys.argv[1]
try:
    requests.get(url, timeout=15)
    print("connected")
except requests.exceptions.SSLError:
    print("rejected")
except Exception:
    print("other")
EOF
}

# run_probe RUNTIME SCRIPT -> prints report lines, returns 1 if any FAIL.
run_probe() {
  local runtime="$1" script="$2" rc=0 url out connected
  for url in "${EMUDHRA_URLS[@]}"; do
    out="$("$PY" -c "$script" "$url" 2>/dev/null || true)"
    case "$out" in
      connected) connected="yes" ;;
      rejected)  connected="no" ;;
      missing)
        report "$runtime" "SKIP" "$url" "library-not-installed"
        continue
        ;;
      *)
        report "$runtime" "SKIP" "$url" "inconclusive-non-tls-error"
        continue
        ;;
    esac
    verdict_from_connect "$runtime" "$url" "$connected" || rc=1
  done
  return "$rc"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --python) PY="${2:?--python needs a value}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  local rc=0
  run_probe "python-urllib" "$(probe_urllib)" || rc=1
  run_probe "python-requests" "$(probe_requests)" || rc=1
  return "$rc"
}

main "$@"
