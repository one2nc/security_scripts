#!/bin/bash
# Run every eMudhra trust probe (curl, node, python, go, java) and print a table.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--label before|after] [--raw] [-h]

Run every trust probe and print a clean table of results, then a summary. Each
probe makes a real HTTPS request to the incident checker hosts using that
runtime's own TLS stack:
  PASS = certificate error (runtime does NOT trust the compromised roots)
  FAIL = connected        (runtime STILL trusts them)
  SKIP = runtime not installed or inconclusive (DNS/timeout)
Exit code is non-zero if any probe reports FAIL.

NOTE: this makes outbound network connections by design, exactly like the curl
commands on the incident page.

Options:
  --label TEXT   Tag the table/summary with a label (e.g. before, after)
  --raw          Also print the raw key=value lines beneath the table
  -h, --help     Show this help message

Examples:
  $(basename "$0") --label before
  $(basename "$0") --label after --raw
EOF
}

check_prereqs() {
  local missing=()
  for f in check-curl.sh check-node.sh check-python.sh check-go.sh check-java.sh; do
    [[ -x "$SCRIPT_DIR/$f" ]] || missing+=("$f")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing or non-executable probe scripts: ${missing[*]}" >&2
    echo "Run: chmod +x $SCRIPT_DIR/*.sh" >&2
    exit 1
  fi
}

# Shorten the full checker URL to just the host for table readability.
short_host() {
  local u="${1#https://}"
  echo "${u%%/*}"
}

print_table() {
  local raw="$1"
  # Header.
  printf '%-16s  %-40s  %-6s  %s\n' "RUNTIME" "HOST" "RESULT" "DETAIL"
  printf '%-16s  %-40s  %-6s  %s\n' "----------------" "----------------------------------------" "------" "------------------------------------"
  # Body: parse key=value lines.
  local line runtime status url detail host
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    runtime=""; status=""; url=""; detail=""
    # shellcheck disable=SC2206  # intentional word split on spaces
    for kv in $line; do
      case "$kv" in
        runtime=*) runtime="${kv#runtime=}" ;;
        status=*)  status="${kv#status=}" ;;
        url=*)     url="${kv#url=}" ;;
        detail=*)  detail="${kv#detail=}" ;;
      esac
    done
    [[ -z "$runtime" ]] && continue
    if [[ "$url" == "none" || -z "$url" ]]; then
      host="-"
    else
      host="$(short_host "$url")"
    fi
    printf '%-16s  %-40s  %-6s  %s\n' "$runtime" "$host" "$status" "$detail"
  done <<< "$raw"
}

main() {
  local label="current" show_raw="no"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --label) label="${2:?--label needs a value}"; shift 2 ;;
      --raw) show_raw="yes"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  log "=== eMudhra trust probe (label=$label) ==="

  local out="" f
  for f in check-curl.sh check-node.sh check-python.sh check-go.sh check-java.sh; do
    out+="$("$SCRIPT_DIR/$f" 2>/dev/null || true)"$'\n'
  done

  print_table "$out"

  if [[ "$show_raw" == "yes" ]]; then
    echo
    echo "# raw:"
    printf '%s' "$out" | grep -E '^runtime=' || true
  fi

  local fails passes skips
  fails="$(printf '%s' "$out" | grep -c 'status=FAIL' || true)"
  passes="$(printf '%s' "$out" | grep -c 'status=PASS' || true)"
  skips="$(printf '%s' "$out" | grep -c 'status=SKIP' || true)"
  log "=== summary (label=$label): PASS=$passes FAIL=$fails SKIP=$skips ==="

  [[ "$fails" == "0" ]]
}

main "$@"
