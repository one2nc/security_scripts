#!/bin/bash
# Run every eMudhra trust probe (curl, node, python, go, java) and print a table.

set -eou pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--raw] [-h]

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
  --all          Probe all 12 checker hosts (default).
  --root-only    Probe only 2 hosts, one per compromised root (quick check).
  --raw          Also print the raw key=value lines beneath the table
  -h, --help     Show this help message

Examples:
  $(basename "$0")
  $(basename "$0") --root-only
  $(basename "$0") --raw
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
  printf '%-16s  %-44s  %-6s  %s\n' "RUNTIME" "HOST" "RESULT" "DETAIL"
  printf '%-16s  %-44s  %-6s  %s\n' "----------------" "--------------------------------------------" "------" "------------------------------------"
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
    printf '%-16s  %-44s  %-6s  %s\n' "$runtime" "$host" "$status" "$detail"
  done <<< "$raw"
}

main() {
  local show_raw="no" scope=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --root-only) scope="--root-only"; shift ;;
      --all) scope="--all"; shift ;;
      --raw) show_raw="yes"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage; exit 1 ;;
    esac
  done

  check_prereqs

  log "=== eMudhra trust probe ==="

  local all="" f name tool_out
  for f in check-curl.sh check-node.sh check-python.sh check-go.sh check-java.sh; do
    name="${f#check-}"; name="${name%.sh}"
    # Run this tool, then print its own table right away so results stream in
    # per tool instead of waiting for every tool to finish.
    # shellcheck disable=SC2086  # $scope is a single optional flag or empty
    tool_out="$("$SCRIPT_DIR/$f" $scope 2>/dev/null || true)"
    echo
    echo "## ${name}"
    print_table "$tool_out"
    if [[ "$show_raw" == "yes" ]]; then
      printf '%s\n' "$tool_out" | grep -E '^runtime=' || true
    fi
    all+="$tool_out"$'\n'
  done

  local fails passes skips
  fails="$(printf '%s' "$all" | grep -c 'status=FAIL' || true)"
  passes="$(printf '%s' "$all" | grep -c 'status=PASS' || true)"
  skips="$(printf '%s' "$all" | grep -c 'status=SKIP' || true)"
  echo
  log "=== summary: PASS=$passes FAIL=$fails SKIP=$skips ==="

  [[ "$fails" == "0" ]]
}

main "$@"
