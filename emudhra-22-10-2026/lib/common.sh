#!/bin/bash
# Shared helpers for eMudhra CA compromise trust probes.
#
# Model: each runtime attempts a TLS handshake to the incident checker hosts.
#   - handshake FAILS (certificate/verification error) => runtime does NOT trust
#     the compromised roots => PASS (safe).
#   - handshake SUCCEEDS                                => runtime STILL trusts
#     them => FAIL (vulnerable).
# This tests actual trust, independent of runtime version.
#
# This file is sourced, not executed, so it does not set strict mode itself;
# the sourcing script is responsible for `set -eou pipefail`.

# The twelve incident checker hosts (same list the browser checker uses). The
# six *-emudhra hosts chain to emSign Root TLS CA - G3; the six *-aaa-emudhra
# hosts chain via the Sectigo cross-sign to AAA Certificate Services. Connecting
# successfully to any of them means the client trusts that compromised chain.
# shellcheck disable=SC2034  # used by the sourcing probe scripts
EMUDHRA_URLS=(
  "https://dv-g3b-emudhra.we-have-a-problem.com/"
  "https://dv-g3c-emudhra.we-have-a-problem.com/"
  "https://ov-g3b-emudhra.we-have-a-problem.com/"
  "https://ov-g3c-emudhra.we-have-a-problem.com/"
  "https://ev-g3b-emudhra.we-have-a-problem.com/"
  "https://ev-g3c-emudhra.we-have-a-problem.com/"
  "https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
  "https://dv-g3c-aaa-emudhra.we-have-a-problem.com/"
  "https://ov-g3b-aaa-emudhra.we-have-a-problem.com/"
  "https://ov-g3c-aaa-emudhra.we-have-a-problem.com/"
  "https://ev-g3b-aaa-emudhra.we-have-a-problem.com/"
  "https://ev-g3c-aaa-emudhra.we-have-a-problem.com/"
)

# log message to stderr.
log() {
  echo "$*" >&2
}

# report RUNTIME STATUS URL DETAIL
# STATUS is PASS, FAIL, or SKIP. Emits a single key=value line to stdout.
# PASS = handshake rejected (safe); FAIL = handshake succeeded (vulnerable).
report() {
  local runtime="$1" status="$2" url="$3" detail="${4:-}"
  printf 'runtime=%s status=%s url=%s detail=%s\n' \
    "$runtime" "$status" "${url:-none}" "${detail:-none}"
}

# verdict_from_connect RUNTIME URL CONNECTED
# CONNECTED is "yes" if the TLS handshake succeeded, "no" if it was rejected.
# Prints the appropriate report line. Returns 1 when the verdict is FAIL so the
# caller can aggregate failures.
verdict_from_connect() {
  local runtime="$1" url="$2" connected="$3"
  if [[ "$connected" == "no" ]]; then
    report "$runtime" "PASS" "$url" "handshake-rejected-not-trusted"
    return 0
  fi
  report "$runtime" "FAIL" "$url" "handshake-succeeded-still-trusted"
  return 1
}
