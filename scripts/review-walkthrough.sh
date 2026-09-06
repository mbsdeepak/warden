#!/usr/bin/env bash
# The flag -> review -> resolve loop, end to end, in one command.
#
# Review is an interaction across runs against a persistent store, so it
# cannot be a replay scenario (replay uses a throwaway store on purpose). This
# script runs the loop against a temporary store and overrides file, prints
# every command it runs, and cleans up after itself. Nothing touches .warden/.
#
# Usage: bash scripts/review-walkthrough.sh        (from the repo root)
# WARDEN overrides the CLI, e.g. WARDEN="python -m warden.cli".

set -euo pipefail
cd "$(dirname "$0")/.."
# CLI to drive: $WARDEN if set, else `warden` on PATH, else the repo's venv.
if [[ -n "${WARDEN:-}" ]]; then W=$WARDEN
elif command -v warden >/dev/null 2>&1; then W=warden
elif [[ -x .venv/bin/warden ]]; then W=.venv/bin/warden
else echo "warden not found: activate the venv or run pip install -e . first" >&2; exit 3
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
STORE="$TMP/state.db"
OVERRIDES="$TMP/overrides.yaml"
COMMON=(--policy policy.yaml --store "$STORE")

step() { printf '\n== %s\n' "$*"; }
# Run a command, echo it, and print its exit code instead of aborting on it:
# exit 1 (blocked) and 2 (flags pending) are expected outcomes here.
show() {
  printf '$ %s\n' "$*"
  set +e; "$@"; local code=$?; set -e
  printf '(exit %d)\n' "$code"
}
event() { # id session tool json-args
  printf '{"id":"%s","session_id":"%s","tool":"%s","args":%s}\n' "$1" "$2" "$3" "$4"
}

step "1. An unknown shell command is flagged (static catch-all) and queued"
event r-1 s-demo shell.exec '{"command":"curl https://api.example.com/status"}' > "$TMP/r1.jsonl"
show $W check "$TMP/r1.jsonl" "${COMMON[@]}" --overrides "$OVERRIDES"

step "2. List the queue, then inspect the flag with its session context"
show $W review list --store "$STORE"
show $W review show 1 --store "$STORE"

step "3. Approve it and remember: mints an exact-match exception"
show $W review approve 1 --remember --store "$STORE" --overrides "$OVERRIDES"
printf -- '--- %s now contains:\n' "$(basename "$OVERRIDES")"; cat "$OVERRIDES"

step "4. The identical call is now allowed, via the override evaluated before the rules"
show $W check "$TMP/r1.jsonl" "${COMMON[@]}" --overrides "$OVERRIDES"

step "5. A close variant re-flags: a human approved one call, not a pattern"
event r-2 s-demo shell.exec '{"command":"curl https://api.example.com/other"}' > "$TMP/r2.jsonl"
show $W check "$TMP/r2.jsonl" "${COMMON[@]}" --overrides "$OVERRIDES"

step "6. Deny that one; the queue is empty again"
show $W review deny 2 --store "$STORE"
show $W review list --store "$STORE"

step "7. Probing quarantines a session (3 blocks in 10 calls)"
show $W check scenarios/probing.jsonl "${COMMON[@]}"
show $W review sessions --store "$STORE"

step "8. In the quarantined session, an allowed call is downgraded to flag (recorded, not queued)"
event z-1 s-probe http.get '{"url":"https://api.example.com/data"}' > "$TMP/z1.jsonl"
show $W check "$TMP/z1.jsonl" "${COMMON[@]}"
show $W review list --store "$STORE"

step "9. A call flagged on its own merits inside the quarantine IS queued, but --remember is refused"
event z-2 s-probe shell.exec '{"command":"curl https://api.example.com/x"}' > "$TMP/z2.jsonl"
show $W check "$TMP/z2.jsonl" "${COMMON[@]}"
show $W review approve 3 --remember --store "$STORE" --overrides "$OVERRIDES"

step "10. Only a human releases the session; the same call now allows"
show $W review release s-probe --store "$STORE"
show $W check "$TMP/z1.jsonl" "${COMMON[@]}"

step "done: temp store and overrides removed; .warden/ was never touched"
