#!/usr/bin/env bash
#
# scripts/verify.sh — the OmniFi verification gate.
#
# Runs every test suite in the repo, including the ones that need live
# infrastructure, and fails loudly instead of skipping quietly. Specifically:
#
#   1. omnifi_core:  dart analyze (zero issues) + dart test
#   2. the pairing/rendezvous integration suite, against a *real* relay that
#      this script starts and stops itself (dart_test.yaml skips these by
#      tag for the fast inner loop — this is what closes that gap)
#   3. the relay's own test suite (npm test, vitest-pool-workers)
#   4. the Flutter app: flutter analyze + flutter test
#   5. the structural invariant: omnifi_core must not import
#      package:flutter/* or dart:ui — that's what keeps the protocol
#      testable without a UI
#
# Usage:
#   scripts/verify.sh [--no-integration]
#
# Exit status is non-zero if any step fails, so this is safe to use as a
# pre-push hook or a CI step.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Non-interactive shells (cron, git hooks, CI) don't source the profile that
# puts Homebrew's Flutter/Dart/Node on PATH. Put it first so the rest of this
# script can just call `dart`, `flutter`, `npx`, `npm`, `curl`, etc.
# ---------------------------------------------------------------------------
export PATH="/opt/homebrew/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$ROOT_DIR/packages/omnifi_core"
RELAY_DIR="$ROOT_DIR/relay"
APP_DIR="$ROOT_DIR/apps/omnifi_app"

RELAY_PORT=8787
RELAY_HEALTH_URL="http://localhost:${RELAY_PORT}/v1/health"
RELAY_READY_ATTEMPTS=45   # bounded poll, ~1s per attempt — no fixed sleep

RUN_INTEGRATION=1
for arg in "$@"; do
  case "$arg" in
    --no-integration)
      RUN_INTEGRATION=0
      ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "verify.sh: unknown argument: $arg" >&2
      echo "usage: verify.sh [--no-integration]" >&2
      exit 2
      ;;
  esac
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/omnifi-verify.XXXXXX")"

# ---------------------------------------------------------------------------
# Bookkeeping. Bash on macOS defaults to 3.2 (no associative arrays), so this
# uses parallel indexed arrays instead.
# ---------------------------------------------------------------------------
STEP_NAMES=()
STEP_STATUSES=()
STEP_SUMMARIES=()
OVERALL_FAIL=0

CORE_COUNT="?"
INTEGRATION_COUNT="skipped"
RELAY_COUNT="?"
APP_COUNT="?"

record_step() {
  STEP_NAMES+=("$1")
  STEP_STATUSES+=("$2")
  STEP_SUMMARIES+=("$3")
}

section() {
  printf '\n=== %s ===\n' "$1"
}

# ---------------------------------------------------------------------------
# Relay process management. `wrangler dev` fans out into a small process
# tree (an npx/node wrapper, esbuild watchers, a workerd runtime), so a plain
# `kill $PID` on the top-level PID is not reliable — walk the tree instead,
# then double-check the port itself as a belt-and-suspenders cleanup.
# ---------------------------------------------------------------------------
RELAY_PID=""
RELAY_LOG=""

kill_tree() {
  local pid="$1" children child
  children="$(pgrep -P "$pid" 2>/dev/null || true)"
  for child in $children; do
    kill_tree "$child"
  done
  kill -TERM "$pid" 2>/dev/null || true
}

stop_relay() {
  if [ -n "$RELAY_PID" ] && kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "Stopping relay (pid $RELAY_PID)..."
    kill_tree "$RELAY_PID"
    local waited=0
    while kill -0 "$RELAY_PID" 2>/dev/null && [ "$waited" -lt 10 ]; do
      sleep 0.5
      waited=$((waited + 1))
    done
  fi
  RELAY_PID=""
  # Belt and suspenders: whatever is actually bound to the port goes away,
  # regardless of how the process tree above was shaped. A leaked `wrangler
  # dev` holding port 8787 makes the next run fail confusingly, and that
  # failure mode is exactly what this script exists to avoid reintroducing.
  local stragglers
  stragglers="$(lsof -ti "tcp:${RELAY_PORT}" 2>/dev/null || true)"
  if [ -n "$stragglers" ]; then
    echo "Force-killing stray listener(s) on port ${RELAY_PORT}: $stragglers"
    kill -9 $stragglers 2>/dev/null || true
  fi
}

cleanup() {
  local exit_code=$?
  stop_relay
  rm -rf "$WORK_DIR" 2>/dev/null || true
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_relay() {
  RELAY_LOG="$WORK_DIR/relay-dev.log"
  echo "Starting relay: (cd relay && npx wrangler dev --port ${RELAY_PORT})"
  ( cd "$RELAY_DIR" && npx wrangler dev --port "$RELAY_PORT" ) >"$RELAY_LOG" 2>&1 &
  RELAY_PID=$!
}

wait_for_relay() {
  local attempt=0
  while [ "$attempt" -lt "$RELAY_READY_ATTEMPTS" ]; do
    if ! kill -0 "$RELAY_PID" 2>/dev/null; then
      echo "ERROR: relay process exited before becoming healthy." >&2
      echo "----- relay log ($RELAY_LOG) -----" >&2
      cat "$RELAY_LOG" >&2 2>/dev/null || true
      return 1
    fi
    if curl -fsS -m 2 "$RELAY_HEALTH_URL" 2>/dev/null | grep -q '"ok":true'; then
      echo "Relay healthy at $RELAY_HEALTH_URL after $((attempt + 1))s."
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "ERROR: relay never reported healthy at $RELAY_HEALTH_URL after ${RELAY_READY_ATTEMPTS}s." >&2
  echo "----- relay log ($RELAY_LOG) -----" >&2
  cat "$RELAY_LOG" >&2 2>/dev/null || true
  return 1
}

# ---------------------------------------------------------------------------
# Test runners. Each captures full output to a log (printed on failure) and
# pulls a human-readable summary line out of it, so the final report shows
# what actually ran rather than just pass/fail.
# ---------------------------------------------------------------------------

# Prints the most useful one-line summary found in a captured log.
extract_summary() {
  local logfile="$1" line
  # package:test reporter (dart test / flutter test): "00:05 +300 ~1: All tests passed!"
  line="$(grep -E '^[0-9]{2}:[0-9]{2} \+[0-9]+.*:' "$logfile" 2>/dev/null | tail -n 1 || true)"
  if [ -z "$line" ]; then
    # vitest: "      Tests  9 passed (9)"
    line="$(grep -E '^[[:space:]]*Tests[[:space:]]' "$logfile" 2>/dev/null | tail -n 1 || true)"
  fi
  if [ -z "$line" ]; then
    # dart analyze / flutter analyze: "No issues found!" / "N issues found."
    line="$(grep -vE '^[[:space:]]*$' "$logfile" 2>/dev/null | tail -n 1 || true)"
  fi
  printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

# Pulls a bare test count out of a package:test-style summary ("+300 ~1: ..." -> 300).
count_from_dart_summary() {
  printf '%s' "$1" | grep -oE '\+[0-9]+' | head -n 1 | tr -d '+'
}

# Pulls a bare test count out of a vitest-style summary ("Tests  9 passed (9)" -> 9).
count_from_npm_summary() {
  printf '%s' "$1" | grep -oE '[0-9]+ passed' | head -n 1 | grep -oE '[0-9]+'
}

# run_step NAME LOGNAME CMD...
# Runs CMD, tees its output to a logfile, and records PASS/FAIL with a
# summary line. Never lets a failing suite abort the rest of the gate:
# every step gets a chance to run and be reported.
LAST_SUMMARY=""
run_step() {
  local name="$1" logname="$2"
  shift 2
  section "$name"
  local logfile="$WORK_DIR/$logname.log"
  local status=0
  "$@" 2>&1 | tee "$logfile" || status=$?
  LAST_SUMMARY="$(extract_summary "$logfile")"
  if [ "$status" -eq 0 ]; then
    record_step "$name" "PASS" "$LAST_SUMMARY"
  else
    record_step "$name" "FAIL" "$LAST_SUMMARY"
    OVERALL_FAIL=1
    echo
    echo "--- $name FAILED (exit $status) — last 40 lines above are from this step ---"
  fi
  return "$status"
}

# ===========================================================================
# 1. omnifi_core: dart analyze + dart test
# ===========================================================================
run_step "omnifi_core: dart analyze" "01-core-analyze" \
  bash -c "cd '$CORE_DIR' && dart analyze" || true

run_step "omnifi_core: dart test" "02-core-test" \
  bash -c "cd '$CORE_DIR' && dart test --reporter expanded" || true
CORE_COUNT="$(count_from_dart_summary "$LAST_SUMMARY")"
CORE_COUNT="${CORE_COUNT:-?}"

# ===========================================================================
# 2. The integration suite: start the relay, wait for it, run the
#    integration-tagged tests, stop the relay. This is the step that
#    "requires a human to have wrangler dev running by hand" used to gate on,
#    and that is exactly the gap this script closes.
# ===========================================================================
if [ "$RUN_INTEGRATION" -eq 1 ]; then
  section "integration suite: starting the relay"
  start_relay
  if wait_for_relay; then
    run_step "integration suite: dart test --tags integration" "03-integration-test" \
      bash -c "cd '$CORE_DIR' && dart test --tags integration --run-skipped --reporter expanded" || true
    INTEGRATION_COUNT="$(count_from_dart_summary "$LAST_SUMMARY")"
    INTEGRATION_COUNT="${INTEGRATION_COUNT:-?}"
  else
    record_step "integration suite: dart test --tags integration" "FAIL" "relay never became healthy — see log above"
    OVERALL_FAIL=1
    INTEGRATION_COUNT="?"
  fi
  stop_relay
else
  echo
  echo "Skipping the integration suite (--no-integration passed). This is a"
  echo "deliberate opt-out, not a default — the point of this script is that"
  echo "these tests do not get to be forgotten."
  record_step "integration suite: dart test --tags integration" "SKIPPED" "--no-integration"
fi

# ===========================================================================
# 3. The relay's own test suite. Independent of the dev server above —
#    vitest-pool-workers spins up its own isolated runtime per test file.
# ===========================================================================
run_step "relay: npm test" "04-relay-test" \
  bash -c "cd '$RELAY_DIR' && npm test" || true
RELAY_COUNT="$(count_from_npm_summary "$LAST_SUMMARY")"
RELAY_COUNT="${RELAY_COUNT:-?}"

# ===========================================================================
# 4. The Flutter app.
# ===========================================================================
run_step "omnifi_app: flutter analyze" "05-app-analyze" \
  bash -c "cd '$APP_DIR' && flutter analyze" || true

run_step "omnifi_app: flutter test" "06-app-test" \
  bash -c "cd '$APP_DIR' && flutter test --reporter expanded" || true
APP_COUNT="$(count_from_dart_summary "$LAST_SUMMARY")"
APP_COUNT="${APP_COUNT:-?}"

# ===========================================================================
# 5. Structural invariant: omnifi_core has no Flutter dependency. That is
#    what makes the protocol testable without a UI, and it's load-bearing
#    enough to gate on rather than just note in a review.
# ===========================================================================
section "structural invariant: omnifi_core must not import Flutter"
FORBIDDEN_HITS="$(grep -rnE 'package:flutter/|dart:ui' "$CORE_DIR/lib" 2>/dev/null || true)"
if [ -z "$FORBIDDEN_HITS" ]; then
  echo "No references to package:flutter/* or dart:ui in $CORE_DIR/lib"
  record_step "structural: omnifi_core has no Flutter import" "PASS" "clean"
else
  echo "$FORBIDDEN_HITS"
  HIT_COUNT="$(printf '%s\n' "$FORBIDDEN_HITS" | grep -c .)"
  record_step "structural: omnifi_core has no Flutter import" "FAIL" "$HIT_COUNT forbidden import(s)"
  OVERALL_FAIL=1
fi

# ===========================================================================
# Report
# ===========================================================================
section "Verification summary"
i=0
while [ "$i" -lt "${#STEP_NAMES[@]}" ]; do
  printf '%-58s %-8s %s\n' "${STEP_NAMES[$i]}" "${STEP_STATUSES[$i]}" "${STEP_SUMMARIES[$i]}"
  i=$((i + 1))
done

echo
echo "Totals: omnifi_core ${CORE_COUNT} + integration ${INTEGRATION_COUNT} + relay ${RELAY_COUNT} + omnifi_app ${APP_COUNT} tests"

if [ "$OVERALL_FAIL" -ne 0 ]; then
  echo
  echo "VERIFY FAILED — see step(s) above marked FAIL."
  exit 1
fi

echo
echo "VERIFY OK"
exit 0
