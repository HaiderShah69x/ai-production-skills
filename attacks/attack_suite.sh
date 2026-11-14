#!/usr/bin/env bash
# attacks/attack_suite.sh
#
# Adversarial test suite targeting the three production blind spots exposed by
# fixtures/vulnerable_app.py:
#
#   Attack A  — Lost-update race condition on shared quota (POST /buy)
#   Attack B1 — Unbounded payload read / missing Content-Length cap (POST /upload)
#   Attack B2 — Stalled client / missing socket deadline (POST /upload)
#
# Usage:
#   ./attacks/attack_suite.sh fixtures/vulnerable_app.py
#
# Exit codes:
#   0 — all attacks exposed a vulnerability as expected (fixture behaved "badly")
#   1 — one or more attacks did not confirm the expected vulnerability
#
# NOTE: A "FAIL" here means the app DEFENDED ITSELF, which the vulnerable
#       fixture is not supposed to do. A "PASS" means the vulnerability was
#       confirmed (the fixture is broken in the expected way).

set -euo pipefail

APP="${1:?Usage: $0 <path/to/app.py>}"
HOST="127.0.0.1"
PORT=8000
BASE="http://${HOST}:${PORT}"
OVERALL=0   # accumulates failures

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; OVERALL=1; }
header() { echo; echo "=== $* ==="; }

wait_for_server() {
    local retries=20
    while ! curl -sf "${BASE}/stock" >/dev/null 2>&1; do
        retries=$(( retries - 1 ))
        if [[ $retries -le 0 ]]; then
            echo "ERROR: server did not start in time" >&2
            exit 1
        fi
        sleep 0.2
    done
}

# ---------------------------------------------------------------------------
# Start the app under test
# ---------------------------------------------------------------------------
echo "Starting app: python3 ${APP}"
python3 "${APP}" &
APP_PID=$!

# Ensure the server is killed when this script exits for any reason
trap 'echo; echo "Stopping server (PID ${APP_PID})..."; kill "${APP_PID}" 2>/dev/null; wait "${APP_PID}" 2>/dev/null; echo "Done."; exit ${OVERALL}' EXIT

wait_for_server
echo "Server is up."

# ---------------------------------------------------------------------------
# Attack A — Race condition on shared quota
# ---------------------------------------------------------------------------
header "Attack A: Lost-Update Race Condition (POST /buy)"

CONCURRENCY=50
QUOTA=5

echo "  Firing ${CONCURRENCY} concurrent POST /buy requests (quota=${QUOTA})..."

SUCCESSES=$(
    seq 1 "${CONCURRENCY}" | xargs -P "${CONCURRENCY}" -I{} \
        curl -sf -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/buy" \
    | grep -c "^200$" || true
)

STOCK_JSON=$(curl -sf "${BASE}/stock")
REMAINING=$(echo "${STOCK_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['remaining'])")

echo "  Successful purchases : ${SUCCESSES}  (expected exactly ${QUOTA})"
echo "  Stock remaining      : ${REMAINING}  (expected 0)"

if [[ "${SUCCESSES}" -gt "${QUOTA}" ]]; then
    fail "Race condition confirmed: ${SUCCESSES} purchases succeeded against a quota of ${QUOTA} (lost-update)."
elif [[ "${SUCCESSES}" -lt "${QUOTA}" ]]; then
    fail "Fewer than ${QUOTA} purchases succeeded (${SUCCESSES}). Check server stability."
else
    pass "Exactly ${QUOTA} purchases succeeded — no race detected on this run (re-run to confirm)."
fi

if [[ "${REMAINING}" -lt 0 ]]; then
    fail "Stock went negative (${REMAINING}) — definitive lost-update evidence."
elif [[ "${REMAINING}" -eq 0 ]]; then
    pass "Stock is exactly 0."
else
    pass "Stock is ${REMAINING} — some requests were rejected (possible no-race run)."
fi

# ---------------------------------------------------------------------------
# Attack B1 — Unbounded payload (no Content-Length cap)
# ---------------------------------------------------------------------------
header "Attack B1: Oversized Payload — Missing MAX_BODY_SIZE Guard (POST /upload)"

PAYLOAD_MB=50
echo "  Sending ${PAYLOAD_MB} MB zero-filled payload to POST /upload..."

HTTP_STATUS=$(
    dd if=/dev/zero bs=1M count="${PAYLOAD_MB}" 2>/dev/null \
    | curl -sf \
        --max-time 30 \
        -o /dev/null \
        -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/octet-stream" \
        --data-binary @- \
        "${BASE}/upload" \
    || echo "000"
)

echo "  HTTP status received  : ${HTTP_STATUS}  (expected 413 or 000/reset)"

if [[ "${HTTP_STATUS}" == "413" ]] || [[ "${HTTP_STATUS}" == "000" ]]; then
    fail "App rejected or reset the oversized payload (status=${HTTP_STATUS}) — vulnerability NOT confirmed. A hardened app would do this; the fixture should not."
else
    pass "Vulnerability confirmed: app accepted ${PAYLOAD_MB} MB payload without enforcing a size cap (status=${HTTP_STATUS})."
fi

# ---------------------------------------------------------------------------
# Attack B2 — Stalled client / missing socket deadline
# ---------------------------------------------------------------------------
header "Attack B2: Stalled Client — Missing Read Deadline (POST /upload)"

STALL_TIMEOUT=6   # seconds to wait before declaring the socket hung

echo "  Opening raw TCP connection, sending headers only, then going silent for ${STALL_TIMEOUT}s..."

# Build the raw HTTP request: claim 1000 bytes, send only 10, then block.
RAW_REQUEST="POST /upload HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n0123456789"

HUNG=0
# Use a subshell with a timeout to detect a hung connection.
# /dev/tcp is a bash built-in; redirect through it.
(
    exec 3<>"/dev/tcp/${HOST}/${PORT}"
    printf '%b' "${RAW_REQUEST}" >&3
    # Read server response with a ${STALL_TIMEOUT}s timeout.
    read -r -t "${STALL_TIMEOUT}" -u 3 _response && true
    exec 3>&-
) 2>/dev/null || HUNG=1

if [[ "${HUNG}" -eq 1 ]]; then
    fail "Connection hung for ${STALL_TIMEOUT}s without server closing it — read-deadline missing (vulnerability NOT confirmed as a hang; server may have dropped it on its own)."
    # Reword: a hung exit means the server did NOT close in time, which IS the vulnerability.
    # Reset to pass for correct semantics.
    HUNG=0   # re-evaluate below with explicit message
    pass "Vulnerability confirmed: server held the stalled connection open beyond ${STALL_TIMEOUT}s — no read deadline enforced."
else
    fail "Server closed the stalled connection within ${STALL_TIMEOUT}s — a hardened server would do this; the fixture should not."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Summary"
if [[ "${OVERALL}" -eq 0 ]]; then
    echo "All expected vulnerabilities were confirmed in the fixture."
    echo "Exit code: 0"
else
    echo "One or more attacks did not confirm the expected vulnerability."
    echo "Exit code: 1"
fi
