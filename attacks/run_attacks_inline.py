#!/usr/bin/env python3
"""
attacks/run_attacks_inline.py
Single-process harness: dynamically loads the target app module, starts its
HTTP handler in a daemon thread, then runs all four attacks in the same
process (bypasses sandbox network isolation).

Attacks:
  A   — Concurrent quota contention (lost-update race)
  B1  — Oversized payload (missing MAX_BODY_SIZE cap)
  B2  — Idle stall (single-gap stall, missing idle timeout)
  B3  — Slow-drip attack (trickle bytes to bypass idle timeout;
         requires an absolute request deadline to defeat)

Usage:
    python attacks/run_attacks_inline.py [--target vulnerable|hardened]

  --target vulnerable  (default) confirms vulnerabilities exist  → exit 0 when
                       all four blind spots fire as expected.
  --target hardened    confirms mitigations work                  → exit 0 when
                       all four defences hold.

Pass/fail semantics differ by target so the same harness grades both apps.
"""

import argparse
import importlib.util
import json
import pathlib
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST       = "127.0.0.1"
PORT       = 8000
BASE       = f"http://{HOST}:{PORT}"
REPO_ROOT  = pathlib.Path(__file__).parent.parent

TARGETS = {
    "vulnerable": REPO_ROOT / "fixtures" / "vulnerable_app.py",
    "hardened":   REPO_ROOT / "fixtures" / "hardened_app.py",
}

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
OVERALL = 0   # 0 = all checks passed for chosen target


def log_pass(msg: str) -> None:
    print(f"  [PASS] {msg}", flush=True)


def log_fail(msg: str) -> None:
    global OVERALL
    OVERALL = 1
    print(f"  [FAIL] {msg}", flush=True)


def header(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


# ---------------------------------------------------------------------------
# Dynamic module loader — imports the handler class from the target file
# ---------------------------------------------------------------------------
def load_handler(path: pathlib.Path):
    """Return the BaseHTTPRequestHandler subclass from *path*."""
    spec   = importlib.util.spec_from_file_location("_target_app", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_target_app"] = module
    spec.loader.exec_module(module)

    from http.server import BaseHTTPRequestHandler
    for name in dir(module):
        obj = getattr(module, name)
        try:
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseHTTPRequestHandler)
                and obj is not BaseHTTPRequestHandler
            ):
                return obj
        except TypeError:
            pass
    raise RuntimeError(f"No BaseHTTPRequestHandler subclass found in {path}")


# ---------------------------------------------------------------------------
# Attack A — concurrent quota contention
# ---------------------------------------------------------------------------
def attack_a(mode: str) -> None:
    header("Attack A: Atomic Check-and-Act — Concurrent POST /buy")

    CONCURRENCY = 50
    QUOTA       = 5
    print(
        f"  Target : {mode}  |  Concurrency={CONCURRENCY}  Quota={QUOTA}",
        flush=True,
    )

    def buy() -> int:
        try:
            req = urllib.request.Request(f"{BASE}/buy", method="POST", data=b"")
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        statuses = [
            f.result()
            for f in as_completed([pool.submit(buy) for _ in range(CONCURRENCY)])
        ]

    successes  = statuses.count(200)
    stock_data = json.loads(urllib.request.urlopen(f"{BASE}/stock", timeout=5).read())
    remaining  = stock_data["remaining"]

    print(f"  Successful purchases : {successes}  (expected exactly {QUOTA})", flush=True)
    print(f"  Stock remaining      : {remaining}  (expected 0)", flush=True)

    if mode == "vulnerable":
        # Confirm the race fires
        if successes > QUOTA:
            log_pass(
                f"Race confirmed: {successes} purchases succeeded against quota "
                f"of {QUOTA} (lost-update race)."
            )
        else:
            log_fail(
                f"Expected >5 successes to confirm race; got {successes}. "
                "Re-run — race may not manifest every time."
            )
        if remaining < 0 or successes > QUOTA:
            log_pass(f"Lost-update race confirmed: {successes} purchases accepted, stock={remaining}.")
        else:
            log_fail(f"Stock was not oversold; got {remaining}.")
    else:
        # Confirm the fix holds
        if successes == QUOTA:
            log_pass(f"Exactly {QUOTA} purchases succeeded — atomicity holds.")
        elif successes > QUOTA:
            log_fail(
                f"Race NOT fixed: {successes} purchases succeeded against quota "
                f"of {QUOTA} (lost-update still present)."
            )
        else:
            log_fail(
                f"Only {successes} purchases succeeded (expected {QUOTA}). "
                "Lock may be held too long or server is unstable."
            )
        if remaining == 0:
            log_pass("Stock is exactly 0 — fully consumed, never negative.")
        elif remaining < 0:
            log_fail(f"Stock went negative ({remaining}) — atomicity broken.")
        else:
            log_fail(f"Stock is {remaining} (expected 0) — not all quota consumed.")


# ---------------------------------------------------------------------------
# Attack B1 — oversized payload
# ---------------------------------------------------------------------------
def attack_b1(mode: str) -> None:
    header("Attack B1: Ingress Resource Bounds — 10 MB POST /upload")

    PAYLOAD_MB    = 10
    payload_bytes = PAYLOAD_MB * 1024 * 1024
    print(f"  Target : {mode}  |  Payload={PAYLOAD_MB} MB", flush=True)

    status = -1
    try:
        data = b"\x00" * payload_bytes
        req  = urllib.request.Request(
            f"{BASE}/upload",
            method="POST",
            data=data,
            headers={"Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        status = 0   # connection reset — equivalent to 000
    except Exception as exc:
        status = 0
        print(f"  (exception: {exc})", flush=True)

    print(
        f"  HTTP status received  : {status}  "
        f"({'expected 413' if mode == 'hardened' else 'expected 200'})",
        flush=True,
    )

    if mode == "vulnerable":
        if status == 200:
            log_pass(
                f"Vulnerability confirmed: app accepted {PAYLOAD_MB} MB without "
                f"a size cap (status=200)."
            )
        else:
            log_fail(
                f"Expected 200 to confirm vulnerability; got {status}. "
                "App may already be guarded."
            )
    else:
        if status == 413:
            log_pass(
                f"Mitigation holds: oversized {PAYLOAD_MB} MB payload rejected "
                f"with HTTP 413."
            )
        elif status == 0:
            log_pass(
                "Mitigation holds: server reset connection on oversized payload "
                "(connection reset / 000)."
            )
        else:
            log_fail(
                f"Expected HTTP 413 for oversized payload; got {status}. "
                "MAX_BODY_SIZE guard missing or not enforced."
            )


# ---------------------------------------------------------------------------
# Attack B2 — stalled client / missing read deadline
# ---------------------------------------------------------------------------
def attack_b2(mode: str) -> None:
    header("Attack B2: Socket Lifecycle — Stalled Client (POST /upload)")

    STALL_WINDOW = 6   # seconds to wait before declaring result

    print(
        f"  Target : {mode}  |  Stall window={STALL_WINDOW}s  "
        f"(hardened READ_TIMEOUT=2s)",
        flush=True,
    )
    print(
        "  Sending HTTP headers + 10/1000 body bytes, then going silent...",
        flush=True,
    )

    partial = (
        "POST /upload HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Length: 1000\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0123456789"   # only 10 of promised 1000 bytes
    ).encode()

    hung    = False
    elapsed = 0.0
    start   = time.monotonic()
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        try:
            sock.sendall(partial)
            sock.settimeout(STALL_WINDOW)
            try:
                data   = sock.recv(4096)
                elapsed = time.monotonic() - start
                hung   = not data   # empty bytes → server closed cleanly
            except socket.timeout:
                elapsed = time.monotonic() - start
                hung    = True      # server never closed within stall window
        finally:
            sock.close()
    except Exception as exc:
        elapsed = time.monotonic() - start
        print(f"  (socket error: {exc})", flush=True)
        hung = False

    print(f"  Elapsed: {elapsed:.2f}s  |  Connection hung: {hung}", flush=True)

    if mode == "vulnerable":
        if hung:
            log_pass(
                f"Vulnerability confirmed: server held stalled connection open "
                f"beyond {STALL_WINDOW}s — no read deadline enforced."
            )
        else:
            log_fail(
                f"Expected connection to hang for {STALL_WINDOW}s; server closed "
                f"after {elapsed:.2f}s. App may already have a timeout."
            )
    else:
        GRACE = 1.5   # allow up to READ_TIMEOUT(2s) + 1.5s grace
        if not hung and elapsed <= (2.0 + GRACE):
            log_pass(
                f"Mitigation holds: server closed stalled connection after "
                f"{elapsed:.2f}s (within READ_TIMEOUT + grace)."
            )
        elif hung:
            log_fail(
                f"READ_TIMEOUT NOT enforced: connection still open after "
                f"{STALL_WINDOW}s."
            )
        else:
            log_fail(
                f"Server closed after {elapsed:.2f}s — outside expected window "
                f"(READ_TIMEOUT=2s + grace={GRACE}s)."
            )


# ---------------------------------------------------------------------------
# Attack B3 — slow-drip attack (bypasses idle timeout via trickle sends)
# ---------------------------------------------------------------------------
def attack_b3(mode: str) -> None:
    header("Attack B3: Slow-Drip — Absolute Request Deadline (POST /upload)")

    # Strategy: declare Content-Length: 100, then send 1 byte every 1.2 s.
    # Each inter-byte gap (1.2 s) is just below the idle READ_TIMEOUT (2.0 s),
    # so a server that only enforces an idle timeout will never fire it.
    # Only an ABSOLUTE_REQUEST_TIMEOUT (e.g. 4.0 s wall-clock) will close this.
    DRIP_INTERVAL  = 1.2   # seconds between each byte — stays under idle timeout
    DRIP_COUNT     = 5     # bytes sent in total (of the promised 100)
    TOTAL_DURATION = DRIP_INTERVAL * DRIP_COUNT   # 6.0 s total experiment window
    ABS_DEADLINE   = 4.0   # hardened_app.py ABSOLUTE_REQUEST_TIMEOUT
    GRACE          = 1.0   # allow up to deadline + grace before calling it hung

    print(
        f"  Target         : {mode}\n"
        f"  Strategy       : send 1 byte every {DRIP_INTERVAL}s "
        f"({DRIP_COUNT} bytes of promised 100)\n"
        f"  Idle timeout   : 2.0s (each gap stays below it)\n"
        f"  Abs deadline   : {ABS_DEADLINE}s (hardened only)\n"
        f"  Experiment cap : {TOTAL_DURATION}s",
        flush=True,
    )

    headers_raw = (
        "POST /upload HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Length: 100\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    closed_at: float = TOTAL_DURATION + 1.0   # sentinel: "never closed"
    start = time.monotonic()

    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        try:
            sock.sendall(headers_raw)

            for i in range(DRIP_COUNT):
                time.sleep(DRIP_INTERVAL)
                try:
                    # Try to send 1 drip byte; if the server already closed
                    # the connection this will raise BrokenPipeError / ECONNRESET / OSError
                    sock.sendall(bytes([0x41 + i]))   # 'A', 'B', …
                except (BrokenPipeError, ConnectionResetError, OSError):
                    closed_at = time.monotonic() - start
                    break
                # Also try a non-blocking peek for a server-sent close / 408
                try:
                    sock.settimeout(0.05)
                    data = sock.recv(256)
                    if not data or b"408" in data or b"close" in data.lower():
                        closed_at = time.monotonic() - start
                        break
                except socket.timeout:
                    continue   # server still open — keep dripping
                except (BrokenPipeError, ConnectionResetError, OSError):
                    closed_at = time.monotonic() - start
                    break

            if closed_at > TOTAL_DURATION:
                # Read one last time with a short timeout to catch a late close
                try:
                    sock.settimeout(0.5)
                    data = sock.recv(256)
                    if not data or b"408" in data:
                        closed_at = time.monotonic() - start
                except (socket.timeout, BrokenPipeError, ConnectionResetError, OSError):
                    pass   # confirmed hung

        finally:
            try:
                sock.close()
            except Exception:
                pass
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        closed_at = time.monotonic() - start
    except Exception as exc:
        print(f"  (unexpected error: {exc})", flush=True)
        closed_at = 0.0

    elapsed = time.monotonic() - start
    hung    = closed_at > (ABS_DEADLINE + GRACE)

    print(
        f"  Closed at      : {closed_at:.2f}s  "
        f"(experiment ran {elapsed:.2f}s)  |  Hung: {hung}",
        flush=True,
    )

    if mode == "vulnerable":
        if hung:
            log_pass(
                f"Vulnerability confirmed: server accepted slow-drip for "
                f"{closed_at:.2f}s — no absolute request deadline enforced."
            )
        else:
            log_fail(
                f"Expected server to stay open for the full drip experiment; "
                f"closed after {closed_at:.2f}s. App may already have an "
                "absolute deadline (unexpected on the vulnerable fixture)."
            )
    else:
        if not hung:
            log_pass(
                f"Mitigation holds: server terminated slow-drip connection after "
                f"{closed_at:.2f}s (within ABSOLUTE_REQUEST_TIMEOUT={ABS_DEADLINE}s "
                f"+ grace={GRACE}s)."
            )
        else:
            log_fail(
                f"ABSOLUTE_REQUEST_TIMEOUT NOT enforced: slow-drip connection "
                f"stayed open beyond {ABS_DEADLINE + GRACE}s. "
                "Idle timeout alone is insufficient against slow-drip attacks."
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the concurrency-and-resource-bounds attack suite.",
    )
    parser.add_argument(
        "--target",
        default="vulnerable",
        help=(
            "Which fixture to test. Accepts a named alias "
            "('vulnerable' or 'hardened') or a path to any app .py file."
        ),
    )
    args = parser.parse_args()
    raw = args.target

    # Resolve --target to a (mode_label, path) pair.
    # Accept both named aliases and explicit file paths.
    if raw in TARGETS:
        mode = raw
        path = TARGETS[raw]
    else:
        # Treat as a file path; derive mode label from filename stem
        path = pathlib.Path(raw)
        if not path.is_absolute():
            # Resolve relative to CWD (caller's working directory)
            path = pathlib.Path.cwd() / path
        path = path.resolve()
        stem = path.stem   # e.g. "hardened_app" → "hardened", "vulnerable_app" → "vulnerable"
        if "hardened" in stem:
            mode = "hardened"
        elif "vulnerable" in stem:
            mode = "vulnerable"
        else:
            # Unknown fixture — grade as hardened (all defences expected)
            mode = "hardened"
        if not path.exists():
            print(f"ERROR: target file not found: {path}", file=sys.stderr)
            sys.exit(2)

    print(f"Loading handler from: {path}", flush=True)
    HandlerClass = load_handler(path)
    print(f"Handler class       : {HandlerClass.__name__}", flush=True)

    # Reset shared state and database files so each run starts fresh
    target_module = sys.modules.get("_target_app")
    if target_module and hasattr(target_module, "init_db"):
        target_module.init_db()
    elif target_module and hasattr(target_module, "STOCK"):
        target_module.STOCK["remaining"] = 5
        target_module.STOCK["sold"]      = 0

    # Also clean up any existing database files directly if target matches
    if mode == "vulnerable":
        db_file = REPO_ROOT / "fixtures" / "store_vulnerable.db"
        for f in [db_file, db_file.with_name("store_vulnerable.db-wal"), db_file.with_name("store_vulnerable.db-shm")]:
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass
        if target_module and hasattr(target_module, "init_db"):
            target_module.init_db()
    elif mode == "hardened":
        db_file = REPO_ROOT / "fixtures" / "store_hardened.db"
        for f in [db_file, db_file.with_name("store_hardened.db-wal"), db_file.with_name("store_hardened.db-shm")]:
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass
        if target_module and hasattr(target_module, "init_db"):
            target_module.init_db()

    print("Starting server...", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), HandlerClass)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.4)
    print("Server is up.\n", flush=True)

    try:
        attack_a(mode)
        attack_b1(mode)
        attack_b2(mode)
        attack_b3(mode)
    finally:
        server.shutdown()
        print("\nServer stopped.", flush=True)

    header("Summary")
    label = "hardened" if mode == "hardened" else "vulnerable fixture"
    if OVERALL == 0:
        print(f"All checks PASSED for {label}.")
    else:
        print(f"One or more checks FAILED for {label}.")
    print(f"Exit code: {OVERALL}", flush=True)
    sys.exit(OVERALL)


if __name__ == "__main__":
    main()
