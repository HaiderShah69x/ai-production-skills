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
import multiprocessing as mp
import os
import pathlib
import re
import select
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
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
# Attack A — concurrent quota contention (multi-process OS concurrency)
# ---------------------------------------------------------------------------
def _worker_buy_process(barrier, url: str) -> tuple[int, bool, int]:
    """
    Worker task executing in a distinct operating system process.
    Synchronizes on barrier to ensure true simultaneous concurrency across
    distinct PIDs, independently opening a new HTTP connection over loopback sockets
    to test true OS-level TCP backlog and SQLite database lock contention.
    Returns (status_code, is_crash, pid).
    """
    pid = os.getpid()
    if barrier is not None:
        try:
            barrier.wait(timeout=15)
        except Exception:
            pass

    try:
        req = urllib.request.Request(f"{url}/buy", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=10) as r:
            return (r.status, False, pid)
    except urllib.error.HTTPError as e:
        is_crash = e.code >= 500
        return (e.code, is_crash, pid)
    except Exception:
        return (0, True, pid)


def attack_a(mode: str) -> None:
    header("Attack A: Atomic Check-and-Act — Concurrent POST /buy")

    CONCURRENCY = 50
    QUOTA       = 5
    print(
        f"  Target : {mode}  |  Concurrency={CONCURRENCY} (Multi-Process)  Quota={QUOTA}",
        flush=True,
    )

    manager = mp.Manager()
    barrier = manager.Barrier(CONCURRENCY)

    with ProcessPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [
            pool.submit(_worker_buy_process, barrier, BASE)
            for _ in range(CONCURRENCY)
        ]
        results = [f.result() for f in as_completed(futures)]

    statuses = [s for s, _, _ in results]
    crashes = sum(1 for _, c, _ in results if c)
    pids = set(pid for _, _, pid in results)
    successes = statuses.count(200)
    out_of_stock = statuses.count(409)

    print("\n  Worker Outcome Distribution:", flush=True)
    print(f"    - Unique Worker PIDs        : {len(pids)} (expected {CONCURRENCY})", flush=True)
    print(f"    - Success (200)             : {successes}", flush=True)
    print(f"    - Out of Stock (409)        : {out_of_stock}", flush=True)
    print(f"    - Unhandled Crashes (500/Ex): {crashes}", flush=True)

    stock_data = json.loads(urllib.request.urlopen(f"{BASE}/stock", timeout=5).read())
    remaining  = stock_data["remaining"]
    sold       = stock_data.get("sold", QUOTA - remaining)

    print(f"\n  Final Database State:", flush=True)
    print(f"    - Sold                     : {sold}  (expected {QUOTA})", flush=True)
    print(f"    - Remaining                : {remaining}  (expected 0)", flush=True)

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
        # Confirm the fix holds with strict assertions:
        # 1. Zero unhandled worker crashes: crash_count == 0
        if crashes == 0:
            log_pass(f"Zero unhandled worker crashes: crash_count == 0 ({crashes} crashes).")
        else:
            log_fail(f"Detected {crashes} worker crashes or unhandled server exceptions.")

        # 2. Exact success quota: exactly 5 workers returned HTTP 200
        if successes == QUOTA:
            log_pass(f"Exact success quota: exactly {QUOTA} workers returned HTTP 200.")
        else:
            log_fail(f"Success quota breached: expected {QUOTA} HTTP 200, got {successes}.")

        # 3. Exact bounded rejection quota: exactly 45 workers returned HTTP 409 (Out of Stock)
        expected_rejections = CONCURRENCY - QUOTA
        if out_of_stock == expected_rejections:
            log_pass(f"Exact bounded rejection quota: exactly {expected_rejections} workers returned HTTP 409 (Out of Stock).")
        else:
            log_fail(f"Rejection quota mismatch: expected {expected_rejections} HTTP 409, got {out_of_stock}.")

        # 4. Database state: sold == 5 and remaining == 0
        if sold == QUOTA and remaining == 0:
            log_pass(f"Database state verified: sold == {QUOTA} and remaining == 0.")
        else:
            log_fail(f"Database state invalid: sold={sold} (expected {QUOTA}), remaining={remaining} (expected 0).")


# ---------------------------------------------------------------------------
# Raw HTTP socket helper
# ---------------------------------------------------------------------------
def send_raw_http(raw_header: bytes, body_chunks: list[bytes] = None) -> tuple[int, bytes]:
    """
    Connect via raw TCP, send HTTP headers and body chunks, and read the response.
    Returns (status_code, response_bytes). If connection is reset or dropped without
    HTTP response, status_code is 0.
    """
    sock = None
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        sock.sendall(raw_header)

        resp = b""

        if body_chunks:
            # Check if server sent an immediate response (e.g. upfront 413 rejection on headers)
            r, _, _ = select.select([sock], [], [], 0.1)
            if r:
                while True:
                    try:
                        sock.settimeout(1.0)
                        data = sock.recv(4096)
                        if not data:
                            break
                        resp += data
                    except Exception:
                        break
            else:
                sock.settimeout(2.0)
                for chunk in body_chunks:
                    # Check if server sent an early response (e.g. streaming cap reached)
                    r, _, _ = select.select([sock], [], [], 0.02)
                    if r:
                        while True:
                            try:
                                sock.settimeout(0.5)
                                data = sock.recv(4096)
                                if not data:
                                    break
                                resp += data
                            except Exception:
                                break
                        break
                    try:
                        sock.sendall(chunk)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break

        # Read any remaining response bytes
        if not resp:
            sock.settimeout(5.0)
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    resp += data
                except Exception:
                    break

        # Extract HTTP status code
        if resp:
            m = re.search(r"HTTP/\d\.\d\s+(\d+)", resp.decode("latin1", errors="ignore"))
            if m:
                return (int(m.group(1)), resp)
        return (0, resp)
    except Exception:
        return (0, b"")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Attack B1 — oversized payload (Content-Length declared)
# ---------------------------------------------------------------------------
def attack_b1_ingress_bounds(mode: str) -> None:
    header("Attack B1: Ingress Resource Bounds — 10 MB POST /upload")

    PAYLOAD_MB    = 10
    payload_bytes = PAYLOAD_MB * 1024 * 1024
    print(f"  Target : {mode}  |  Payload={PAYLOAD_MB} MB", flush=True)

    raw_header = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Content-Length: {payload_bytes}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    chunk = b"\x00" * (64 * 1024)
    num_chunks = payload_bytes // len(chunk)
    body_chunks = [chunk for _ in range(num_chunks)]

    status, resp = send_raw_http(raw_header, body_chunks)

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
                f"with RFC-compliant HTTP 413."
            )
        elif status == 0:
            log_fail(
                "Mitigation failed: server dropped/reset connection (status 0); "
                "expected clean HTTP 413 RFC compliance."
            )
        else:
            log_fail(
                f"Expected HTTP 413 for oversized payload; got {status}. "
                "MAX_BODY_SIZE guard missing or not enforced."
            )


attack_b1 = attack_b1_ingress_bounds


# ---------------------------------------------------------------------------
# Attack B1 (Chunked) — chunked streaming exhaustion (no Content-Length)
# ---------------------------------------------------------------------------
def attack_b1_chunked_streaming_exhaustion(mode: str) -> None:
    header("Attack B1 (Chunked): Streaming Ingress Exhaustion (POST /upload)")

    STREAM_MB = 1.25  # Exceeds 1 MB cap
    print(f"  Target : {mode}  |  Chunked stream={STREAM_MB} MB (no Content-Length)", flush=True)

    raw_header = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    chunk_payload = b"X" * (64 * 1024)  # 64 KB
    chunk_line = f"{len(chunk_payload):x}\r\n".encode() + chunk_payload + b"\r\n"
    # 20 chunks * 64 KB = 1,280 KB = 1.25 MB
    chunks = [chunk_line for _ in range(20)] + [b"0\r\n\r\n"]

    status, resp = send_raw_http(raw_header, chunks)

    print(
        f"  HTTP status received  : {status}  "
        f"({'expected 413' if mode == 'hardened' else 'expected 200'})",
        flush=True,
    )

    if mode == "vulnerable":
        if status == 200:
            log_pass(
                f"Vulnerability confirmed: app ingested {STREAM_MB} MB chunked stream "
                "without memory bounds (status=200)."
            )
        else:
            log_fail(
                f"Expected 200 on vulnerable target; got {status}."
            )
    else:
        if status == 413:
            log_pass(
                f"Mitigation holds: unannounced chunked stream exceeding 1 MB rejected "
                "with RFC-compliant HTTP 413."
            )
        elif status == 0:
            log_fail(
                "Mitigation failed: server dropped/reset connection (status 0); "
                "expected clean HTTP 413 RFC compliance."
            )
        else:
            log_fail(
                f"Expected HTTP 413 for chunked streaming exhaustion; got {status}."
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
# Attack B3 — Slowloris connection pool exhaustion & anti-starvation
# ---------------------------------------------------------------------------
def attack_b3_slowloris_pool_exhaustion(mode: str) -> None:
    header("Attack B3: Slowloris Pool Exhaustion & Anti-Starvation (POST /upload + POST /buy)")

    SLOW_CLIENTS    = 35    # concurrent slow-drip sockets (exceeds MAX_CONCURRENT_CONNECTIONS = 30)
    LEGIT_CLIENTS   = 5     # concurrent legitimate business requests
    DRIP_INTERVAL   = 1.5   # seconds between each trickle byte (stays under READ_TIMEOUT=2.0s)
    DRIP_COUNT      = 4     # 4 gaps * 1.5s = 6.0s total experiment duration
    ABS_DEADLINE    = 4.0   # hardened ABSOLUTE_REQUEST_TIMEOUT
    GRACE           = 1.5   # allow up to deadline + grace before declaring hung
    CUTOFF          = ABS_DEADLINE + GRACE  # 5.5s

    # Reset database stock and connection pool before Attack B3
    target_module = sys.modules.get("_target_app")
    if target_module and hasattr(target_module, "reset_connection_pool"):
        target_module.reset_connection_pool()

    db_file = REPO_ROOT / "fixtures" / ("store_hardened.db" if mode == "hardened" else "store_vulnerable.db")
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute("UPDATE stock SET remaining = 10, sold = 0 WHERE id = 1;")
    conn.close()

    print(
        f"  Target          : {mode}\n"
        f"  Database stock  : reset to remaining=10, sold=0\n"
        f"  Slowloris pool  : {SLOW_CLIENTS} concurrent slow-drip sockets (cap = 30)\n"
        f"  Abs deadline    : {ABS_DEADLINE}s (hardened only)\n"
        f"  Experiment cap  : {DRIP_INTERVAL * DRIP_COUNT}s",
        flush=True,
    )

    ready_barrier = threading.Barrier(SLOW_CLIENTS)
    slow_closed_times: dict[int, float] = {}
    slow_503_flags: dict[int, bool] = {}

    def slow_worker(idx: int) -> None:
        t0 = time.monotonic()
        closed_at = 999.0
        got_503 = False
        sock = None
        try:
            sock = socket.create_connection((HOST, PORT), timeout=10)
            try:
                ready_barrier.wait(timeout=5.0)
            except Exception:
                pass

            headers = (
                "POST /upload HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                "Content-Length: 1000\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()
            sock.sendall(headers)

            # Check if server immediately rejected with 503 (connection pool exhausted)
            r, _, _ = select.select([sock], [], [], 0.5)
            if r:
                try:
                    data = sock.recv(1024)
                    if b"503" in data and b"connection_pool_exhausted" in data:
                        got_503 = True
                        closed_at = time.monotonic() - t0
                except Exception:
                    pass

            if not got_503:
                for i in range(DRIP_COUNT):
                    time.sleep(DRIP_INTERVAL)
                    try:
                        sock.sendall(bytes([0x41 + (i % 26)]))
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        closed_at = time.monotonic() - t0
                        break
                    try:
                        sock.settimeout(0.05)
                        data = sock.recv(256)
                        if not data or b"408" in data or b"close" in data.lower():
                            closed_at = time.monotonic() - t0
                            break
                    except socket.timeout:
                        continue
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        closed_at = time.monotonic() - t0
                        break

                if closed_at == 999.0:
                    try:
                        sock.settimeout(0.5)
                        data = sock.recv(256)
                        if not data or b"408" in data:
                            closed_at = time.monotonic() - t0
                    except Exception:
                        pass
        except Exception:
            closed_at = time.monotonic() - t0
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            slow_503_flags[idx] = got_503
            slow_closed_times[idx] = closed_at

    slow_threads = [
        threading.Thread(target=slow_worker, args=(i,), daemon=True)
        for i in range(SLOW_CLIENTS)
    ]
    for t in slow_threads:
        t.start()

    # Wait for all slowloris threads to complete (either via 503 or 4.0s deadline)
    for t in slow_threads:
        t.join(timeout=8.0)

    closed_values = list(slow_closed_times.values())
    count_503 = sum(1 for v in slow_503_flags.values() if v)
    acquired_count = SLOW_CLIENTS - count_503
    hung_slow = sum(1 for idx, c in slow_closed_times.items() if not slow_503_flags.get(idx, False) and c > CUTOFF)
    terminated_slow = acquired_count - hung_slow
    acquired_closed_vals = [c for idx, c in slow_closed_times.items() if not slow_503_flags.get(idx, False)]
    avg_closed = sum(acquired_closed_vals) / len(acquired_closed_vals) if acquired_closed_vals else 0.0

    print(
        f"  Excess sockets (503): {count_503}/{SLOW_CLIENTS} rejected immediately with HTTP 503\n"
        f"  Acquired sockets    : {terminated_slow}/{acquired_count} terminated within deadline "
        f"({hung_slow} hung past {CUTOFF:.1f}s)",
        flush=True,
    )

    if mode == "vulnerable":
        if hung_slow > 0:
            log_pass(
                f"Vulnerability confirmed: server held {hung_slow}/{SLOW_CLIENTS} "
                f"slow-drip sockets open beyond {CUTOFF:.1f}s (no absolute deadline enforced)."
            )
        else:
            log_fail(
                "Expected slow-drip sockets to hang; server closed all sockets early "
                f"(avg {avg_closed:.2f}s)."
            )
    else:
        # 1. Assert exactly 5 excess sockets rejected with 503
        if count_503 == 5 and acquired_count == 30:
            log_pass(
                f"Pool bounding holds: exactly {count_503} excess connections rejected with "
                "HTTP 503, exactly 30 acquired pool slots."
            )
        else:
            log_fail(
                f"Expected exactly 5 excess connections rejected with 503; got {count_503} "
                f"(acquired={acquired_count})."
            )

        # 2. Assert all 30 slow-drip sockets terminated by deadline
        if hung_slow == 0 and terminated_slow == 30:
            log_pass(
                f"Mitigation holds: all {acquired_count} acquired slow-drip sockets terminated within "
                f"ABSOLUTE_REQUEST_TIMEOUT + grace (avg {avg_closed:.2f}s <= {CUTOFF:.1f}s)."
            )
        else:
            log_fail(
                f"ABSOLUTE_REQUEST_TIMEOUT NOT enforced: {hung_slow}/{acquired_count} "
                f"slow-drip sockets hung beyond {CUTOFF:.1f}s."
            )

        # 3. Dispatch legitimate requests to verify server recovery and database atomicity
        print(
            f"  Dispatching {LEGIT_CLIENTS} concurrent legitimate POST /buy requests "
            "after pool recovery...",
            flush=True,
        )

        def legit_buy() -> tuple[int, float]:
            t_start = time.monotonic()
            try:
                req = urllib.request.Request(f"{BASE}/buy", method="POST", data=b"")
                with urllib.request.urlopen(req, timeout=5) as r:
                    return (r.status, time.monotonic() - t_start)
            except urllib.error.HTTPError as e:
                return (e.code, time.monotonic() - t_start)
            except Exception:
                return (0, time.monotonic() - t_start)

        with ThreadPoolExecutor(max_workers=LEGIT_CLIENTS) as pool:
            futures = [pool.submit(legit_buy) for _ in range(LEGIT_CLIENTS)]
            legit_results = [f.result() for f in as_completed(futures)]

        legit_statuses = [st for st, _ in legit_results]
        legit_max_time = max(dur for _, dur in legit_results)

        print(
            f"  Legitimate requests : {len(legit_statuses)} completed in max {legit_max_time:.2f}s "
            f"(statuses: {sorted(legit_statuses)})",
            flush=True,
        )

        if all(st == 200 for st in legit_statuses) and legit_max_time <= 1.0:
            log_pass(
                f"Transactional integrity holds: all {LEGIT_CLIENTS} legitimate requests returned HTTP 200 "
                f"within {legit_max_time:.2f}s."
            )
        else:
            log_fail(
                f"Legitimate requests failed or slow: statuses={legit_statuses}, max_time={legit_max_time:.2f}s."
            )

        # 4. Assert database stock reflects exactly 5 purchases (remaining=5, sold=5)
        conn = sqlite3.connect(db_file)
        row = conn.execute("SELECT remaining, sold FROM stock WHERE id = 1;").fetchone()
        conn.close()
        remaining, sold = row[0], row[1]
        print(f"  Final DB stock state: remaining={remaining}, sold={sold}", flush=True)

        if remaining == 5 and sold == 5:
            log_pass(
                f"Database state verified: remaining={remaining}, sold={sold} (5 units successfully sold)."
            )
        else:
            log_fail(
                f"Database state mismatch: expected remaining=5, sold=5; got remaining={remaining}, sold={sold}."
            )


attack_b3 = attack_b3_slowloris_pool_exhaustion


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
    class BoundThreadingHTTPServer(ThreadingHTTPServer):
        request_queue_size = 128
    server = BoundThreadingHTTPServer((HOST, PORT), HandlerClass)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.4)
    print("Server is up.\n", flush=True)

    try:
        attack_a(mode)
        attack_b1_ingress_bounds(mode)
        attack_b1_chunked_streaming_exhaustion(mode)
        attack_b2(mode)
        attack_b3_slowloris_pool_exhaustion(mode)
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
