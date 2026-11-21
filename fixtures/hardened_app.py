"""
fixtures/hardened_app.py — Production-hardened implementation with DB-level atomicity.

Implements all three invariants from skills/concurrency-and-resource-bounds/SKILL.md:

  Invariant 1 — Atomic Check-and-Act
      Uses database-level conditional atomic update:
      UPDATE stock SET remaining = remaining - 1, sold = sold + 1 WHERE id = 1 AND remaining > 0;
      Inspects cursor.rowcount for reservation. Multi-process/multi-worker safe.
      Runs with SQLite WAL mode and busy_timeout=5000.

  Invariant 2 — Strict Ingress Resource Bounds
      MAX_BODY_SIZE (1 MB) enforced upfront via Content-Length and incrementally
      during chunked streaming reads; oversized payloads -> HTTP 413.

  Invariant 3 — Bounded Socket Lifecycles & Deadlines
      READ_TIMEOUT = 2.0s idle timeout set on connection.
      ABSOLUTE_REQUEST_TIMEOUT = 4.0s cumulative deadline to defeat slow data-drip attacks.
"""

import json
import pathlib
import socket
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Configuration constants (Invariant 2 + 3)
# ---------------------------------------------------------------------------
MAX_BODY_SIZE: int              = 1024 * 1024   # 1 MiB hard cap on every inbound body
CHUNK_SIZE: int                 = 64 * 1024     # 64 KiB streaming read window
READ_TIMEOUT: float             = 2.0           # seconds idle timeout on socket
ABSOLUTE_REQUEST_TIMEOUT: float = 4.0           # absolute cumulative deadline for request

DB_PATH = pathlib.Path(__file__).parent / "store_hardened.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS stock (id INTEGER PRIMARY KEY, remaining INTEGER, sold INTEGER);"
            )
            conn.execute("DELETE FROM stock WHERE id = 1;")
            conn.execute("INSERT INTO stock (id, remaining, sold) VALUES (1, 5, 0);")
    finally:
        conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.row_factory = sqlite3.Row
    return conn


class HardenedHandler(BaseHTTPRequestHandler):
    """HTTP request handler with database-level atomicity and resource limits."""

    timeout: float = READ_TIMEOUT

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        try:
            if self.path == "/stock":
                conn = get_db()
                try:
                    row = conn.execute("SELECT remaining, sold FROM stock WHERE id = 1;").fetchone()
                    if row:
                        self._json(200, {"remaining": row["remaining"], "sold": row["sold"]})
                    else:
                        self._json(404, {"error": "not found"})
                finally:
                    conn.close()
            else:
                self._json(404, {"error": "not found"})
        except (socket.timeout, TimeoutError):
            self._send_408()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    def do_POST(self):
        try:
            if self.path == "/buy":
                self._handle_buy()
            elif self.path == "/upload":
                self._handle_upload()
            else:
                self._json(404, {"error": "not found"})
        except (socket.timeout, TimeoutError):
            self._send_408()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass

    # ------------------------------------------------------------------
    # POST /buy — Invariant 1: atomic database reservation
    # ------------------------------------------------------------------
    def _handle_buy(self) -> None:
        conn = None
        try:
            conn = get_db()
            cursor = conn.execute(
                "UPDATE stock SET remaining = remaining - 1, sold = sold + 1 WHERE id = 1 AND remaining > 0;"
            )
            if cursor.rowcount == 1:
                conn.commit()
                # Downstream I/O simulation outside database lock/transaction
                time.sleep(0.005)
                self._json(200, {"status": "purchased"})
            else:
                conn.rollback()
                self._json(409, {"error": "out_of_stock"})
        except sqlite3.OperationalError as exc:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            self._json(503, {"error": "database_busy", "detail": str(exc)})
        finally:
            if conn:
                conn.close()

    # ------------------------------------------------------------------
    # POST /upload — Invariant 2 & 3: bounded streaming read & deadline
    # ------------------------------------------------------------------
    def _handle_upload(self) -> None:
        start_time = time.monotonic()

        raw_cl = self.headers.get("Content-Length")
        expected_len = None

        if raw_cl is not None:
            try:
                expected_len = int(raw_cl)
                if expected_len > MAX_BODY_SIZE:
                    self._send_413()
                    return
            except ValueError:
                self._json(400, {"error": "invalid content-length"})
                return

        # Ingress Stream / Chunked Protection:
        # Read the ingress socket stream in chunks with a rolling byte counter.
        # If cumulative received bytes exceed MAX_BODY_SIZE, immediately flush HTTP 413 and close.
        total_read = 0

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= ABSOLUTE_REQUEST_TIMEOUT:
                self._send_408()
                return

            remaining_time = max(0.01, ABSOLUTE_REQUEST_TIMEOUT - elapsed)
            current_timeout = min(READ_TIMEOUT, remaining_time)
            self.connection.settimeout(current_timeout)

            if expected_len is not None:
                bytes_left = expected_len - total_read
                if bytes_left <= 0:
                    break
                want = min(CHUNK_SIZE, bytes_left)
            else:
                want = CHUNK_SIZE

            try:
                chunk = self.connection.recv(want)
            except (socket.timeout, TimeoutError):
                if time.monotonic() - start_time >= ABSOLUTE_REQUEST_TIMEOUT:
                    self._send_408()
                    return
                raise
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                return

            if not chunk:
                break

            total_read += len(chunk)

            if total_read > MAX_BODY_SIZE:
                self._send_413()
                return

            if expected_len is not None and total_read >= expected_len:
                break

        self._json(200, {"bytes_received": total_read})

    def _send_413(self) -> None:
        try:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error": "payload_too_large", "max_bytes": 1048576}')
            self.wfile.flush()
        except Exception:
            pass
        finally:
            self.close_connection = True
            try:
                self.connection.close()
            except Exception:
                pass

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_408(self) -> None:
        try:
            self._json(408, {"error": "request timeout"})
        except Exception:
            pass
        finally:
            try:
                self.connection.close()
            except Exception:
                pass


if __name__ == "__main__":
    init_db()
    addr = ("127.0.0.1", 8000)
    server = ThreadingHTTPServer(addr, HardenedHandler)
    print(f"Listening on {addr[0]}:{addr[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
