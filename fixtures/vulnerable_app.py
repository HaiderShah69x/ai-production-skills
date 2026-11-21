"""
fixtures/vulnerable_app.py — Intentionally vulnerable baseline implementation.

Demonstrates canonical production blind spots:
  1. Non-atomic check-then-update at the database layer (lost-update race):
     SELECT remaining ... -> if remaining > 0 -> sleep -> UPDATE stock SET remaining = ...
  2. Unbounded payload read trusting Content-Length with no cap.
  3. No socket deadlines or timeouts.

DO NOT use this code in production. It exists solely as an attack target.
"""

import json
import pathlib
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = pathlib.Path(__file__).parent / "store_vulnerable.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS stock (id INTEGER PRIMARY KEY, remaining INTEGER, sold INTEGER);"
            )
            conn.execute("DELETE FROM stock WHERE id = 1;")
            conn.execute("INSERT INTO stock (id, remaining, sold) VALUES (1, 5, 0);")
    finally:
        conn.close()


def get_db():
    # Return a new connection per request/thread with busy timeout
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


class VulnerableHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
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

    def do_POST(self):
        if self.path == "/buy":
            self._handle_buy()
        elif self.path == "/upload":
            self._handle_upload()
        else:
            self._json(404, {"error": "not found"})

    def _handle_buy(self):
        # FLAW 1: classic non-atomic check-then-update on SQLite database
        conn = get_db()
        try:
            row = conn.execute("SELECT remaining, sold FROM stock WHERE id = 1;").fetchone()
            if not row or row["remaining"] <= 0:
                self._json(409, {"error": "out_of_stock"})
                return

            remaining = row["remaining"]
            sold = row["sold"]

            # Simulation of DB/network/processing latency outside transaction lock
            time.sleep(0.01)

            # Non-atomic blind update based on stale local variables
            with conn:
                conn.execute(
                    "UPDATE stock SET remaining = ?, sold = ? WHERE id = 1;",
                    (remaining - 1, sold + 1),
                )
            self._json(200, {"status": "purchased"})
        finally:
            conn.close()

    def _handle_upload(self):
        # FLAW 2: unbounded payload read, no size limits or timeouts
        raw_cl = self.headers.get("Content-Length")
        if raw_cl is not None:
            length = int(raw_cl)
            data = self.rfile.read(length)
        else:
            # Unbounded chunked streaming read without size limit
            data = bytearray()
            while True:
                chunk = self.connection.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
                if b"0\r\n\r\n" in chunk:
                    break
        self._json(200, {"bytes_received": len(data)})

    def _json(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    init_db()
    addr = ("127.0.0.1", 8000)
    server = ThreadingHTTPServer(addr, VulnerableHandler)
    print(f"Listening on {addr[0]}:{addr[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
