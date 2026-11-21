"""
fixtures/auth_fixtures.py — SQLite-backed vulnerable and hardened document services.

Replaces in-memory mock abstractions with real database state, live TCP loopback
server harness, and OS-level handle containment using isolated in-memory SQLite URIs.

Production blind spots covered:
  1. Cross-tenant IDOR via un-scoped SQL mutations.
  2. Path traversal, symlink/junction escapes, NTFS ADS, Windows device names.
  3. Mass-assignment of tenant_id, owner_id, role, or arbitrary keys.
  4. TOCTOU filesystem races defeated via handle-based path confinement.
"""

import ctypes
import json
import os
import pathlib
import re
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple

FIXTURES_DIR = pathlib.Path(__file__).parent.resolve()
PUBLIC_FILES_DIR = (FIXTURES_DIR / "public_files").resolve()
PUBLIC_FILES_DIR.mkdir(exist_ok=True)

# Write a benign public file and a secret external file
(PUBLIC_FILES_DIR / "report.txt").write_text("Public Quarterly Report Data", encoding="utf-8")
SECRET_FILE = (FIXTURES_DIR / "secret_keys.txt").resolve()
SECRET_FILE.write_text("SUPER_SECRET_API_KEY_9999", encoding="utf-8")

# Windows reserved device names (case-insensitive, with or without extension)
_WINDOWS_RESERVED = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..+)?$", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Database Layer
# ---------------------------------------------------------------------------

def create_isolated_db() -> Tuple[str, sqlite3.Connection]:
    """
    Initialize an isolated, unique in-memory SQLite database using URI shared cache.
    Prevents file lock contention on Windows while providing real SQLite engine semantics.
    """
    db_uri = f"file:memdb_{uuid.uuid4().hex}?mode=memory&cache=shared"
    conn = sqlite3.connect(db_uri, uri=True)
    conn.execute("PRAGMA foreign_keys = ON;")
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                role TEXT,
                FOREIGN KEY(tenant_id) REFERENCES tenants(id)
            );
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                owner_id TEXT,
                title TEXT,
                content TEXT,
                FOREIGN KEY(tenant_id) REFERENCES tenants(id),
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT,
                status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute(
            "INSERT OR REPLACE INTO tenants VALUES ('tenant_1', 'Org Alpha'), ('tenant_2', 'Org Beta');"
        )
        conn.execute(
            "INSERT OR REPLACE INTO users VALUES ('usr_a', 'tenant_1', 'user'), ('usr_b', 'tenant_2', 'user');"
        )
        conn.execute(
            "INSERT OR REPLACE INTO documents VALUES ('doc_1', 'tenant_1', 'usr_a', 'Doc 1', 'Tenant 1 Private Data');"
        )
        conn.execute(
            "INSERT OR REPLACE INTO documents VALUES ('doc_2', 'tenant_2', 'usr_b', 'Doc 2', 'Tenant 2 Private Data');"
        )
    return db_uri, conn


# ---------------------------------------------------------------------------
# Vulnerable Implementation
# ---------------------------------------------------------------------------

class VulnerableDocumentService:
    """
    Intentionally insecure service:
      - Updates via insecure query: UPDATE documents SET content = ? WHERE id = ?;
        (completely ignoring tenant and owner boundaries, and ignoring rowcount).
      - Direct file read using base_dir / filename without canonicalization, device name filtering,
        or handle containment.
      - Direct dictionary assignment accepting any key (allowing mass assignment of tenant_id, owner_id, or arbitrary roles).
    """

    def __init__(self, db_uri: str | None = None, keepalive_conn: sqlite3.Connection | None = None):
        if db_uri is None or keepalive_conn is None:
            self.db_uri, self._keepalive_conn = create_isolated_db()
        else:
            self.db_uri = db_uri
            self._keepalive_conn = keepalive_conn
        self.base_dir = PUBLIC_FILES_DIR
        self.session_tenant_id: str = ""
        self.session_user_id: str = ""

    def set_session(self, tenant_id: str, user_id: str) -> None:
        self.session_tenant_id = tenant_id
        self.session_user_id = user_id

    def reset_db(self) -> None:
        conn = sqlite3.connect(self.db_uri, uri=True)
        try:
            with conn:
                conn.execute("UPDATE documents SET content = 'Tenant 1 Private Data', tenant_id = 'tenant_1', owner_id = 'usr_a', title = 'Doc 1' WHERE id = 'doc_1';")
                conn.execute("UPDATE documents SET content = 'Tenant 2 Private Data', tenant_id = 'tenant_2', owner_id = 'usr_b', title = 'Doc 2' WHERE id = 'doc_2';")
                conn.execute("DELETE FROM documents WHERE id NOT IN ('doc_1', 'doc_2');")
        finally:
            conn.close()

    def update_document(self, doc_id: str, new_content: str) -> Tuple[int, dict]:
        """FLAW: Insecure query ignoring tenant and owner boundaries, and ignoring rowcount."""
        conn = sqlite3.connect(self.db_uri, uri=True)
        try:
            cur = conn.execute(
                "UPDATE documents SET content = ? WHERE id = ?;",
                (new_content, doc_id),
            )
            conn.commit()
            return (200, {"status": "updated", "rowcount": cur.rowcount})
        finally:
            conn.close()

    def read_file(self, filename: str) -> str:
        """FLAW: Direct file read using base_dir / filename without canonicalization, device filtering, or handle bounds."""
        target = self.base_dir / filename
        with open(target, "r", encoding="utf-8") as f:
            return f.read()

    def update_document_fields(self, doc_id: str, data: Dict[str, Any]) -> Tuple[int, dict]:
        """FLAW: Direct dictionary assignment accepting any key (allowing mass assignment)."""
        conn = sqlite3.connect(self.db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM documents WHERE id = ?;", (doc_id,)
            ).fetchone()
            if not row:
                return (404, {"error": "not found"})

            for key, value in data.items():
                if key == "id":
                    continue
                val_to_store = value if not isinstance(value, (list, dict)) else json.dumps(value)
                try:
                    conn.execute(
                        f"UPDATE documents SET {key} = ? WHERE id = ?;",
                        (val_to_store, doc_id),
                    )
                except sqlite3.OperationalError:
                    pass
            conn.commit()
            return (200, {"status": "fields updated"})
        finally:
            conn.close()

    def get_document_content(self, doc_id: str) -> str | None:
        conn = sqlite3.connect(self.db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT content FROM documents WHERE id = ?;", (doc_id,)
            ).fetchone()
            return row["content"] if row else None
        finally:
            conn.close()

    def get_document_field(self, doc_id: str, field: str) -> Any:
        conn = sqlite3.connect(self.db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM documents WHERE id = ?;", (doc_id,)
            ).fetchone()
            if row is None:
                return None
            return row[field] if field in row.keys() else None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Hardened Implementation
# ---------------------------------------------------------------------------

class HardenedDocumentService:
    """
    Production-grade service enforcing:
      - Compound SQL mutation: UPDATE documents SET content = ? WHERE id = ? AND tenant_id = ? AND owner_id = ?;
      - Verifies cursor.rowcount == 1. If rowcount == 0, rolls back and returns HTTP 404/403.
      - Handle-Based Path Confinement (TOCTOU Defense):
        * Reject any filename containing ':' immediately (blocks NTFS Alternate Data Streams).
        * Strip trailing dots ('.') and whitespace before path evaluation.
        * Reject Windows reserved device names: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 (case-insensitive check against filename stem).
        * Resolve target canonically and strictly enforce target.resolve().is_relative_to(base_dir.resolve()) and target != base_dir.
        * Open file descriptor via os.open(), query canonical device volume path from handle (GetFinalPathNameByHandleW on Windows),
          strip '\\?\\' prefixes, and verify handle containment before reading.
      - Strict schema allowlist: only permits updating 'title' and 'content' as strings; drops or rejects modifications to tenant_id, owner_id, or id.
    """

    ALLOWED_UPDATE_FIELDS = {
        "title": str,
        "content": str,
    }

    def __init__(self, db_uri: str | None = None, keepalive_conn: sqlite3.Connection | None = None):
        if db_uri is None or keepalive_conn is None:
            self.db_uri, self._keepalive_conn = create_isolated_db()
        else:
            self.db_uri = db_uri
            self._keepalive_conn = keepalive_conn
        self.base_dir = PUBLIC_FILES_DIR
        self.session_tenant_id: str = ""
        self.session_user_id: str = ""

    def set_session(self, tenant_id: str, user_id: str) -> None:
        self.session_tenant_id = tenant_id
        self.session_user_id = user_id

    def reset_db(self) -> None:
        conn = sqlite3.connect(self.db_uri, uri=True)
        try:
            with conn:
                conn.execute("UPDATE documents SET content = 'Tenant 1 Private Data', tenant_id = 'tenant_1', owner_id = 'usr_a', title = 'Doc 1' WHERE id = 'doc_1';")
                conn.execute("UPDATE documents SET content = 'Tenant 2 Private Data', tenant_id = 'tenant_2', owner_id = 'usr_b', title = 'Doc 2' WHERE id = 'doc_2';")
                conn.execute("DELETE FROM documents WHERE id NOT IN ('doc_1', 'doc_2');")
        finally:
            conn.close()

    def update_document(self, doc_id: str, new_content: str) -> Tuple[int, dict]:
        """Compound SQL mutation with rowcount verification."""
        conn = sqlite3.connect(self.db_uri, uri=True)
        try:
            cur = conn.execute(
                "UPDATE documents SET content = ? WHERE id = ? AND tenant_id = ? AND owner_id = ?;",
                (new_content, doc_id, self.session_tenant_id, self.session_user_id),
            )
            if cur.rowcount == 0:
                conn.rollback()
                return (404, {"error": "not found or access denied"})
            conn.commit()
            return (200, {"status": "updated", "rowcount": cur.rowcount})
        finally:
            conn.close()

    def read_file(self, filename: str) -> str:
        if "\x00" in filename:
            raise ValueError("Null bytes in path prohibited")

        # 1. Reject any filename containing ':' immediately (blocks NTFS ADS)
        if ":" in filename:
            raise ValueError("Colons and NTFS alternate data streams prohibited in filename")

        # 2. Strip trailing dots and whitespace from each component
        cleaned_parts = []
        for part in pathlib.PurePosixPath(filename).parts:
            stripped = part.rstrip(". ")
            if not stripped:
                continue
            cleaned_parts.append(stripped)
        clean_name = os.sep.join(cleaned_parts) if cleaned_parts else filename

        # 3. Reject Windows reserved device names (case-insensitive check against filename stem)
        stem = pathlib.PurePath(clean_name).stem if cleaned_parts else filename
        if _WINDOWS_RESERVED.match(stem):
            raise ValueError(f"Windows reserved device name rejected: {stem}")

        # 4. Resolve target canonically and strictly enforce containment
        base = self.base_dir.resolve()
        raw_path = self.base_dir / clean_name
        canonical_target = raw_path.resolve()

        if not canonical_target.is_relative_to(base) or canonical_target == base:
            raise PermissionError(f"Access denied: path escapes base directory {base}")

        if not canonical_target.is_file():
            raise FileNotFoundError(f"File not found: {filename}")

        # 5. Enforce Handle-Based Path Confinement (TOCTOU Defense)
        fd = os.open(str(canonical_target), os.O_RDONLY)
        try:
            if os.name == "nt":
                import msvcrt
                handle = msvcrt.get_osfhandle(fd)
                buf = ctypes.create_unicode_buffer(1024)
                res = ctypes.windll.kernel32.GetFinalPathNameByHandleW(handle, buf, 1024, 0)
                if res == 0:
                    raise PermissionError("Failed to resolve final path from file handle")
                canonical_str = buf.value.removeprefix("\\\\?\\")
                canonical_path = pathlib.Path(canonical_str).resolve()
            else:
                canonical_path = pathlib.Path(os.path.realpath(f"/proc/self/fd/{fd}")).resolve()

            if not canonical_path.is_relative_to(base) or canonical_path == base:
                raise PermissionError(f"Handle boundary escape: {canonical_path} not within {base}")

            with os.fdopen(fd, "r", encoding="utf-8") as f:
                content = f.read()
                fd = None  # fdopen transfers ownership
                return content
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def update_document_fields(self, doc_id: str, data: Dict[str, Any]) -> Tuple[int, dict]:
        """Strict schema allowlist: only permits updating title and content as strings."""
        sanitized = {}
        for key, expected_type in self.ALLOWED_UPDATE_FIELDS.items():
            if key in data and isinstance(data[key], expected_type):
                sanitized[key] = data[key]

        if not sanitized:
            return (400, {"error": "no valid fields to update"})

        set_clause = ", ".join(f"{k} = ?" for k in sanitized)
        values = list(sanitized.values()) + [
            doc_id, self.session_tenant_id, self.session_user_id
        ]

        conn = sqlite3.connect(self.db_uri, uri=True)
        try:
            cur = conn.execute(
                f"UPDATE documents SET {set_clause} WHERE id = ? AND tenant_id = ? AND owner_id = ?;",
                values,
            )
            if cur.rowcount == 0:
                conn.rollback()
                return (404, {"error": "not found or access denied"})
            conn.commit()
            return (200, {"status": "fields updated"})
        finally:
            conn.close()

    def get_document_content(self, doc_id: str) -> str | None:
        conn = sqlite3.connect(self.db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT content FROM documents WHERE id = ?;", (doc_id,)
            ).fetchone()
            return row["content"] if row else None
        finally:
            conn.close()

    def get_document_field(self, doc_id: str, field: str) -> Any:
        conn = sqlite3.connect(self.db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM documents WHERE id = ?;", (doc_id,)
            ).fetchone()
            if row is None:
                return None
            return row[field] if field in row.keys() else None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Loopback Server & Request Handler
# ---------------------------------------------------------------------------

class AuthRequestHandler(BaseHTTPRequestHandler):
    """
    Lightweight HTTP request handler exposing document and file endpoints
    over live TCP sockets. Identity context is strictly bound from service session.
    """

    def log_message(self, format, *args):  # noqa: A002
        pass

    @property
    def service(self):
        return self.server.service

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self) -> None:
        path_only = self.path.split("?", 1)[0]
        parts = [p for p in path_only.strip("/").split("/") if p]
        if len(parts) == 2 and parts[0] == "documents":
            doc_id = parts[1]
            try:
                cl = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(cl) if cl > 0 else b""
                body = json.loads(raw_body) if raw_body else {}
            except (json.JSONDecodeError, ValueError):
                self._send_json(400, {"error": "invalid JSON"})
                return

            if not isinstance(body, dict):
                self._send_json(400, {"error": "body must be a JSON object"})
                return

            if set(body.keys()) == {"content"} and isinstance(body["content"], str):
                status, res = self.service.update_document(doc_id, body["content"])
            else:
                status, res = self.service.update_document_fields(doc_id, body)
            self._send_json(status, res)
            return

        self._send_json(404, {"error": "not found"})

    def do_GET(self) -> None:
        path_only = self.path.split("?", 1)[0]
        parts = [p for p in path_only.strip("/").split("/") if p]

        if len(parts) == 2 and parts[0] == "documents":
            doc_id = parts[1]
            content = self.service.get_document_content(doc_id)
            if content is not None:
                self._send_json(200, {"id": doc_id, "content": content})
            else:
                self._send_json(404, {"error": "document not found"})
            return

        if len(parts) >= 2 and parts[0] == "files":
            filename = "/".join(parts[1:])
            try:
                content = self.service.read_file(filename)
                self._send_json(200, {"content": content})
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
            except PermissionError as e:
                self._send_json(403, {"error": str(e)})
            except FileNotFoundError as e:
                self._send_json(404, {"error": str(e)})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        self._send_json(404, {"error": "not found"})


def create_auth_server(service, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """
    Instantiate a ThreadingHTTPServer bound to an ephemeral kernel-allocated port (port=0).
    Attaches the provided document service to the server instance.
    """
    server = ThreadingHTTPServer((host, port), AuthRequestHandler)
    server.service = service
    return server
