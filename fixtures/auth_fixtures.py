"""
fixtures/auth_fixtures.py — SQLite-backed vulnerable and hardened document services.

Replaces in-memory mock abstractions with real database state, wire-format
dispatch, and OS-level path enforcement using isolated in-memory SQLite URIs.

Production blind spots covered:
  1. Cross-tenant IDOR via un-scoped SQL mutations.
  2. Path traversal, symlink/junction escapes, NTFS ADS, Windows device names.
  3. Mass-assignment of tenant_id, owner_id, role, or arbitrary keys.
"""

import json
import os
import pathlib
import re
import sqlite3
import uuid
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
      - Direct file read using base_dir / filename without canonicalization or device name filtering.
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
        """FLAW: Direct file read using base_dir / filename without canonicalization or device name filtering."""
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
      - Filesystem canonical bounds:
        * Reject any filename containing ':' immediately (blocks NTFS Alternate Data Streams).
        * Reject Windows reserved device names: CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 (case-insensitive check against filename stem).
        * Strip trailing dots ('.') and whitespace before path evaluation.
        * Resolve target canonically and strictly enforce target.resolve().is_relative_to(base_dir.resolve()) and target != base_dir.
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
            raise FileNotFoundError("File not found")

        return canonical_target.read_text(encoding="utf-8")

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
# Wire Dispatcher
# ---------------------------------------------------------------------------

def dispatch_request(
    service: VulnerableDocumentService | HardenedDocumentService,
    method: str,
    path: str,
    headers: dict,
    raw_body: bytes,
) -> Tuple[int, dict]:
    """
    Minimal wire-format dispatcher.

    Identity context (tenant_id, user_id) MUST be bound strictly from
    verified session context in the service, never read from client query params,
    unverified headers, or JSON body.
    """
    parts = [p for p in path.strip("/").split("/") if p]

    # PUT /documents/<doc_id>
    if method == "PUT" and len(parts) == 2 and parts[0] == "documents":
        doc_id = parts[1]
        try:
            body = json.loads(raw_body) if raw_body else {}
        except (json.JSONDecodeError, ValueError):
            return (400, {"error": "invalid JSON"})

        if not isinstance(body, dict):
            return (400, {"error": "body must be a JSON object"})

        # If body has only "content", use the simpler update_document path
        if set(body.keys()) == {"content"} and isinstance(body["content"], str):
            return service.update_document(doc_id, body["content"])

        # Otherwise use the multi-field update path
        return service.update_document_fields(doc_id, body)

    # GET /files/<filename>
    if method == "GET" and len(parts) >= 2 and parts[0] == "files":
        filename = "/".join(parts[1:])
        try:
            content = service.read_file(filename)
            return (200, {"content": content})
        except ValueError as e:
            return (400, {"error": str(e)})
        except PermissionError as e:
            return (403, {"error": str(e)})
        except FileNotFoundError as e:
            return (404, {"error": str(e)})

    return (404, {"error": "not found"})
