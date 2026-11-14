"""
fixtures/auth_fixtures.py — Baseline vulnerable and hardened service implementations.

Exposes three critical production blind spots:
  1. Broken Object-Level Authorization (IDOR) with Multi-Tenant Scoping.
  2. Path Traversal & Symlink / Junction Boundary Escapes.
  3. Shallow and Nested / Deep Mass-Assignment Privilege Escalation.
"""

import os
import pathlib
from typing import Dict, Any, Optional

FIXTURES_DIR = pathlib.Path(__file__).parent.resolve()
PUBLIC_FILES_DIR = (FIXTURES_DIR / "public_files").resolve()
PUBLIC_FILES_DIR.mkdir(exist_ok=True)

# Write a benign public file and a secret external file
(PUBLIC_FILES_DIR / "report.txt").write_text("Public Quarterly Report Data", encoding="utf-8")
SECRET_FILE = (FIXTURES_DIR / "secret_keys.txt").resolve()
SECRET_FILE.write_text("SUPER_SECRET_API_KEY_9999", encoding="utf-8")


class VulnerableAuthService:
    """
    Intentionally vulnerable service exhibiting:
      - Single-key / cross-tenant IDOR
      - Naive string path concatenation allowing symlink and ../ escapes
      - Unchecked nested mass-assignment
    """
    def __init__(self):
        # Multi-tenant document store
        self.documents: Dict[int, Dict[str, Any]] = {
            101: {
                "id": 101,
                "tenant_id": "tenant_alpha",
                "owner_id": "alice",
                "title": "Alpha Confidential Roadmap",
                "content": "Secret Alpha Data",
            },
            102: {
                "id": 102,
                "tenant_id": "tenant_beta",
                "owner_id": "bob",
                "title": "Beta Internal Budget",
                "content": "Secret Beta Budget",
            },
        }
        self.users: Dict[str, Dict[str, Any]] = {
            "alice": {
                "user_id": "alice",
                "tenant_id": "tenant_alpha",
                "name": "Alice Cooper",
                "is_admin": False,
                "metadata": {"theme": "light", "notifications": True},
            },
            "bob": {
                "user_id": "bob",
                "tenant_id": "tenant_beta",
                "name": "Bob Vance",
                "is_admin": False,
                "metadata": {"theme": "dark", "notifications": False},
            },
        }
        self.base_dir = PUBLIC_FILES_DIR

    # 1. IDOR Defect: Retrieves document solely by doc_id (or ignores tenant_id scoping)
    def get_document(self, doc_id: int, user_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        doc = self.documents.get(doc_id)
        # FLAW: Returns document without verifying compound tenant_id AND owner_id
        return doc

    # 2. Path Traversal & Symlink Defect: Naive string join without canonical resolution
    def read_file(self, filename: str) -> str:
        # FLAW: os.path.join followed by open() follows symlinks/junctions outside base_dir
        target_path = os.path.join(self.base_dir, filename)
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()

    # 3. Mass-Assignment Defect: Naive recursive update merging raw nested dicts
    def update_profile(self, user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        user = self.users.get(user_id)
        if not user:
            raise KeyError("User not found")

        # FLAW: Merges raw dictionaries including nested structures
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(user.get(k), dict):
                user[k].update(v)
            else:
                user[k] = v
        return user


class HardenedAuthService:
    """
    Production-grade service strictly enforcing:
      - Compound object-level authorization (tenant_id AND user_id scoping)
      - Canonical path containment asserting is_relative_to(base) to defeat ../ and symlinks
      - Recursive schema allowlisting against nested mass assignment
    """
    # Strict recursive field and type allowlist
    ALLOWED_SCHEMA = {
        "name": str,
        "email": str,
        "metadata": {
            "theme": str,
            "notifications": bool,
        },
    }

    def __init__(self):
        self.documents: Dict[int, Dict[str, Any]] = {
            101: {
                "id": 101,
                "tenant_id": "tenant_alpha",
                "owner_id": "alice",
                "title": "Alpha Confidential Roadmap",
                "content": "Secret Alpha Data",
            },
            102: {
                "id": 102,
                "tenant_id": "tenant_beta",
                "owner_id": "bob",
                "title": "Beta Internal Budget",
                "content": "Secret Beta Budget",
            },
        }
        self.users: Dict[str, Dict[str, Any]] = {
            "alice": {
                "user_id": "alice",
                "tenant_id": "tenant_alpha",
                "name": "Alice Cooper",
                "is_admin": False,
                "metadata": {"theme": "light", "notifications": True},
            },
            "bob": {
                "user_id": "bob",
                "tenant_id": "tenant_beta",
                "name": "Bob Vance",
                "is_admin": False,
                "metadata": {"theme": "dark", "notifications": False},
            },
        }
        self.base_dir = PUBLIC_FILES_DIR

    # 1. Invariant 1: Mandatory Compound Tenant & Object-Level Authorization
    def get_document(self, doc_id: int, user_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
        doc = self.documents.get(doc_id)
        # Compound query: MUST match both tenant_id AND owner_id
        if not doc:
            return None
        if doc.get("tenant_id") != tenant_id or doc.get("owner_id") != user_id:
            return None
        return doc

    # 2. Invariant 2: Strict Canonical Path & Symlink Dereference Containment
    def read_file(self, filename: str) -> str:
        base = self.base_dir.resolve()
        raw_path = self.base_dir / filename

        if "\x00" in filename:
            raise ValueError("Null bytes in path prohibited")

        # Invariant 2: Block NTFS Alternate Data Streams and colons
        if ":" in filename:
            raise ValueError("Colons and NTFS alternate data streams prohibited in filename")

        # Fully resolve symlinks, junctions, and relative parent references
        canonical_target = raw_path.resolve()

        # Strict containment check
        if not canonical_target.is_relative_to(base):
            raise PermissionError(f"Access denied: path escapes base directory {base}")

        if not canonical_target.is_file():
            raise FileNotFoundError("File not found")

        return canonical_target.read_text(encoding="utf-8")

    # 3. Invariant 3: Recursive Nested-Schema Whitelist Filter
    def _filter_schema(self, incoming: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for key, expected_spec in schema.items():
            if key not in incoming:
                continue
            val = incoming[key]
            if isinstance(expected_spec, dict):
                if isinstance(val, dict):
                    nested_clean = self._filter_schema(val, expected_spec)
                    sanitized[key] = nested_clean
            elif isinstance(expected_spec, type):
                if isinstance(val, expected_spec):
                    sanitized[key] = val
        return sanitized

    def update_profile(self, user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        user = self.users.get(user_id)
        if not user:
            raise KeyError("User not found")

        clean_data = self._filter_schema(data, self.ALLOWED_SCHEMA)

        for k, v in clean_data.items():
            if isinstance(v, dict) and isinstance(user.get(k), dict):
                user[k].update(v)
            else:
                user[k] = v

        return user
