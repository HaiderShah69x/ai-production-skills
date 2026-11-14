"""
fixtures/auth_fixtures.py — Baseline vulnerable and hardened service implementations.

Exposes three critical boundary flaws:
  1. Broken Object-Level Authorization (IDOR)
  2. Naive Path Traversal
  3. Mass-Assignment / Privilege Escalation
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
    Intentionally vulnerable service exhibiting IDOR, Traversal, and Mass-Assignment.
    """
    def __init__(self):
        self.documents: Dict[int, Dict[str, Any]] = {
            101: {"id": 101, "owner_id": "alice", "title": "Alice's Secret Diary", "content": "Confidential Alice"},
            102: {"id": 102, "owner_id": "bob", "title": "Bob's Work Plan", "content": "Internal Bob Project"},
        }
        self.users: Dict[str, Dict[str, Any]] = {
            "alice": {"user_id": "alice", "name": "Alice Cooper", "is_admin": False},
            "bob": {"user_id": "bob", "name": "Bob Vance", "is_admin": False},
        }
        self.base_dir = PUBLIC_FILES_DIR

    # 1. IDOR Defect: Looks up document solely by primary key doc_id
    def get_document(self, doc_id: int, user_id: str) -> Optional[Dict[str, Any]]:
        doc = self.documents.get(doc_id)
        # FLAW: Returns document directly without checking doc["owner_id"] == user_id
        return doc

    # 2. Path Traversal Defect: Naive string join without boundary assertion
    def read_file(self, filename: str) -> str:
        # FLAW: os.path.join allows "../" to escape self.base_dir
        target_path = os.path.join(self.base_dir, filename)
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()

    # 3. Mass-Assignment Defect: Raw dict update
    def update_profile(self, user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        user = self.users.get(user_id)
        if not user:
            raise KeyError("User not found")
        # FLAW: Blindly applies raw dictionary, letting caller overwrite "is_admin"
        user.update(data)
        return user


class HardenedAuthService:
    """
    Production-grade service strictly enforcing object scoping, canonical path containment,
    and schema allowlists.
    """
    ALLOWED_PROFILE_FIELDS = {"name", "email", "bio"}

    def __init__(self):
        self.documents: Dict[int, Dict[str, Any]] = {
            101: {"id": 101, "owner_id": "alice", "title": "Alice's Secret Diary", "content": "Confidential Alice"},
            102: {"id": 102, "owner_id": "bob", "title": "Bob's Work Plan", "content": "Internal Bob Project"},
        }
        self.users: Dict[str, Dict[str, Any]] = {
            "alice": {"user_id": "alice", "name": "Alice Cooper", "is_admin": False},
            "bob": {"user_id": "bob", "name": "Bob Vance", "is_admin": False},
        }
        self.base_dir = PUBLIC_FILES_DIR

    # 1. Invariant 1: Mandatory Object-Level Authorization
    def get_document(self, doc_id: int, user_id: str) -> Optional[Dict[str, Any]]:
        doc = self.documents.get(doc_id)
        if not doc or doc.get("owner_id") != user_id:
            # Rejects unauthorized access without leaking metadata
            return None
        return doc

    # 2. Invariant 2: Strict Canonical Path Containment
    def read_file(self, filename: str) -> str:
        base = self.base_dir.resolve()
        target = (base / filename).resolve()

        # Reject null bytes and boundary escapes
        if "\x00" in filename:
            raise ValueError("Null bytes in path prohibited")
        if not target.is_relative_to(base):
            raise PermissionError(f"Access denied: path escapes root boundary {base}")
        if not target.is_file():
            raise FileNotFoundError("File not found")

        return target.read_text(encoding="utf-8")

    # 3. Invariant 3: Explicit Schema Allowlist
    def update_profile(self, user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        user = self.users.get(user_id)
        if not user:
            raise KeyError("User not found")

        # Extract only allowed fields; drop or reject sensitive privilege attributes
        for key, val in data.items():
            if key in self.ALLOWED_PROFILE_FIELDS:
                user[key] = val

        return user
