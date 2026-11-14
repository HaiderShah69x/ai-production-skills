"""
tests/test_auth_adversarial.py — Adversarial test suite for untrusted boundaries and auth.

Adheres strictly to skills/untrusted-boundaries-and-auth/SKILL.md:
  - Negative tests first: IDOR, path traversal, mass-assignment.
  - Positive parity test: authorized requests succeed.
  - Zero swallowed exceptions and strict literal assertions.
"""

import os
import sys
import pathlib
import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.auth_fixtures import VulnerableAuthService, HardenedAuthService


def get_service():
    impl = os.environ.get("AUTH_SERVICE_IMPL", "hardened")
    if impl == "vulnerable":
        return VulnerableAuthService()
    return HardenedAuthService()


def test_idor_unauthorized_access_rejected():
    """
    Negative Test 1 (IDOR):
    Alice attempts to read Document 102 (owned by Bob).
    Must return None (rejection), leaking zero data.
    """
    service = get_service()

    # Document 102 belongs to 'bob'
    doc = service.get_document(doc_id=102, user_id="alice")

    assert doc is None, (
        f"IDOR VULNERABILITY! Alice accessed Bob's document: {doc}"
    )


def test_path_traversal_rejected():
    """
    Negative Test 2 (Path Traversal):
    Attempts to read secret_keys.txt located outside the public directory
    using relative escape ('../secret_keys.txt').
    Must raise PermissionError / ValueError, rejecting traversal before read.
    """
    service = get_service()

    # Attempt to read parent secret file
    traversal_path = "../secret_keys.txt"

    with pytest.raises((PermissionError, ValueError)) as excinfo:
        content = service.read_file(traversal_path)
        # If no exception raised, assert content did not leak secret
        assert "SUPER_SECRET" not in content, "Path traversal succeeded in reading secret keys!"


def test_mass_assignment_rejected():
    """
    Negative Test 3 (Mass Assignment):
    Alice attempts to promote herself to admin by submitting 'is_admin': True.
    Must reject or drop 'is_admin', leaving Alice's role strictly False.
    """
    service = get_service()

    payload = {"name": "Alice Superuser", "is_admin": True}
    updated_user = service.update_profile("alice", payload)

    assert updated_user["name"] == "Alice Superuser", "Allowed field 'name' failed to update"
    assert updated_user["is_admin"] is False, (
        "MASS ASSIGNMENT VULNERABILITY! Alice successfully escalated privileges to is_admin=True"
    )


def test_authorized_access_succeeds():
    """
    Positive Parity Test:
    Alice accesses her own Document 101 and reads a legitimate public report.
    Verifies the system does not fail-closed / deny-all for legitimate requests.
    """
    service = get_service()

    # Alice reads her own document
    doc = service.get_document(doc_id=101, user_id="alice")
    assert doc is not None, "Legitimate owner Alice was unable to read her document"
    assert doc["id"] == 101
    assert doc["owner_id"] == "alice"

    # Alice reads legitimate file
    report = service.read_file("report.txt")
    assert "Public Quarterly Report Data" in report
