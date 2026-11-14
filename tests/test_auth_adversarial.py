"""
tests/test_auth_adversarial.py — Comprehensive adversarial test suite for Skill 03.

Enforces:
  1. Negative IDOR & Cross-Tenant compound scoping.
  2. Negative Path Traversal & Symlink / Junction dereferencing escapes.
  3. Negative Shallow & Deep/Nested Mass Assignment privilege escalation.
  4. Positive functional parity tests.
"""

import os
import subprocess
import sys
import pathlib
import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.auth_fixtures import VulnerableAuthService, HardenedAuthService, PUBLIC_FILES_DIR, FIXTURES_DIR


def get_service():
    impl = os.environ.get("AUTH_SERVICE_IMPL", "hardened")
    if impl == "vulnerable":
        return VulnerableAuthService()
    return HardenedAuthService()


# ---------------------------------------------------------------------------
# Test 1: Standard IDOR
# ---------------------------------------------------------------------------
def test_idor_unauthorized_access_rejected():
    """
    Negative Test 1 (IDOR):
    Alice (tenant_alpha) attempts to read Document 102 (Bob's document in tenant_beta).
    Must return None, leaking zero document data.
    """
    service = get_service()
    doc = service.get_document(doc_id=102, user_id="alice", tenant_id="tenant_alpha")
    assert doc is None, f"IDOR DEFECT! Alice accessed unowned document: {doc}"


# ---------------------------------------------------------------------------
# Test 2: Cross-Tenant Compound Scoping IDOR
# ---------------------------------------------------------------------------
def test_cross_tenant_idor_rejected():
    """
    Negative Test 2 (Cross-Tenant IDOR):
    User from tenant_alpha queries a document belonging to tenant_beta,
    passing a forged or matching user_id without valid tenant boundary.
    Must be strictly rejected.
    """
    service = get_service()
    # Attempting to read Document 102 under tenant_alpha scope
    doc = service.get_document(doc_id=102, user_id="bob", tenant_id="tenant_alpha")
    assert doc is None, f"CROSS-TENANT IDOR DEFECT! Cross-tenant access succeeded: {doc}"


# ---------------------------------------------------------------------------
# Test 3: Direct Path Traversal
# ---------------------------------------------------------------------------
def test_path_traversal_rejected():
    """
    Negative Test 3 (Direct Path Traversal):
    Attempts to read secret_keys.txt via '../secret_keys.txt'.
    Must raise PermissionError / ValueError before file open.
    """
    service = get_service()
    traversal_path = "../secret_keys.txt"

    with pytest.raises((PermissionError, ValueError)):
        content = service.read_file(traversal_path)
        assert "SUPER_SECRET" not in content, "Path traversal read secret data!"


# ---------------------------------------------------------------------------
# Test 4: Symlink / Junction Traversal Escape
# ---------------------------------------------------------------------------
def test_symlink_traversal_rejected():
    """
    Negative Test 4 (Symlink / Junction Escape):
    An attacker establishes a directory junction / symlink inside the public directory
    pointing to the parent secret directory ('ext_junction' -> FIXTURES_DIR).
    Querying 'ext_junction/secret_keys.txt' must be rejected via canonical resolution.
    """
    service = get_service()
    junction_dir = PUBLIC_FILES_DIR / "ext_junction"

    # Create junction if on Windows, symlink on Unix
    created = False
    try:
        if os.name == "nt":
            cmd = f'cmd /c "mklink /J \"{junction_dir}\" \"{FIXTURES_DIR}\""'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            created = junction_dir.exists()
        else:
            junction_dir.symlink_to(FIXTURES_DIR, target_is_directory=True)
            created = junction_dir.exists()
    except Exception:
        created = False

    try:
        if not created:
            pytest.skip("Unable to create filesystem link/junction in this environment")

        target_file = "ext_junction/secret_keys.txt"

        with pytest.raises((PermissionError, ValueError)):
            content = service.read_file(target_file)
            assert "SUPER_SECRET" not in content, "Symlink escape read secret data!"
    finally:
        if created and junction_dir.exists():
            if os.name == "nt":
                subprocess.run(f'cmd /c "rmdir \"{junction_dir}\""', shell=True)
            else:
                junction_dir.unlink()


# ---------------------------------------------------------------------------
# Test 5: Shallow Mass Assignment
# ---------------------------------------------------------------------------
def test_mass_assignment_rejected():
    """
    Negative Test 5 (Shallow Mass Assignment):
    Alice attempts to escalate privileges via top-level 'is_admin': True.
    'is_admin' must remain False.
    """
    service = get_service()
    payload = {"name": "Alice Superuser", "is_admin": True}
    updated = service.update_profile("alice", payload)

    assert updated["name"] == "Alice Superuser", "Allowed field 'name' failed to update"
    assert updated["is_admin"] is False, "MASS ASSIGNMENT DEFECT! Privilege escalated via top-level key"


# ---------------------------------------------------------------------------
# Test 6: Nested / Deep Mass Assignment
# ---------------------------------------------------------------------------
def test_nested_mass_assignment_rejected():
    """
    Negative Test 6 (Deep / Nested Mass Assignment):
    Alice attempts to inject 'is_admin': True or 'role': 'admin' inside nested 'metadata'.
    Must strip unauthorized nested keys while preserving valid ones ('theme').
    """
    service = get_service()
    payload = {
        "metadata": {
            "theme": "dark",
            "is_admin": True,
            "role": "superadmin",
        }
    }
    updated = service.update_profile("alice", payload)

    assert updated["metadata"]["theme"] == "dark", "Allowed nested field 'theme' failed to update"
    assert "is_admin" not in updated["metadata"] and updated.get("is_admin") is not True, (
        "NESTED MASS ASSIGNMENT DEFECT! Injected is_admin into metadata"
    )
    assert "role" not in updated["metadata"], (
        "NESTED MASS ASSIGNMENT DEFECT! Injected role into metadata"
    )


# ---------------------------------------------------------------------------
# Test 7: Positive Parity Test
# ---------------------------------------------------------------------------
def test_authorized_access_succeeds():
    """
    Positive Parity Test:
    Legitimate owner reads their own document and standard public report.
    """
    service = get_service()
    doc = service.get_document(doc_id=101, user_id="alice", tenant_id="tenant_alpha")
    assert doc is not None, "Legitimate owner failed to read own document"
    assert doc["id"] == 101

    report = service.read_file("report.txt")
    assert "Public Quarterly Report Data" in report
