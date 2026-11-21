"""
tests/test_auth_adversarial.py — Adversarial test suite for Skill 03.

Verifies physical SQLite state and OS-level boundary enforcement via
dispatch_request wire format. Every negative test asserts both HTTP
status AND database state integrity. Services are initialized using
create_isolated_db().

Tests:
  1. test_cross_tenant_idor_mutation_blocked
  2. test_sql_mutation_rowcount_integrity
  3. test_windows_device_names_blocked (parametrized CON, NUL.txt, aux.dat)
  4. test_ntfs_alternate_data_stream_blocked
  5. test_mass_assignment_type_and_tenant_tampering
  6. test_positive_authorized_update
"""

import json
import os
import sys
import pathlib
import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.auth_fixtures import (
    create_isolated_db,
    VulnerableDocumentService,
    HardenedDocumentService,
    dispatch_request,
)


def get_service(db_uri: str | None = None, conn=None):
    """Factory creating service instances with isolated SQLite databases."""
    if db_uri is None or conn is None:
        db_uri, conn = create_isolated_db()
    impl = os.environ.get("AUTH_SERVICE_IMPL", "hardened")
    if impl == "vulnerable":
        svc = VulnerableDocumentService(db_uri=db_uri, keepalive_conn=conn)
    else:
        svc = HardenedDocumentService(db_uri=db_uri, keepalive_conn=conn)
    svc.set_session("tenant_1", "usr_a")
    return svc


# ---------------------------------------------------------------------------
# Test 1: Cross-Tenant IDOR Mutation Blocked
# ---------------------------------------------------------------------------
def test_cross_tenant_idor_mutation_blocked():
    """
    Authenticate as User A (Tenant 1). Issue PUT /documents/doc_2 with
    {"content": "tampered"}. Assert status 403/404 AND doc_2 in SQLite
    remains exactly "Tenant 2 Private Data".
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    status, body = dispatch_request(
        svc, "PUT", "/documents/doc_2", {},
        json.dumps({"content": "tampered"}).encode(),
    )
    assert status in (403, 404), (
        f"IDOR DEFECT! Cross-tenant mutation returned {status}: {body}"
    )
    actual = svc.get_document_content("doc_2")
    assert actual == "Tenant 2 Private Data", (
        f"IDOR DEFECT! doc_2 content mutated to: {actual!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: SQL Mutation Rowcount Integrity
# ---------------------------------------------------------------------------
def test_sql_mutation_rowcount_integrity():
    """
    Issue an update against an unowned/non-existent document ID. Assert the
    service detects cursor.rowcount == 0 and denies the mutation with 403/404.
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    status, body = dispatch_request(
        svc, "PUT", "/documents/doc_nonexistent", {},
        json.dumps({"content": "ghost"}).encode(),
    )
    assert status in (403, 404), (
        f"ROWCOUNT DEFECT! Update to non-existent doc returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 3: Windows Device Names Blocked
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("device_name", ["CON", "NUL.txt", "aux.dat"])
def test_windows_device_names_blocked(device_name):
    """
    Request files named CON, NUL.txt, or aux.dat. Assert rejection without
    hanging or blocking the process.
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    status, body = dispatch_request(
        svc, "GET", f"/files/{device_name}", {}, b"",
    )
    assert status in (400, 403), (
        f"DEVICE NAME DEFECT! Request for {device_name!r} returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 4: NTFS Alternate Data Stream Blocked
# ---------------------------------------------------------------------------
def test_ntfs_alternate_data_stream_blocked():
    """
    Request file.txt:stream. Assert immediate rejection (HTTP 400 or 403).
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    status, body = dispatch_request(
        svc, "GET", "/files/file.txt:stream", {}, b"",
    )
    assert status in (400, 403), (
        f"ADS DEFECT! NTFS alternate stream request returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 5: Mass-Assignment of Protected Fields Rejected
# ---------------------------------------------------------------------------
def test_mass_assignment_type_and_tenant_tampering():
    """
    Issue PUT /documents/doc_1 with payload containing content (valid),
    tenant_id (protected), and role (non-schema list type). Assert content
    updates while tenant_id remains "tenant_1" in SQLite.
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    payload = {
        "content": "updated",
        "tenant_id": "tenant_2",
        "role": ["admin"],
    }
    status, body = dispatch_request(
        svc, "PUT", "/documents/doc_1", {},
        json.dumps(payload).encode(),
    )
    actual_content = svc.get_document_content("doc_1")
    actual_tenant = svc.get_document_field("doc_1", "tenant_id")

    assert actual_content == "updated", (
        f"UPDATE FAILED: content expected 'updated', got {actual_content!r}"
    )
    assert actual_tenant == "tenant_1", (
        f"MASS ASSIGNMENT DEFECT! tenant_id changed to {actual_tenant!r}"
    )


# ---------------------------------------------------------------------------
# Test 6: Positive Authorized Update
# ---------------------------------------------------------------------------
def test_positive_authorized_update():
    """
    User A (Tenant 1) updates doc_1 with valid content payload. Assert
    HTTP 200 and database reflects the new content.
    """
    db_uri, conn = create_isolated_db()
    svc = get_service(db_uri=db_uri, conn=conn)

    new_content = "Authorized content update by usr_a"
    status, body = dispatch_request(
        svc, "PUT", "/documents/doc_1", {},
        json.dumps({"content": new_content}).encode(),
    )
    assert status == 200, (
        f"POSITIVE PARITY DEFECT! Authorized update returned {status}: {body}"
    )
    actual = svc.get_document_content("doc_1")
    assert actual == new_content, (
        f"POSITIVE PARITY DEFECT! Database content is {actual!r}, expected {new_content!r}"
    )
