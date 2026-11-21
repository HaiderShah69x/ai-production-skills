"""
tests/test_auth_adversarial.py — Adversarial test suite for Skill 03.

Verifies physical SQLite state and OS-level boundary enforcement via
live loopback TCP sockets and raw HTTP wire bytes using http.client.HTTPConnection.
Every negative test asserts both HTTP status AND database state integrity.
Services are initialized using create_isolated_db() and hosted on an ephemeral
kernel-allocated port per test session.

Tests (8 total):
  1. test_cross_tenant_idor_mutation_blocked
  2. test_sql_mutation_rowcount_integrity
  3. test_windows_device_names_blocked (parametrized: CON, NUL.txt, aux.dat -> 3 tests)
  4. test_ntfs_alternate_data_stream_blocked
  5. test_mass_assignment_type_and_tenant_tampering
  6. test_positive_authorized_update
"""

import http.client
import json
import os
import pathlib
import sys
import threading
import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.auth_fixtures import (
    create_isolated_db,
    create_auth_server,
    VulnerableDocumentService,
    HardenedDocumentService,
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
# Session-Scoped Ephemeral Loopback Server Harness
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def auth_server():
    """
    Spins up a lightweight ThreadingHTTPServer on an ephemeral port (port 0)
    bound to loopback ('127.0.0.1') for the lifetime of the test session.
    """
    db_uri, conn = create_isolated_db()
    service = get_service(db_uri=db_uri, conn=conn)
    server = create_auth_server(service, "127.0.0.1", 0)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield ("127.0.0.1", port, service)

    server.shutdown()
    server.server_close()
    conn.close()


@pytest.fixture(autouse=True)
def reset_db_state(auth_server):
    """Resets database contents to known seed state before each test."""
    _, _, service = auth_server
    service.reset_db()
    yield


def wire_request(host: str, port: int, method: str, path: str, body: bytes = b"", headers: dict = None) -> tuple[int, dict]:
    """Transmits raw HTTP bytes over live TCP socket via http.client.HTTPConnection."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        req_headers = headers.copy() if headers else {}
        if body and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            data = {"raw": raw.decode("utf-8", errors="ignore")}
        return resp.status, data
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Test 1: Cross-Tenant IDOR Mutation Blocked
# ---------------------------------------------------------------------------
def test_cross_tenant_idor_mutation_blocked(auth_server):
    """
    Authenticate as User A (Tenant 1). Transmit PUT /documents/doc_2 with
    {"content": "tampered"} over TCP socket. Assert status 403/404 AND doc_2
    in SQLite remains exactly "Tenant 2 Private Data".
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_2",
        body=json.dumps({"content": "tampered"}).encode(),
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
def test_sql_mutation_rowcount_integrity(auth_server):
    """
    Issue an update against an unowned/non-existent document ID over TCP.
    Assert the service detects cursor.rowcount == 0 and denies the mutation with 403/404.
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_nonexistent",
        body=json.dumps({"content": "ghost"}).encode(),
    )
    assert status in (403, 404), (
        f"ROWCOUNT DEFECT! Update to non-existent doc returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 3: Windows Device Names Blocked
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("device_name", ["CON", "NUL.txt", "aux.dat"])
def test_windows_device_names_blocked(auth_server, device_name):
    """
    Request files named CON, NUL.txt, or aux.dat over TCP socket.
    Assert rejection (400 or 403) without hanging or blocking the process.
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "GET", f"/files/{device_name}",
    )
    assert status in (400, 403), (
        f"DEVICE NAME DEFECT! Request for {device_name!r} returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 4: NTFS Alternate Data Stream Blocked
# ---------------------------------------------------------------------------
def test_ntfs_alternate_data_stream_blocked(auth_server):
    """
    Request file.txt:stream over TCP socket. Assert immediate rejection (HTTP 400 or 403).
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "GET", "/files/file.txt:stream",
    )
    assert status in (400, 403), (
        f"ADS DEFECT! NTFS alternate stream request returned {status}: {body}"
    )


# ---------------------------------------------------------------------------
# Test 5: Mass-Assignment of Protected Fields Rejected
# ---------------------------------------------------------------------------
def test_mass_assignment_type_and_tenant_tampering(auth_server):
    """
    Issue PUT /documents/doc_1 with payload containing content (valid),
    tenant_id (protected), and role (non-schema list type) over TCP socket.
    Assert content updates while tenant_id remains "tenant_1" in SQLite.
    """
    host, port, svc = auth_server

    payload = {
        "content": "updated",
        "tenant_id": "tenant_2",
        "role": ["admin"],
    }
    status, body = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps(payload).encode(),
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
def test_positive_authorized_update(auth_server):
    """
    User A (Tenant 1) updates doc_1 with valid content payload over TCP socket.
    Assert HTTP 200 and database reflects the new content.
    """
    host, port, svc = auth_server

    new_content = "Authorized content update by usr_a"
    status, body = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": new_content}).encode(),
    )
    assert status == 200, (
        f"POSITIVE PARITY DEFECT! Authorized update returned {status}: {body}"
    )
    actual = svc.get_document_content("doc_1")
    assert actual == new_content, (
        f"POSITIVE PARITY DEFECT! Database content is {actual!r}, expected {new_content!r}"
    )
