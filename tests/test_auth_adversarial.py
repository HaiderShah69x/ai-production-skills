"""
tests/test_auth_adversarial.py — Adversarial test suite for Skill 03.

Verifies physical SQLite state and OS-level boundary enforcement via
live loopback TCP sockets and raw HTTP wire bytes using http.client.HTTPConnection.
Every negative test asserts both HTTP status AND database state integrity.
Services are initialized using create_isolated_db() and hosted on an ephemeral
kernel-allocated port per test session. Identity context is strictly bound to
cryptographically signed HMAC-SHA256 bearer tokens.

Tests (13 total):
  1. test_cross_tenant_idor_mutation_blocked
  2. test_sql_mutation_rowcount_integrity
  3. test_windows_device_names_blocked (parametrized: CON, NUL.txt, aux.dat -> 3 tests)
  4. test_ntfs_alternate_data_stream_blocked
  5. test_mass_assignment_type_and_tenant_tampering
  6. test_positive_authorized_update
  7. test_http_parameter_pollution_rejection
  8. test_header_identity_spoofing_ignored
  9. test_wire_tampered_payload_rejected_401
  10. test_wire_invalid_signature_rejected_401
  11. test_wire_missing_or_unsigned_authorization_header_rejected_401
"""

import base64
import http.client
import json
import os
import pathlib
import sys
import threading
import pytest

# Ensure AUTH_HMAC_SECRET is present in the environment for tests
os.environ.setdefault("AUTH_HMAC_SECRET", "production-secure-hmac-secret-key-32b!")

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.auth_fixtures import (
    create_isolated_db,
    create_auth_server,
    create_token,
    VulnerableDocumentService,
    HardenedDocumentService,
)

TOKEN_USER_A = create_token({"tenant_id": "tenant_1", "user_id": "usr_a"})
TOKEN_USER_B = create_token({"tenant_id": "tenant_2", "user_id": "usr_b"})

AUTH_A = {"Authorization": f"Bearer {TOKEN_USER_A}"}
AUTH_B = {"Authorization": f"Bearer {TOKEN_USER_B}"}


def get_service(db_uri: str | None = None, conn=None):
    """Factory creating service instances with isolated SQLite databases."""
    if db_uri is None or conn is None:
        db_uri, conn = create_isolated_db()
    impl = os.environ.get("AUTH_SERVICE_IMPL", "hardened")
    if impl == "vulnerable":
        svc = VulnerableDocumentService(db_uri=db_uri, keepalive_conn=conn)
    else:
        svc = HardenedDocumentService(db_uri=db_uri, keepalive_conn=conn)
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
    Authenticate as User A (Tenant 1) via signed Bearer token.
    Transmit PUT /documents/doc_2 with {"content": "tampered"} over TCP socket.
    Assert status 403/404 AND doc_2 in SQLite remains exactly "Tenant 2 Private Data".
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_2",
        body=json.dumps({"content": "tampered"}).encode(),
        headers=AUTH_A,
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
    Issue an update against an unowned/non-existent document ID with User A token.
    Assert the service detects cursor.rowcount == 0 and denies the mutation with 403/404.
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_nonexistent",
        body=json.dumps({"content": "ghost"}).encode(),
        headers=AUTH_A,
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
    Request files named CON, NUL.txt, or aux.dat over TCP socket with valid auth.
    Assert rejection (400 or 403) without hanging or blocking the process.
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "GET", f"/files/{device_name}",
        headers=AUTH_A,
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
        headers=AUTH_A,
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
        headers=AUTH_A,
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
        headers=AUTH_A,
    )
    assert status == 200, (
        f"POSITIVE PARITY DEFECT! Authorized update returned {status}: {body}"
    )
    actual = svc.get_document_content("doc_1")
    assert actual == new_content, (
        f"POSITIVE PARITY DEFECT! Database content is {actual!r}, expected {new_content!r}"
    )


# ---------------------------------------------------------------------------
# Test 7: HTTP Parameter Pollution Rejection
# ---------------------------------------------------------------------------
def test_http_parameter_pollution_rejection(auth_server):
    """
    Transmit PUT /documents/doc_1?tenant_id=tenant_2&tenant_id=tenant_1 with
    a valid content update over TCP socket. Assert the service ignores client
    query parameters and binds identity strictly from the verified bearer token.
    """
    host, port, svc = auth_server

    status, body = wire_request(
        host, port, "PUT",
        "/documents/doc_1?tenant_id=tenant_2&tenant_id=tenant_1",
        body=json.dumps({"content": "param_pollution_test"}).encode(),
        headers=AUTH_A,
    )

    assert status == 200, (
        f"PARAMETER POLLUTION DEFECT! Authorized update with polluted query params "
        f"returned {status}: {body}"
    )

    actual_doc1 = svc.get_document_content("doc_1")
    assert actual_doc1 == "param_pollution_test", (
        f"UPDATE FAILED: doc_1 content expected 'param_pollution_test', got {actual_doc1!r}"
    )

    actual_doc2 = svc.get_document_content("doc_2")
    assert actual_doc2 == "Tenant 2 Private Data", (
        f"PARAMETER POLLUTION DEFECT! doc_2 content changed to {actual_doc2!r}"
    )

    actual_tenant = svc.get_document_field("doc_1", "tenant_id")
    assert actual_tenant == "tenant_1", (
        f"PARAMETER POLLUTION DEFECT! doc_1 tenant_id changed to {actual_tenant!r}"
    )


# ---------------------------------------------------------------------------
# Test 8: Header Identity Spoofing Ignored
# ---------------------------------------------------------------------------
def test_header_identity_spoofing_ignored(auth_server):
    """
    Transmit PUT /documents/doc_1 with forged identity headers
    (X-Tenant-ID: tenant_attacker, X-User-ID: admin) alongside User A's token.
    Assert the server ignores unverified identity headers and mutates only
    records authorized by the verified token claims.
    """
    host, port, svc = auth_server

    spoofed_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TOKEN_USER_A}",
        "X-Tenant-ID": "tenant_attacker",
        "X-User-ID": "admin",
        "X-Forwarded-User": "root",
        "X-Original-Tenant": "tenant_2",
    }
    status, body = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "header_spoof_test"}).encode(),
        headers=spoofed_headers,
    )

    assert status == 200, (
        f"HEADER SPOOFING DEFECT! Authorized update with forged headers "
        f"returned {status}: {body}"
    )
    actual_doc1 = svc.get_document_content("doc_1")
    assert actual_doc1 == "header_spoof_test", (
        f"UPDATE FAILED: doc_1 content expected 'header_spoof_test', got {actual_doc1!r}"
    )

    spoofed_read_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TOKEN_USER_A}",
        "X-Tenant-ID": "tenant_2",
        "X-User-ID": "usr_b",
    }
    status2, body2 = wire_request(
        host, port, "PUT", "/documents/doc_2",
        body=json.dumps({"content": "spoofed_cross_tenant"}).encode(),
        headers=spoofed_read_headers,
    )

    assert status2 in (403, 404), (
        f"HEADER SPOOFING DEFECT! Cross-tenant mutation with forged headers "
        f"returned {status2}: {body2}"
    )

    actual_doc2 = svc.get_document_content("doc_2")
    assert actual_doc2 == "Tenant 2 Private Data", (
        f"HEADER SPOOFING DEFECT! doc_2 content mutated to {actual_doc2!r}"
    )


# ---------------------------------------------------------------------------
# Test 9: Wire Tampered Payload Rejected (HTTP 401)
# ---------------------------------------------------------------------------
def test_wire_tampered_payload_rejected_401(auth_server):
    """
    Craft a token where payload claims tenant_2, but signature is from tenant_1's token.
    Assert HTTP 401 Unauthorized and database remains untouched.
    """
    host, port, svc = auth_server

    # Forge payload to claim tenant_2 while copying signature from User A
    orig_parts = TOKEN_USER_A.split(".")
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps({"tenant_id": "tenant_2", "user_id": "usr_b"}, sort_keys=True).encode()
    ).decode().rstrip("=")
    tampered_token = f"{tampered_payload}.{orig_parts[1]}"

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_2",
        body=json.dumps({"content": "tampered_token_payload"}).encode(),
        headers={"Authorization": f"Bearer {tampered_token}"},
    )

    assert status == 401, (
        f"CRYPTOGRAPHIC AUTH DEFECT! Tampered token payload was accepted with status {status}: {body}"
    )
    actual_doc2 = svc.get_document_content("doc_2")
    assert actual_doc2 == "Tenant 2 Private Data", (
        f"CRYPTOGRAPHIC AUTH DEFECT! doc_2 mutated via tampered token payload: {actual_doc2!r}"
    )


# ---------------------------------------------------------------------------
# Test 10: Wire Invalid Signature Rejected (HTTP 401)
# ---------------------------------------------------------------------------
def test_wire_invalid_signature_rejected_401(auth_server):
    """
    Transmit token signed with wrong secret key.
    Assert HTTP 401 Unauthorized.
    """
    host, port, svc = auth_server

    wrong_token = create_token({"tenant_id": "tenant_1", "user_id": "usr_a"}, secret=b"wrong-untrusted-key-bytes-12345!")

    status, body = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "invalid_sig_content"}).encode(),
        headers={"Authorization": f"Bearer {wrong_token}"},
    )

    assert status == 401, (
        f"CRYPTOGRAPHIC AUTH DEFECT! Token with invalid signature accepted with status {status}: {body}"
    )
    actual_doc1 = svc.get_document_content("doc_1")
    assert actual_doc1 != "invalid_sig_content", (
        f"CRYPTOGRAPHIC AUTH DEFECT! doc_1 mutated via invalid signature token"
    )


# ---------------------------------------------------------------------------
# Test 11: Wire Missing or Unsigned Authorization Header Rejected (HTTP 401)
# ---------------------------------------------------------------------------
def test_wire_missing_or_unsigned_authorization_header_rejected_401(auth_server):
    """
    Transmit requests with no Authorization header and with an unsigned raw string.
    Assert both return HTTP 401 Unauthorized.
    """
    host, port, svc = auth_server

    # Case A: Missing header entirely
    status1, body1 = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "no_auth_content"}).encode(),
        headers={},
    )
    assert status1 == 401, (
        f"AUTH DEFECT! Request with missing Authorization header returned {status1}: {body1}"
    )

    # Case B: Plain unsigned string header
    status2, body2 = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "unsigned_auth_content"}).encode(),
        headers={"Authorization": "Bearer unsigned-plain-string-no-sig"},
    )
    assert status2 == 401, (
        f"AUTH DEFECT! Request with unsigned Authorization header returned {status2}: {body2}"
    )


# ---------------------------------------------------------------------------
# Test 12: Wire Alg:None Token Rejected (HTTP 401)
# ---------------------------------------------------------------------------
def test_alg_none_token_rejection(auth_server):
    """
    Transmit tokens with 'alg': 'none' (both in claims payload and JWT header)
    with empty/omitted signatures.
    Assert HTTP 401 Unauthorized and database remains untouched.
    """
    host, port, svc = auth_server

    # Variant A: Claims payload with {"alg": "none"} and trailing dot (empty sig)
    payload_a = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "tenant_id": "tenant_1", "user_id": "usr_a"}, sort_keys=True).encode()
    ).decode().rstrip("=")
    token_none_a = f"{payload_a}."

    status_a, body_a = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "alg_none_tamper_attempt_a"}).encode(),
        headers={"Authorization": f"Bearer {token_none_a}"},
    )
    assert status_a == 401, (
        f"AUTH DEFECT! alg:none payload token accepted with status {status_a}: {body_a}"
    )

    # Variant B: JWT 3-part token with header {"alg": "none", "typ": "JWT"}
    header_b = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}, sort_keys=True).encode()
    ).decode().rstrip("=")
    payload_b = base64.urlsafe_b64encode(
        json.dumps({"tenant_id": "tenant_1", "user_id": "usr_a"}, sort_keys=True).encode()
    ).decode().rstrip("=")
    token_none_b = f"{header_b}.{payload_b}."

    status_b, body_b = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "alg_none_tamper_attempt_b"}).encode(),
        headers={"Authorization": f"Bearer {token_none_b}"},
    )
    assert status_b == 401, (
        f"AUTH DEFECT! alg:none header token accepted with status {status_b}: {body_b}"
    )

    actual_doc1 = svc.get_document_content("doc_1")
    assert actual_doc1 != "alg_none_tamper_attempt_a" and actual_doc1 != "alg_none_tamper_attempt_b", (
        "AUTH DEFECT! doc_1 mutated via alg:none token"
    )


# ---------------------------------------------------------------------------
# Test 13: Wire Truncated and Malformed Base64 Token Rejected (HTTP 401)
# ---------------------------------------------------------------------------
def test_truncated_token_rejection(auth_server):
    """
    Transmit truncated tokens (missing signature component entirely) and tokens
    with corrupted/malformed base64.
    Assert HTTP 401 Unauthorized and database remains untouched.
    """
    host, port, svc = auth_server

    # Variant A: Truncated token without signature part
    truncated_token = TOKEN_USER_A.split(".")[0]

    status_a, body_a = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "truncated_tamper_attempt"}).encode(),
        headers={"Authorization": f"Bearer {truncated_token}"},
    )
    assert status_a == 401, (
        f"AUTH DEFECT! Truncated token accepted with status {status_a}: {body_a}"
    )

    # Variant B: Malformed base64 string
    malformed_token = "invalid!@#$%^&*().tampered_signature"

    status_b, body_b = wire_request(
        host, port, "PUT", "/documents/doc_1",
        body=json.dumps({"content": "malformed_tamper_attempt"}).encode(),
        headers={"Authorization": f"Bearer {malformed_token}"},
    )
    assert status_b == 401, (
        f"AUTH DEFECT! Malformed token accepted with status {status_b}: {body_b}"
    )

    actual_doc1 = svc.get_document_content("doc_1")
    assert actual_doc1 != "truncated_tamper_attempt" and actual_doc1 != "malformed_tamper_attempt", (
        "AUTH DEFECT! doc_1 mutated via truncated/malformed token"
    )
