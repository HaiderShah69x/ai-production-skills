---
name: untrusted-boundaries-and-auth
description: >-
  Enforces object-level authorization (IDOR prevention), strict path boundary
  containment with symlink dereferencing, Windows filesystem sanitization, and
  strict input schema validation to prevent privilege escalation and unauthorized
  file access. Use when writing resource endpoints, document fetchers, file
  download/upload handlers, or user profile APIs.
---

# Untrusted Boundaries and Auth

## Core Objective

Eliminate perimeter and boundary blind spots in AI-generated code by enforcing
real database-level authorization, OS-level path containment, and strict schema
allowlists — verified against physical SQLite state, not in-memory mocks.

1. **Broken Object-Level Authorization (IDOR) & Multi-Tenant Leaks:** Mutating or returning private records solely by record ID without compound tenant + owner scoping in the SQL WHERE clause.
2. **Path Traversal, Symlink Escapes & OS Edge Cases:** Naive path concatenation, unresolved symlinks/junctions, NTFS Alternate Data Streams, and Windows reserved device names bypassing boundary checks.
3. **Mass-Assignment Privilege Escalation:** Binding raw client dictionaries into SQL UPDATE or model merge operations, allowing callers to overwrite `tenant_id`, `owner_id`, `role`, or inject arbitrary keys.

---

## Invariant 1 — Mandatory Compound SQL Scoping & Cryptographic Bearer Tokens

### Rule
**Authentication is not authorization.** Every SQL query that reads, updates, or deletes tenant- or user-scoped data **must** bind both `tenant_id` AND `owner_id` resolved from cryptographically verified HMAC-SHA256 bearer tokens directly in the WHERE clause.

### Requirements
- **Cryptographic Token Verification:** All ingress requests to protected endpoints (`/documents/*`, `/files/*`) **must** present an `Authorization: Bearer <payload_b64>.<signature_b64>` (or 3-part `<header_b64>.<payload_b64>.<sig_b64>`) header. Tokens are signed with HMAC-SHA256 over canonical JSON payloads and verified via constant-time comparison (`hmac.compare_digest`). The HMAC secret **must** be dynamically injected via environment variables (`AUTH_HMAC_SECRET`) with no insecure default fallbacks. Missing, truncated, malformed, or tampered tokens, as well as tokens specifying `"alg": "none"`, must immediately receive **HTTP 401 Unauthorized**.
- **Trusted Dynamic Context Only:** The `tenant_id` and `user_id` bound into SQL queries **MUST** originate from verified token claims. Static or hardcoded service instance state (e.g. `session_tenant_id`) is strictly eliminated in favor of dynamic per-request token claim extraction.
- **HTTP Parameter Pollution (HPP) Defense:** Route dispatchers and request handlers must strip query strings from path routing (e.g. `path.split("?", 1)[0]`). Multi-value query keys or conflicting parameters (`?tenant_id=tenant_2&tenant_id=tenant_1`) must never override verified token claims or leak data across tenant boundaries.
- **Header Identity Spoofing Defense:** Untrusted ingress headers (such as `X-Tenant-ID`, `X-User-ID`, `X-Forwarded-User`, or `X-Original-Tenant`) must be completely ignored for identity resolution unless injected by a verified internal API gateway. Tenancy scoping must derive solely from verified cryptographic token signatures.
- **Compound SQL Scoping:** Every mutation must enforce compound ownership at the database level:
  ```sql
  UPDATE documents SET content = ?
  WHERE id = ? AND tenant_id = ? AND owner_id = ?;
  ```
- **Rowcount Verification:** After every mutation, verify `cursor.rowcount == 1`. If `rowcount == 0`, the record either does not exist or belongs to another tenant — rollback and return HTTP 404/403 without leaking record existence.
- **No In-Memory Post-Filtering:** Ownership checks must occur inside the SQL WHERE clause, never deferred to application code after fetching un-scoped rows.

---

## Invariant 2 — Strict Canonical Path Containment & OS Sanitization

### Rule
Every filesystem path resolved from client input **must** be canonically resolved and asserted to reside strictly within the base directory. All OS-specific attack vectors must be blocked before path resolution.

### Requirements
- **Block NTFS Alternate Data Streams:** Reject any filename containing `:` immediately (e.g. `file.txt:hidden`, `dir::$INDEX_ALLOCATION`).
- **Block Windows Reserved Device Names:** Reject `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` (case-insensitive check against the filename stem, with or without extension).
- **Strip Trailing Dots and Whitespace:** Remove trailing `.` and spaces from each path component before evaluation (Windows silently strips these, creating bypass opportunities).
- **Canonical Resolution & Containment:**
  ```python
  base = Path(BASE_DIR).resolve()
  canonical_target = (base / clean_name).resolve()
  assert canonical_target.is_relative_to(base) and canonical_target != base
  ```
- **Handle-Based Path Confinement (Cross-Platform TOCTOU Defense):** To prevent time-of-check to time-of-use
  (TOCTOU) symlink races, open the file descriptor first using `os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))`
  and query the final canonical device volume path directly from the opened handle before reading:
  * On Windows (`sys.platform == "win32"`): resolve using `ctypes.windll.kernel32.GetFinalPathNameByHandleW` via `msvcrt.get_osfhandle(fd)`,
    strip device prefix namespaces (`\\?\`), and verify `canonical_path.is_relative_to(base_dir.resolve())`.
  * On POSIX / macOS (`sys.platform != "win32"`): inspect descriptor containment via `/proc/self/fd/{fd}` or compare `os.fstat(fd)` against `os.stat(canonical_target)` to ensure device and inode parity with `O_NOFOLLOW`. Close the descriptor cleanly if containment fails.
- **Symlink/Junction Dereferencing:** Both path resolution and handle inspection follow symlinks and junctions — the real underlying target must reside strictly inside `base`.
- **Forbid String Replacement Sanitizers:** Never rely on stripping `../`, regex blacklists, or substring filters.

---

## Invariant 3 — Strict Schema Allowlist (Mass-Assignment Defense)

### Rule
All client payloads **must** be filtered against an explicit schema allowlist before updating database records. Protected fields (`tenant_id`, `owner_id`, `id`, `role`) must never be writable from client input.

### Requirements
- **Explicit Field + Type Allowlist:**
  ```python
  ALLOWED_UPDATE_FIELDS = {
      "title": str,
      "content": str,
  }
  ```
- **Drop or Reject Unauthorized Keys:** Any key not in the allowlist (including `tenant_id`, `owner_id`, `id`, `role`) must be silently dropped or rejected with HTTP 400/422.
- **Type Enforcement:** Values must match the expected type. Non-string types (lists, dicts, integers) for string-typed fields must be rejected.
- **Compound Scoping on Updates:** Even for allowed fields, the UPDATE query must include `AND tenant_id = ? AND owner_id = ?` to prevent cross-tenant writes.

---

## Verification Requirements

The adversarial test suite runs against a live loopback server (`http.server.ThreadingHTTPServer(('127.0.0.1', 0), ...)`)
on an ephemeral kernel-allocated port, transmitting raw HTTP wire bytes using `http.client.HTTPConnection`.
Synthetic dispatch mocks and hardcoded session properties are eliminated. Every test asserts HTTP wire status and physical database state:

1. **Cross-Tenant IDOR Mutation:** User A (Tenant 1) issues `PUT /documents/doc_2` with User A's token over live TCP socket. Assert HTTP 403/404 AND doc_2 content in SQLite remains unchanged ("Tenant 2 Private Data").
2. **Rowcount Integrity:** Update a non-existent document ID over TCP. Assert HTTP 403/404 and zero state mutation.
3. **Windows Device Names:** Request `CON`, `NUL.txt`, `aux.dat` over TCP. Assert rejection (HTTP 400/403) without process hang.
4. **NTFS Alternate Data Stream:** Request `file.txt:stream` over TCP. Assert immediate rejection (HTTP 400/403).
5. **Mass-Assignment Tampering:** PUT `/documents/doc_1` with `{"content": "valid", "tenant_id": "tenant_2", "role": ["admin"]}`. Assert content updates while `tenant_id` remains `"tenant_1"` in SQLite.
6. **Positive Parity:** User A updates own `doc_1` with valid payload and token over TCP. Assert HTTP 200 and database reflects new content.
7. **HTTP Parameter Pollution Rejection:** Issue `PUT /documents/doc_1?tenant_id=tenant_2&tenant_id=tenant_1` over TCP. Assert service ignores ambiguous query parameters and binds strictly to verified token claims without cross-tenant modification.
8. **Header Identity Spoofing Ignored:** Issue PUT requests with forged identity headers (`X-Tenant-ID: tenant_attacker`, `X-User-ID: admin`). Assert server ignores spoofed headers and strictly denies cross-tenant access.
9. **Tampered Token Payload Rejection:** Issue PUT request with a modified token payload (tampering tenant ID without resigning). Assert HTTP 401 Unauthorized.
10. **Invalid Signature Token Rejection:** Issue PUT request with token signed with an invalid secret. Assert HTTP 401 Unauthorized.
11. **Missing or Unsigned Header Rejection:** Issue PUT request with missing or unsigned Authorization header. Assert HTTP 401 Unauthorized.
12. **Alg:None Token Rejection:** Transmit tokens setting `"alg": "none"` in payload or JWT header with empty/omitted signature. Assert HTTP 401 Unauthorized.
13. **Truncated & Malformed Token Rejection:** Transmit tokens missing signature component or malformed base64 strings. Assert HTTP 401 Unauthorized.

---

## Checklist

- [ ] Every SQL mutation includes compound `WHERE tenant_id = ? AND owner_id = ?`.
- [ ] `cursor.rowcount` verified after every UPDATE; rollback on mismatch.
- [ ] Identity context bound dynamically from verified HMAC-SHA256 bearer tokens, never from client input or static instance variables.
- [ ] `AUTH_HMAC_SECRET` injected dynamically from environment variables with no fallback to insecure defaults in hardened mode.
- [ ] HTTP Parameter Pollution blocked; query strings stripped from routes and ignored for auth.
- [ ] Ingress identity headers (`X-Tenant-ID`, `X-User-ID`) ignored in favor of verified token signatures.
- [ ] Missing, malformed, truncated, or tampered tokens, as well as alg:none tokens, rejected with HTTP 401.
- [ ] File paths reject `:` before resolution (NTFS ADS block).
- [ ] Windows reserved device names rejected case-insensitively.
- [ ] Trailing dots/spaces stripped from path components.
- [ ] Canonical resolution via `resolve()` + `is_relative_to(base)` enforced.
- [ ] Handle-based path confinement verifies opened file descriptor via device handle (`GetFinalPathNameByHandleW` on Windows, `/proc/self/fd` or `fstat` with `O_NOFOLLOW` on POSIX) before reading.
- [ ] Schema allowlist active — `tenant_id`, `owner_id`, `id`, `role` unwritable.
- [ ] Live ephemeral loopback TCP sockets tested with `http.client.HTTPConnection`.
- [ ] All 15 security test cases pass against hardened, fail against vulnerable.
