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

## Invariant 1 — Mandatory Compound SQL Scoping & Trusted Session Context

### Rule
**Authentication is not authorization.** Every SQL query that reads, updates, or deletes tenant- or user-scoped data **must** bind both `tenant_id` AND `owner_id` from the cryptographically verified session context directly in the WHERE clause.

### Requirements
- **Trusted Context Only (Forgery Prevention):** The `tenant_id` and `user_id` bound into SQL queries **MUST** originate from the verified session/token context (e.g. `service.session_tenant_id`). It is **strictly forbidden** to read these values from client query strings, JSON request bodies, form fields, or unverified headers.
- **HTTP Parameter Pollution (HPP) Defense:** Route dispatchers and request handlers must strip query strings from path routing (e.g. `path.split("?", 1)[0]`). Multi-value query keys or conflicting parameters (`?tenant_id=tenant_2&tenant_id=tenant_1`) must never override verified session identity or leak data across tenant boundaries.
- **Header Identity Spoofing Defense:** Untrusted ingress headers (such as `X-Tenant-ID`, `X-User-ID`, `X-Forwarded-User`, or `X-Original-Tenant`) must be completely ignored for identity resolution unless injected by a verified, authenticated internal API gateway. Tenancy scoping must derive solely from verified cryptographic session state.
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
- **Handle-Based Path Confinement (TOCTOU Defense):** To prevent time-of-check to time-of-use
  (TOCTOU) symlink races, open the file descriptor first using `os.open(str(target), os.O_RDONLY)`
  and query the final canonical device volume path directly from the opened handle before reading.
  On Windows, resolve using `ctypes.windll.kernel32.GetFinalPathNameByHandleW` via `msvcrt.get_osfhandle(fd)`,
  strip device prefix namespaces (`\\?\`), and verify `canonical_path.is_relative_to(base_dir.resolve())`.
  On POSIX, resolve via `/proc/self/fd/{fd}` or `realpath`. Close the descriptor cleanly if containment fails.
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
Synthetic dispatch mocks are eliminated. Every negative test asserts both HTTP status and physical database state:

1. **Cross-Tenant IDOR Mutation:** User A (Tenant 1) issues `PUT /documents/doc_2` over live TCP socket. Assert HTTP 403/404 AND doc_2 content in SQLite remains unchanged ("Tenant 2 Private Data").
2. **Rowcount Integrity:** Update a non-existent document ID over TCP. Assert HTTP 403/404 and zero state mutation.
3. **Windows Device Names:** Request `CON`, `NUL.txt`, `aux.dat` over TCP. Assert rejection (HTTP 400/403) without process hang.
4. **NTFS Alternate Data Stream:** Request `file.txt:stream` over TCP. Assert immediate rejection (HTTP 400/403).
5. **Mass-Assignment Tampering:** PUT `/documents/doc_1` with `{"content": "valid", "tenant_id": "tenant_2", "role": ["admin"]}`. Assert content updates while `tenant_id` remains `"tenant_1"` in SQLite.
6. **Positive Parity:** User A updates own `doc_1` with valid payload over TCP. Assert HTTP 200 and database reflects new content.
7. **HTTP Parameter Pollution Rejection:** Issue `PUT /documents/doc_1?tenant_id=tenant_2&tenant_id=tenant_1` over TCP. Assert service ignores ambiguous query parameters and binds strictly to verified session identity without cross-tenant modification.
8. **Header Identity Spoofing Ignored:** Issue PUT requests with forged identity headers (`X-Tenant-ID: tenant_attacker`, `X-User-ID: admin`). Assert server ignores spoofed headers and strictly denies cross-tenant access.

---

## Checklist

- [ ] Every SQL mutation includes compound `WHERE tenant_id = ? AND owner_id = ?`.
- [ ] `cursor.rowcount` verified after every UPDATE; rollback on mismatch.
- [ ] Identity context bound from verified session, never from client input.
- [ ] HTTP Parameter Pollution blocked; query strings stripped from routes and ignored for auth.
- [ ] Ingress identity headers (`X-Tenant-ID`, `X-User-ID`) ignored in favor of verified session context.
- [ ] File paths reject `:` before resolution (NTFS ADS block).
- [ ] Windows reserved device names rejected case-insensitively.
- [ ] Trailing dots/spaces stripped from path components.
- [ ] Canonical resolution via `resolve()` + `is_relative_to(base)` enforced.
- [ ] Handle-based path confinement verifies opened file descriptor via device handle before reading.
- [ ] Schema allowlist active — `tenant_id`, `owner_id`, `id`, `role` unwritable.
- [ ] Live ephemeral loopback TCP sockets tested with `http.client.HTTPConnection`.
- [ ] All 10 adversarial tests pass against hardened, fail against vulnerable.
