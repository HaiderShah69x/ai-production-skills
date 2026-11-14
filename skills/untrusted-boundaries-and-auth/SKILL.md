---
name: untrusted-boundaries-and-auth
description: >-
  Enforces object-level authorization (IDOR prevention), strict path boundary
  containment with symlink dereferencing, and recursive input schema validation to
  prevent privilege escalation and unauthorized file access. Use when writing resource
  endpoints, document fetchers, file download/upload handlers, or user profile APIs.
---

# Untrusted Boundaries and Auth

## Core Objective

Eliminate perimeter and boundary blind spots in AI-generated code:
1. **Broken Object-Level Authorization (IDOR) & Multi-Tenant Leaks:** Returning or modifying private records solely by record ID or single tenant key, allowing cross-tenant or cross-user data exposure.
2. **Path Traversal & Symlink Escapes:** Naive path concatenation (`os.path.join`) or partial checks that allow `../` or symlinks/junctions pointing outside the base directory.
3. **Shallow & Nested Mass-Assignment:** Binding raw client dictionaries or merging unvalidated nested objects into models, allowing callers to overwrite privileged attributes (`is_admin`, `role`, `tenant_id`, `balance`).

---

## Invariant 1 — Mandatory Object-Level Authorization & Compound Scoping

### Rule
**Authentication is not authorization.** Every query that reads, updates, or deletes tenant- or user-scoped data **must** bind both the authenticated actor's ID and tenant ID directly in the retrieval query.

### Requirements
- **Trusted Context Only (Forgery Prevention):** The `tenant_id` and `user_id` bound into retrieval and mutation queries **MUST** originate strictly from the cryptographically verified session token, JWT claims, or mutual-TLS context (e.g. `auth_context.tenant_id`, `request.state.user.id`). It is **strictly forbidden** to accept or trust tenancy identifiers or actor IDs supplied via client query strings, JSON request bodies, form fields, or unverified custom headers (e.g. `X-Tenant-ID`), which invite trivial client-controlled tenancy forgery.
- **Compound Scoping Required:** In multi-tenant systems, single-key lookups are defective. Every data access query must include compound filters:
  ```sql
  SELECT * FROM documents
  WHERE id = :doc_id
    AND tenant_id = :authenticated_tenant_id
    AND owner_id = :authenticated_user_id;
  ```
- **Uniform Rejection Without Leaks:** If the record does not exist or belongs to another tenant/user, return HTTP 404 (or 403 without metadata leaks). Never disclose whether a cross-tenant or foreign record ID exists.
- **No In-Memory Post-Filtering:** Ownership checks must never be deferred to application memory after fetching un-scoped records from the database.

---

## Invariant 2 — Strict Canonical Path Containment & Symlink Dereferencing

### Rule
Every filesystem path resolved from client-provided input **must** be canonically resolved—including full symlink and directory junction dereferencing—and asserted to reside within the intended base directory before touching file descriptors.

### Requirements
- **Dereference Canonical Target:** Always resolve the path completely before inspection:
  ```python
  base = Path(BASE_DIR).resolve()
  canonical_target = (base / user_filename).resolve()
  ```
- **Assert Containment (`is_relative_to`):** Verify `canonical_target.is_relative_to(base)`. If false, abort immediately with an error (e.g. `PermissionError`, HTTP 403 / 400).
- **Symlink Boundary Checks:** If `user_filename` points to a symlink or junction, resolving it exposes the real target file. The real target file itself must reside inside `base`.
- **Windows Path & NTFS Alternate Data Stream Sanitization:**
  - Forbid `:` (colons) in client-supplied path components to block **NTFS Alternate Data Streams** (e.g. `report.txt:hidden_stream` or `dir::$INDEX_ALLOCATION`).
  - Forbid Windows reserved device names (e.g. `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`).
- **Forbid String Replacement:** Never rely on stripping `../`, regex sanitizers, or substring blacklists. Attackers easily bypass string filters via encoded slashes, backslashes, or null bytes (`\x00`).

---

## Invariant 3 — Recursive Schema Allowlisting (Nested Mass-Assignment Defense)

### Rule
All external client payloads (JSON, form data, nested dicts) **must** be filtered against an explicit, recursive allowlist schema before updating domain models or persistent stores.

### Requirements
- **Never Bind Raw or Shallow-Cleaned Dictionaries:** Forbid `model.update(request_data)`, shallow dictionary merges (`dict.update()`), or unpackings (`**data`).
- **Recursive Allowlist Schema:** Define explicit structures matching nested objects and types:
  ```python
  ALLOWED_SCHEMA = {
      "name": str,
      "email": str,
      "metadata": {
          "theme": str,
          "notifications": bool,
      },
  }
  ```
- **Strip or Reject Unauthorized Keys at Every Level:** Any attempt to provide unlisted keys at the root level (`is_admin`, `role`) or nested levels (`metadata.is_admin`, `metadata.role`) must be stripped or rejected with a validation error (HTTP 422/400).

---

## Verification Requirements

The test suite must include negative verification for all critical boundary violations:
1. **Standard IDOR:** Attempt to access User B's document using User A's credentials. Must return rejection and leak zero data.
2. **Cross-Tenant IDOR:** User from Tenant A attempts to access Tenant B's document using a valid document ID under Tenant A's scope. Must be rejected.
3. **Direct Path Traversal:** Accessing `../secret_keys.txt` must be rejected before opening the file.
4. **Symlink / Junction Traversal:** Symlinks or junctions placed in public directories pointing to external targets must be rejected via canonical resolution.
5. **Shallow Mass Assignment:** Top-level privilege injection (`{"is_admin": True}`) must be stripped or rejected.
6. **Nested Mass Assignment:** Deep nested privilege injection (`{"metadata": {"is_admin": True}}`) must be stripped or rejected.
7. **Positive Parity:** Legitimate users can access their own documents, read valid relative files, and update allowed profile fields.

---

## Checklist

- [ ] Every user/tenant scoped query includes compound `tenant_id` AND `owner_id` in the `WHERE` clause.
- [ ] No ownership checks deferred to application memory after fetching un-scoped records.
- [ ] All file paths use `Path(...).resolve()` and `is_relative_to(base_dir)`.
- [ ] Symlink/junction dereferencing confirmed before opening file descriptors.
- [ ] No string-replacement path filters.
- [ ] Recursive field allowlist active for both root and nested payload structures.
- [ ] Negative IDOR, cross-tenant, traversal, symlink, and mass-assignment tests passing.
