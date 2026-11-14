---
name: untrusted-boundaries-and-auth
description: >-
  Enforces object-level authorization (IDOR prevention), strict path boundary
  containment, and explicit input schema validation to prevent privilege escalation
  and unauthorized file access. Use when writing resource endpoints, document
  fetchers, file download/upload handlers, or user profile APIs.
---

# Untrusted Boundaries and Auth

## Core Objective

Eliminate critical perimeter and boundary blind spots in AI-generated code:
1. **Broken Object-Level Authorization (IDOR):** Returning private records solely by primary key (`id`), trusting the caller's role without scoping to the caller's tenant or user identity.
2. **Path Traversal & Arbitrary File Access:** Using naive path concatenation (`os.path.join`) without canonical resolution and root boundary containment checks.
3. **Mass-Assignment / Parameter Tampering:** Binding raw client dictionaries directly into models or persistence layers, allowing callers to overwrite privileged attributes (`is_admin`, `role`, `balance`).

---

## Invariant 1 — Mandatory Object-Level Authorization (IDOR Prevention)

### Rule
**Authentication is not authorization.** Every query that reads, updates, or deletes tenant- or user-scoped data **must** bind the authenticated caller's identity directly into the retrieval query.

### Requirements
- **Bind Owner ID Directly:** Never fetch by `id` alone and check ownership in Python memory. Always scope queries at the data layer:
  ```sql
  SELECT * FROM documents WHERE id = :doc_id AND owner_id = :current_user_id;
  ```
- **Uniform Rejection:** If the record does not exist or belongs to another user, return HTTP 404 (or 403 without metadata leaks). Do not disclose whether an unowned ID exists in the database.
- **Hierarchical/Tenant Scoping:** In multi-tenant systems, every query must include `tenant_id` alongside user/role constraints.

---

## Invariant 2 — Strict Canonical Path Containment

### Rule
Every filesystem path resolved from client-provided input **must** be canonically resolved and strictly asserted to reside within the intended base directory before touching file descriptors.

### Requirements
- **Use Canonical Path Resolution:** Always resolve paths with `pathlib.Path(base_dir / client_input).resolve()`.
- **Assert Containment (`is_relative_to`):** Verify `target_path.is_relative_to(base_dir)`. If false, abort immediately with an error (e.g. HTTP 403 / 400).
- **Forbid String Matching / Replacement:** Never attempt to sanitize paths by stripping `../`, removing slashes, or replacing substrings. Attackers bypass string filters via URL-encoding (`%2e%2e%2f`), backslashes, or null bytes (`\x00`).
- **Canonical Pattern:**
  ```python
  base = Path("/var/app/uploads").resolve()
  target = Path(base / user_filename).resolve()
  if not target.is_relative_to(base):
      raise PermissionError("Path traversal attempt detected")
  ```

---

## Invariant 3 — Explicit Schema Whitelists (Mass-Assignment Defense)

### Rule
All external client payloads (JSON, form data, query params) **must** be filtered against an explicit, strict allowlist before updating domain models or persistent stores.

### Requirements
- **Never Bind Raw Dictionaries:** Forbid `model.update(request_data)`, `db.execute("UPDATE ...", data)`, or unpackings like `**request.json`.
- **Strict Allowlist:** Define `ALLOWED_FIELDS = {"name", "email", "bio"}`. Explicitly extract and validate each allowed key.
- **Reject or Strip Privileged Keys:** Any attempt to provide sensitive attributes (`is_admin`, `role`, `verified`, `balance`, `tenant_id`) must either raise a validation error (HTTP 422/400) or be dropped cleanly.

---

## Verification Requirements

The test suite must include negative verification for all three boundaries:
1. **IDOR Test:** Attempt to access Document B (owned by User 2) using User 1's credentials. Must return rejection and leak zero data.
2. **Traversal Test:** Attempt file retrieval with `../secret.txt`, nested `../../`, and absolute paths. Must be rejected before any `open()` or file read call.
3. **Mass-Assignment Test:** Submit `{"is_admin": True, "name": "Alice"}`. Assert `is_admin` remains unchanged while permitted fields update.
4. **Positive Parity:** Verify valid users can access their own documents, read valid relative files, and update legitimate profile fields.

---

## Checklist

- [ ] Every user/tenant scoped query includes `owner_id` or `tenant_id` in the `WHERE` clause.
- [ ] No ownership checks deferred to application memory after fetching un-scoped records.
- [ ] All file paths use `Path(...).resolve()` and `is_relative_to(base_dir)`.
- [ ] No string-replacement path filters.
- [ ] Payload inputs filtered against an explicit field allowlist.
- [ ] Negative IDOR, traversal, and mass-assignment tests passing.
