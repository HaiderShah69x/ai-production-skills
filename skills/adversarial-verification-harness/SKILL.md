---
name: adversarial-verification-harness
description: >-
  Enforces negative-first testing, strict assertion contracts, SUT integrity,
  collection guards, deterministic non-zero exit codes, and automated AST mutation
  testing. Use when authoring test suites, test runners, CI checks, or validating
  APIs, auth gates, and business logic.
---

# Adversarial Verification Harness

## Core Objective

Eliminate the **"Exit Code 0" illusion** — preventing AI coding agents and human developers from gaming test suites via weak assertions, mocked controls, swallowed exceptions, skipped tests, or zero-collection passes. A test suite must actively falsify claims, not merely execute code without throwing errors.

Verification harnesses must achieve true vigilance by passing automated **AST-level mutation testing** (>= 90% mutation kill score) rather than relying solely on hand-crafted or mocked defect cases.

---

## Invariant 1 — Adversarial Coverage & Parity

### Rule
For every security policy or business constraint, negative test verification must be executed alongside positive functional tests to prevent both broken implementations and trivial "deny-all" bypasses.

### Requirements
- **Negative Verification First:** Test unauthorized tokens, malformed bodies, boundary overflows, negative amounts, and duplicate replays *before* or alongside happy paths.
- **Strict Assertion on Rejection:** Must assert exact rejection codes (e.g., HTTP 400, 401, 403, 409, 413, 422, 429) **AND** verify zero state mutation (balances, quotas, records remain identical to pre-test baseline).
- **Positive Parity:** Every endpoint/component must include positive verification with valid parameters. A system that blindly returns `False`, `403`, or throws an exception on all inputs must fail the test suite.

---

## Invariant 2 — Strict Assertion Contracts

### Rule
Vague assertions that can pass accidentally or permit multiple states are strictly forbidden. Assertions must use exact literals for inputs, expected returns, and resulting state transitions.

### Requirements
- **Banned Vague Assertions:**
  - `assert result is not None`
  - `assert balance >= 0`
  - `assert status_code != 500`
  - `assert result in [True, False]`
  - `assert len(items) > 0`
- **Mandatory Exact Assertions:**
  - Initial baseline state check: `assert balance == 10000`
  - Exact outcome check: `assert result is False`
  - Post-operation invariant check: `assert balance == 10000`
- **Currency & Precision:** Financial values, balances, and counts must use integer cents (e.g. `10000` for `$100.00`) or `Decimal`, never IEEE 754 floating-point numbers (`0.1 + 0.2 != 0.3`).

---

## Invariant 3 — Zero Swallowed Failures

### Rule
Exceptions must never be quietly suppressed. Expected exceptions must be strictly verified, and unexpected exceptions must immediately terminate the test with a non-zero exit code.

### Requirements
- **Forbidden Patterns:**
  - Empty catch blocks: `except Exception: pass` or `catch (err) {}`.
  - Fallback defaults masking errors: `except: return 200`.
  - Inverted try/except: writing a `try` block that passes when no error is raised, without verifying that expected exceptions actually fire.
- **Verifying Expected Failures:** When an operation is expected to raise an error, the harness must fail if the exception is *not* raised:
  ```python
  # CORRECT:
  try:
      service.transfer(-5000, recipient)
      record_failure("Expected ValueError was not raised")
  except ValueError:
      pass  # expected
  ```

---

## Invariant 4 — System Under Test (SUT) Integrity

### Rule
The security boundaries, validators, core business logic, and authentication layers under test **must never be mocked, monkeypatched, or bypassed**.

### Requirements
- **Mocks Restricted to External Boundaries:** Mocks are permitted *only* for unmanaged external third-party boundaries (e.g., external credit card gateways, third-party SMS providers).
- **Real Component Verification:** Application databases (or test DBs/in-memory SQLite), internal domain logic, input validators, and authorization middleware must run as real, instantiated components during verification.

---

## Invariant 5 — Automated AST Mutation Engine & Collection Guards

### Rule
Test runners must prove their vigilance against programmatically generated defects via abstract syntax tree (AST) mutations, rather than relying on hand-crafted bug mocks. A harness is only complete if it catches >= 90% of AST mutants and enforces deterministic collection guards.

### Requirements
- **Collection Guards:** The test runner must enforce a minimum test execution threshold:
  ```python
  if TESTS_RUN < REQUIRED_MINIMUM:
      sys.exit(2)  # Zero-collection / test-omission failure
  ```
- **Automated AST Mutation Engine:**
  The harness runner parses the production target AST and programmatically injects mutations:
  1. *Comparison Inversions:* `Gt` <-> `LtE`, `GtE` <-> `Lt`, `Eq` <-> `NotEq` (e.g. flipping boundary checks).
  2. *Boolean Inversions:* `Constant(value=True)` <-> `Constant(value=False)` (e.g. flipping validation outcomes).
  3. *Statement Stripping:* Replacing state mutation `AugAssign` (deductions / credits) with `Pass`.
  4. *Return Neutralisation:* Replacing return values with `None`.
- **Mutation Kill Score Threshold (>= 90%):**
  For every generated mutant, the test suite must execute and terminate with a non-zero exit code (`exit code != 0`).
  $$\text{Mutation Score} = \left( \frac{\text{Mutants Killed}}{\text{Total Mutants}} \right) \times 100 \ge 90\%$$
  Any mutant that slips through unnoticed indicates a gap or vague assertion in the test suite.
- **Deterministic Exit Codes:**
  - Collection guard violation: Exit Code 2.
  - Test suite assertion failure or mutation score < 90%: Exit Code 1.
  - All tests passing with mutation score >= 90%: Exit Code 0.

---

## Harness Rule — The Harness is Read-Only

> [!CAUTION]
> The test harness, assertion thresholds, test payloads, and required test collections are **read-only** to the implementation agent. Agents must never:
> - Delete, skip, or disable tests.
> - Weaken assertions (`==` to `!=`, exact to `>=`).
> - Mock internal components to force a test pass.
>
> When a test fails, the defect resides in the **implementation**, not the test harness.

---

## Verification Checklist

- [ ] Negative verification written and passing with exact rejection codes.
- [ ] Positive parity test confirms valid requests succeed (no deny-all stubs).
- [ ] No floating-point math in financial/quota logic (cents or Decimal only).
- [ ] Exact literal assertions used for baseline, return value, and post-state.
- [ ] Zero empty `except` blocks; expected exceptions verified explicitly.
- [ ] Core business components and security validators executed without mocks.
- [ ] Collection guard active (`TESTS_RUN >= MINIMUM`, exit code 2 on failure).
- [ ] Automated AST mutation engine generates >= 6 syntactically valid mutants.
- [ ] Mutation kill score >= 90% achieved against AST mutants.
- [ ] Clean reference implementation passes 100% with exit code 0.
