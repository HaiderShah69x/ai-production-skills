---
name: adversarial-verification-harness
description: >-
  Enforces negative-first testing, strict assertion contracts, SUT integrity,
  collection guards, and deterministic non-zero exit codes. Use when authoring test
  suites, test runners, CI checks, or validating APIs, auth gates, and business logic.
---

# Adversarial Verification Harness

## Core Objective

Eliminate the **"Exit Code 0" illusion** — preventing AI coding agents and human developers from gaming test suites via weak assertions, mocked controls, swallowed exceptions, skipped tests, or zero-collection passes. A test suite must actively falsify claims, not merely execute code without throwing errors.

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

## Invariant 5 — Harness Failure Propagation & Collection Guards

### Rule
Test runners must track execution counts and failures deterministically. If required tests are omitted or skipped, or if any assertion fails, the process must exit with a non-zero code.

### Requirements
- **Collection Guards:** The test runner must enforce a minimum test execution threshold:
  ```python
  if TESTS_RUN < REQUIRED_MINIMUM:
      sys.exit(2)  # Zero-collection / test-omission failure
  ```
- **Mutation Kill Matrix Verification:** Test suites must be validated by running them against deliberate, realistic code mutations:
  * Boundary omissions (e.g. `amount <= 0` check omitted).
  * Edge condition bypasses (e.g. `amount < 0` allowing `amount == 0`).
  * State leaks (e.g. balances deducted prior to failed downstream steps without refund).
  Every mutation MUST fail the test suite with exit code 1. A suite that passes against any mutated defect is incomplete and rejected.
- **Explicit Failure Accumulator:** Use an explicit accumulator (`FAIL = 0`), incremented on any test failure.
- **Deterministic Exit:** The final statement of the test runner entrypoint must be `sys.exit(1 if FAIL else 0)` or `sys.exit(FAIL)`. Never allow a runner with failed assertions to return naturally with exit code 0.

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
- [ ] Collection guard active (`TESTS_RUN >= MINIMUM`).
- [ ] Final exit status strictly reflects the failure accumulator.
