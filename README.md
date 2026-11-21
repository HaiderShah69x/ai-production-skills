# AI Production Skills

An executable, adversarial benchmark suite for AI-generated code.

## Repository Vision

AI coding agents optimize for "happy path" syntax and pass superficial tests with mocked assertions while failing under true adversarial pressure. They produce code that compiles, returns correct outputs for golden inputs, and exits with code 0 — yet silently breaks under concurrent load, malicious payloads, boundary escapes, and privilege escalation vectors that any production deployment will face.

This repository defines a standard to expose those gaps: **every skill pairs an executable `SKILL.md` specification with a dual-target benchmark harness (`vulnerable_app` vs `hardened_app`) and an adversarial runner that verifies attack detection and failure modes.** The vulnerable target embodies the defects that default AI agents produce. The hardened target implements the invariants the skill mandates. The runner proves the difference is real, measurable, and reproducible.

## Implemented Skills Matrix

| Skill | Target Defects | Hardened Invariants |
|-------|---------------|---------------------|
| **01 — `concurrency-and-resource-bounds`** | Lost-update race conditions (check-then-act) under multi-process load, unbounded payload ingress, idle socket resource exhaustion, slow-drip connection leakage. | SQLite WAL-mode atomic updates (`UPDATE ... WHERE remaining > 0` with `cursor.rowcount == 1`), 1 MB streaming upload cap (`MAX_BODY_SIZE`), 2.0s socket read deadline, 4.0s cumulative request timeout (`ABSOLUTE_REQUEST_TIMEOUT`). |
| **02 — `adversarial-verification-harness`** | Mocked assertions, swallowed exception anti-patterns, test-skipping evasion, float precision drift in financial calculations. | Native `pytest` test suites, integer-cent currency units, Stage 1 Collection Guard (fails build if test count < 4), Stage 2 Dynamic AST Mutation Engine (>= 90% kill score across operator inversions, boolean flips, statement stripping, and return neutralization). |
| **03 — `untrusted-boundaries-and-auth`** | Horizontal/vertical IDOR, cross-tenant resource leakage, directory junction / symlink boundary escapes, Windows NTFS Alternate Data Streams (`file.txt:stream`), nested dictionary mass-assignment privilege escalation. | Cryptographically verified session-bound compound scoping (`tenant_id` + `owner_id`), canonical path resolution (`resolve()` + `is_relative_to()`), colon-rejection on filename boundaries, recursive nested schema allowlists (`ALLOWED_SCHEMA`). |

## Reproduction Commands

### Skill 01 — Concurrency & Resource Bounds Benchmark

```bash
python attacks/run_attacks_inline.py --target fixtures/vulnerable_app.py
python attacks/run_attacks_inline.py --target fixtures/hardened_app.py
```

### Skill 02 — Harness Mutation Matrix Benchmark

```bash
python attacks/run_skill02_benchmark.py
```

### Skill 03 — Auth & Boundary Benchmark

```bash
python attacks/run_skill03_benchmark.py
```

## Benchmark Invariant

A skill is only considered complete if all three conditions hold:

1. **Vulnerable target fails ≥ 80% of security test cases.** The adversarial runner must confirm that the default (AI-generated) implementation is exploitable under the attack suite.
2. **Hardened target passes 100% of test cases without mock overrides.** Every invariant defined in the `SKILL.md` must hold under real adversarial pressure — no mocked controls, no swallowed exceptions, no skipped assertions.
3. **Collection guard catches test tampering or skipped decorators (Exit Code 2).** If the test suite collects fewer tests than the minimum threshold, the runner terminates with exit code 2 before evaluation begins, preventing silent evasion through removed or disabled tests.
