"""
fixtures/adversarial_test.py — Skill-02-governed test suite.

Implements all invariants from
skills/adversarial-verification-harness/SKILL.md:

  Invariant 1 — Adversarial Coverage & Parity
      Negative cases tested first with exact rejections and zero state mutation.
      Positive cases verify functional parity (fails any "deny-all" stub).

  Invariant 2 — Strict Assertion Contracts
      Exact literals, integer cents ($100.00 = 10000 cents), no vague checks.

  Invariant 3 — Zero Swallowed Failures
      No empty except blocks; explicit failure recording.

  Invariant 4 — System Under Test Integrity
      Real domain components evaluated without mocks or monkeypatching.

  Invariant 5 — Harness Failure Propagation & Collection Guards
      Tracks TESTS_RUN and FAIL.
      If TESTS_RUN < 3, fails with code 2.
      Exits with code 1 if FAIL else 0.

Usage:
    python fixtures/adversarial_test.py                   # tests account_service (vulnerable)
    python fixtures/adversarial_test.py --fixed           # tests fixed_account_service (hardened)

Exit codes:
    0 — all assertions passed
    1 — one or more assertions failed
    2 — collection guard failure (too few tests run)
"""

import sys
import argparse

# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--fixed", action="store_true",
                    help="Test fixed_account_service instead of account_service")
cli_args, _ = parser.parse_known_args()

if cli_args.fixed:
    from fixed_account_service import Account
    TARGET_LABEL = "fixed_account_service.py (HARDENED)"
else:
    from account_service import Account
    TARGET_LABEL = "account_service.py (VULNERABLE)"

# ---------------------------------------------------------------------------
# Invariant 5 — Execution and failure tracking
# ---------------------------------------------------------------------------
TESTS_RUN = 0
FAIL = 0


def record_failure(msg: str) -> None:
    """Increment FAIL counter and print a [FAIL] line. Never swallows."""
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}", flush=True)


def assert_exact(actual, expected, label: str) -> None:
    """Assert actual == expected; record failure with full detail on mismatch."""
    if actual != expected:
        record_failure(f"{label}: expected {expected!r}, got {actual!r}")
    else:
        print(f"  [PASS] {label}", flush=True)


def assert_false(value: bool, label: str) -> None:
    """Assert value is strictly False."""
    assert_exact(value, False, label)


def assert_true(value: bool, label: str) -> None:
    """Assert value is strictly True."""
    assert_exact(value, True, label)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_neg1_negative_amount_rejected():
    """
    NEGATIVE TEST 1 — negative transfer amount must be rejected.
    Amount: -5000 cents (-$50.00).
    Expected: returns False, Alice remains 10000 cents, Bob remains 0 cents.
    """
    global TESTS_RUN
    TESTS_RUN += 1

    alice = Account("Alice", balance=10000)
    bob   = Account("Bob",   balance=0)

    result = alice.transfer(-5000, bob)

    # Invariant 1 & 2: exact return value + zero state mutation check
    assert_false(result, "transfer(-5000) must return False")
    assert_exact(alice.balance, 10000,
                 "Alice.balance unchanged after rejected negative transfer")
    assert_exact(bob.balance, 0,
                 "Bob.balance unchanged after rejected negative transfer")


def test_neg2_zero_amount_rejected():
    """
    NEGATIVE TEST 2 — zero transfer amount must be rejected.
    Amount: 0 cents.
    Expected: returns False, Alice remains 10000 cents, Bob remains 0 cents.
    """
    global TESTS_RUN
    TESTS_RUN += 1

    alice = Account("Alice", balance=10000)
    bob   = Account("Bob",   balance=0)

    result = alice.transfer(0, bob)

    assert_false(result, "transfer(0) must return False")
    assert_exact(alice.balance, 10000,
                 "Alice.balance unchanged after rejected zero transfer")
    assert_exact(bob.balance, 0,
                 "Bob.balance unchanged after rejected zero transfer")


def test_pos1_valid_transfer_succeeds():
    """
    POSITIVE TEST 1 — legitimate transfer within balance must succeed.
    Amount: 2000 cents ($20.00).
    Expected: returns True, Alice balance drops to 8000, Bob balance rises to 2000.
    """
    global TESTS_RUN
    TESTS_RUN += 1

    alice = Account("Alice", balance=10000)
    bob   = Account("Bob",   balance=0)

    result = alice.transfer(2000, bob)

    assert_true(result, "transfer(2000) must return True")
    assert_exact(alice.balance, 8000,
                 "Alice.balance = 8000 after $20 transfer")
    assert_exact(bob.balance, 2000,
                 "Bob.balance = 2000 after $20 transfer")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TESTS = [
    test_neg1_negative_amount_rejected,
    test_neg2_zero_amount_rejected,
    test_pos1_valid_transfer_succeeds,
]


def run_all() -> None:
    for test_fn in TESTS:
        print(f"\n--- {test_fn.__name__} ---", flush=True)
        try:
            test_fn()
        except Exception as exc:
            record_failure(
                f"Unexpected exception in {test_fn.__name__}: "
                f"{type(exc).__name__}: {exc}"
            )
            raise


if __name__ == "__main__":
    print("=" * 60, flush=True)
    print(f"adversarial_test.py  →  {TARGET_LABEL}", flush=True)
    print("Skill: adversarial-verification-harness", flush=True)
    print("=" * 60, flush=True)

    run_all()

    print("\n" + "=" * 60, flush=True)
    print(f"Total Tests Executed: {TESTS_RUN}", flush=True)

    # Invariant 5: Collection Guard
    if TESTS_RUN < 3:
        print(f"COLLECTION GUARD FAILURE: Only {TESTS_RUN} tests executed (minimum 3 required).", flush=True)
        sys.exit(2)

    if FAIL == 0:
        print("All adversarial checks PASSED.  Exit code: 0", flush=True)
    else:
        print(f"{FAIL} adversarial check(s) FAILED.  Exit code: 1", flush=True)
    print("=" * 60, flush=True)

    # Invariant 5: Deterministic Exit Status
    sys.exit(1 if FAIL else 0)
