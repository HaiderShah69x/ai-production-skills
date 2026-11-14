"""
fixtures/passive_test.py — Default AI-generated test suite (anti-pattern).

Demonstrates the "Exit Code 0 Illusion":
  - Only tests a valid happy-path transfer.
  - Wraps the critical negative-amount test in `except Exception: pass`,
    silently swallowing the failure signal.
  - Uses a vague `is not None` assertion that can never fail.
  - Exits with code 0 even though a severe business-logic bug is present.

This file is intentionally defective. It illustrates why passively-written
test suites provide false confidence and must be replaced by the patterns
in skills/02-adversarial-verification-harness/SKILL.md.

Target: fixtures/account_service.py (vulnerable)
"""

import sys
from account_service import Account


def test_valid_transfer():
    """Happy-path only: confirms a legitimate $20 transfer."""
    alice = Account("Alice", balance=100)
    bob   = Account("Bob",   balance=0)

    result = alice.transfer(20, bob)

    # Weak assertion: only checks the return value is truthy
    assert result is True,            "transfer() should return True"
    # Vague assertion: balance is 'not None' — always passes, proves nothing
    assert alice.balance is not None, "Alice should still have a balance"

    print("[passive] test_valid_transfer         PASSED", flush=True)


def test_negative_transfer():
    """
    Attempts to test the negative-amount exploit — but swallows the failure.

    The vulnerable account_service.py ALLOWS negative transfers, so
    alice.balance becomes 150 and bob.balance becomes -50.
    The assertion below would catch this IF it were allowed to run.
    However, the bare `except Exception: pass` swallows any AssertionError,
    and the test reports PASSED regardless.
    """
    alice = Account("Alice", balance=100)
    bob   = Account("Bob",   balance=0)

    try:
        result = alice.transfer(-50, bob)   # exploit: negative amount

        # This assertion SHOULD fail on the vulnerable service:
        #   result is True  (transfer "succeeds")
        #   alice.balance is 150 (inflated!)
        #   bob.balance is -50  (stolen!)
        assert result is False, \
            f"Expected transfer(-50) to be rejected; got result={result}, " \
            f"alice={alice.balance}, bob={bob.balance}"

    except Exception:
        # ANTI-PATTERN: swallows AssertionError → test always "passes"
        pass

    print("[passive] test_negative_transfer      PASSED  ← FALSE POSITIVE",
          flush=True)


def test_overdraft():
    """Checks that overdraft is rejected — this guard exists in the vulnerable version."""
    alice = Account("Alice", balance=100)
    bob   = Account("Bob",   balance=0)

    result = alice.transfer(500, bob)

    assert result is False, "Overdraft should be rejected"
    print("[passive] test_overdraft              PASSED", flush=True)


if __name__ == "__main__":
    print("=" * 60, flush=True)
    print("passive_test.py  →  account_service.py (VULNERABLE)", flush=True)
    print("=" * 60, flush=True)

    test_valid_transfer()
    test_negative_transfer()
    test_overdraft()

    print("-" * 60, flush=True)
    print("All passive tests passed.  Exit code: 0", flush=True)
    print("(BUG: negative-amount exploit is present but undetected!)",
          flush=True)
    print("=" * 60, flush=True)

    # FALSE EXIT CODE 0 — the negative-amount exploit was never caught
    sys.exit(0)
