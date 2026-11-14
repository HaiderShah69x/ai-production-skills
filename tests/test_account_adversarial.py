"""
tests/test_account_adversarial.py — Adversarial pytest suite for Account service.

Governed strictly by skills/adversarial-verification-harness/SKILL.md:
  - Invariant 1: Negative verification first (negative amount, zero amount, overdraft).
  - Invariant 2: Exact literal assertions and integer cents ($100.00 = 10000 cents).
  - Invariant 3: Zero swallowed failures.
  - Invariant 4: Real domain components evaluated without mocks.
  - State Immutability Rule: On any failed transfer, sender and receiver balances
    must undergo zero modification.

The target Account class is dynamically configured via the environment variable
ACCOUNT_BUG_TYPE (defaults to "fixed").
"""

import os
import sys
import pathlib

# Ensure workspace root is in sys.path
REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.mutations import AccountMutant


def get_account(name: str, balance: int = 10000) -> AccountMutant:
    bug_type = os.environ.get("ACCOUNT_BUG_TYPE", "fixed")
    return AccountMutant(name=name, balance=balance, bug_type=bug_type)


def test_rejects_negative_transfer():
    """
    Negative Test 1: Transfer of -5000 cents (-$50.00) must return False.
    State Immutability: Alice balance remains exactly 10000 cents, Bob remains 0.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(-5000, bob)

    assert result is False, f"Expected False for negative transfer, got {result}"
    assert alice.balance == 10000, f"Alice balance leaked or inflated: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered on rejected transfer: expected 0, got {bob.balance}"


def test_rejects_zero_transfer():
    """
    Negative Test 2: Transfer of 0 cents must return False.
    State Immutability: Alice balance remains exactly 10000 cents, Bob remains 0.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(0, bob)

    assert result is False, f"Expected False for zero transfer, got {result}"
    assert alice.balance == 10000, f"Alice balance altered on zero transfer: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered on zero transfer: expected 0, got {bob.balance}"


def test_rejects_overdraft_and_preserves_state():
    """
    Negative Test 3: Transfer of 50000 cents (exceeding 10000 balance) must return False.
    State Immutability: Alice balance remains exactly 10000 cents, Bob remains 0.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(50000, bob)

    assert result is False, f"Expected False for overdraft, got {result}"
    assert alice.balance == 10000, f"Alice balance altered on overdraft: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered on overdraft: expected 0, got {bob.balance}"


def test_valid_transfer_succeeds():
    """
    Positive Test: Legitimate transfer of 2000 cents ($20.00) must succeed.
    Parity Guard: Alice balance transitions to 8000, Bob balance transitions to 2000.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(2000, bob)

    assert result is True, f"Expected True for valid transfer, got {result}"
    assert alice.balance == 8000, f"Alice balance incorrect: expected 8000, got {alice.balance}"
    assert bob.balance == 2000, f"Bob balance incorrect: expected 2000, got {bob.balance}"
