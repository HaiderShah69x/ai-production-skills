"""
tests/test_harness_adversarial.py — Adversarial verification suite for banking operations.

Governed strictly by skills/adversarial-verification-harness/SKILL.md:
  - Invariant 1: Negative verification first (negative amount, zero amount, overdraft).
  - Invariant 2: Exact literal assertions and integer cents ($100.00 = 10000 cents).
  - Invariant 3: Zero swallowed failures.
  - Invariant 4: Real domain components evaluated without mocks.
  - State Immutability Rule: On any failed transfer, sender and receiver balances
    must undergo zero modification.

The target Account class is loaded dynamically:
  - If MUTANT_MODULE_PATH is set: dynamically loaded from the generated AST mutant.
  - Otherwise: loaded from fixtures.banking_fixtures.Account (clean baseline).
"""

import importlib.util
import os
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def get_account_class():
    mutant_path = os.environ.get("MUTANT_MODULE_PATH")
    if mutant_path and os.path.exists(mutant_path):
        spec = importlib.util.spec_from_file_location("mutated_account_module", mutant_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module.Account
    from fixtures.banking_fixtures import Account
    return Account


def get_account(name: str, balance: int = 10000):
    account_cls = get_account_class()
    return account_cls(name=name, balance=balance)


def test_rejects_negative_transfer():
    """
    Negative Test 1: Transfer of -5000 cents (-$50.00) must return False.
    State Immutability: Alice balance remains exactly 10000 cents, Bob remains 0.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(-5000, bob)

    assert result is False, f"Expected False for negative transfer, got {result!r}"
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

    assert result is False, f"Expected False for zero transfer, got {result!r}"
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

    assert result is False, f"Expected False for overdraft, got {result!r}"
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

    assert result is True, f"Expected True for valid transfer, got {result!r}"
    assert alice.balance == 8000, f"Alice balance incorrect: expected 8000, got {alice.balance}"
    assert bob.balance == 2000, f"Bob balance incorrect: expected 2000, got {bob.balance}"
    assert repr(alice) == "Account('Alice', balance=8000)", f"Alice repr incorrect: got {repr(alice)!r}"


def test_exact_balance_transfer_succeeds():
    """
    Boundary Test: Transfer of exactly 10000 cents ($100.00, full balance).
    Boundary Guard: amount <= self.balance permits transferring entire balance.
    Mutant #6 (boundary_5_Boundary_Gt_to_GtE: amount >= self.balance -> rejects exact balance) is killed.
    """
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(10000, bob)

    assert result is True, f"Expected True for exact full balance transfer, got {result!r}"
    assert alice.balance == 0, f"Alice balance incorrect: expected 0, got {alice.balance}"
    assert bob.balance == 10000, f"Bob balance incorrect: expected 10000, got {bob.balance}"
