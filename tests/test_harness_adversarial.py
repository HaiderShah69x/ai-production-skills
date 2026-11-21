"""
tests/test_harness_adversarial.py — Adversarial verification suite for banking operations.

Governed strictly by skills/adversarial-verification-harness/SKILL.md:
  - Invariant 1: Negative verification first (negative amount, zero amount, overdraft).
  - Invariant 2: Exact literal assertions and integer cents ($100.00 = 10000 cents).
  - Invariant 3: Zero swallowed failures.
  - Invariant 4: Real domain components evaluated without mocks (multi-method banking service).
  - State Immutability Rule: On any failed transfer, sender and receiver balances
    and audit records must undergo zero modification.

The target banking module is loaded dynamically:
  - If MUTANT_MODULE_PATH is set: dynamically loaded from the generated AST mutant.
  - Otherwise: loaded from fixtures.banking_fixtures (clean baseline).
"""

import importlib.util
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def get_banking_module():
    mutant_path = os.environ.get("MUTANT_MODULE_PATH")
    if mutant_path and os.path.exists(mutant_path):
        spec = importlib.util.spec_from_file_location("mutated_banking_module", mutant_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    import fixtures.banking_fixtures as mod
    return mod


def get_account_class():
    return get_banking_module().Account


def get_account(name: str, balance: int = 10000):
    account_cls = get_account_class()
    return account_cls(name=name, balance=balance)


def test_rejects_negative_transfer():
    """Negative Test 1: Transfer of -5000 cents must return False with zero state modification."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(-5000, bob)

    assert result is False, f"Expected False for negative transfer, got {result!r}"
    assert alice.balance == 10000, f"Alice balance altered: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered: expected 0, got {bob.balance}"
    assert len(alice.audit_records) == 0, "Audit log emitted for rejected negative transfer"
    assert len(bob.audit_records) == 0, "Audit log emitted for rejected negative transfer"


def test_rejects_zero_transfer():
    """Negative Test 2: Transfer of 0 cents must return False with zero state modification."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(0, bob)

    assert result is False, f"Expected False for zero transfer, got {result!r}"
    assert alice.balance == 10000, f"Alice balance altered on zero transfer: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered on zero transfer: expected 0, got {bob.balance}"
    assert len(alice.audit_records) == 0, "Audit log emitted on zero transfer"
    assert len(bob.audit_records) == 0, "Audit log emitted on zero transfer"


def test_rejects_overdraft_and_preserves_state():
    """Negative Test 3: Transfer of 50000 cents (exceeding 10000 balance) must return False."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(50000, bob)

    assert result is False, f"Expected False for overdraft, got {result!r}"
    assert alice.balance == 10000, f"Alice balance altered on overdraft: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered on overdraft: expected 0, got {bob.balance}"
    assert len(alice.audit_records) == 0, "Audit log emitted on overdraft"
    assert len(bob.audit_records) == 0, "Audit log emitted on overdraft"


def test_valid_transfer_succeeds_and_deducts_fee():
    """Positive Test: Transfer of 2000 cents ($20.00) incurs $1.00 (100 cents) fee and emits audit logs."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(2000, bob)

    assert result is True, f"Expected True for valid transfer, got {result!r}"
    assert alice.balance == 7900, f"Alice balance incorrect (expected 10000 - 2100 = 7900): got {alice.balance}"
    assert bob.balance == 2000, f"Bob balance incorrect (expected 2000): got {bob.balance}"
    assert repr(alice) == "Account('Alice', balance=7900)", f"Alice repr incorrect: got {repr(alice)!r}"

    assert len(alice.audit_records) == 1, f"Expected 1 audit record on Alice, got {len(alice.audit_records)}"
    assert alice.audit_records[0] == {"event": "transfer_out", "account_id": "Alice", "amount": 2000}
    assert len(bob.audit_records) == 1, f"Expected 1 audit record on Bob, got {len(bob.audit_records)}"
    assert bob.audit_records[0] == {"event": "transfer_in", "account_id": "Bob", "amount": 2000}


def test_small_transfer_incurs_zero_fee():
    """Transfer of 500 cents (<= 1000 cents) incurs zero fee."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(500, bob)

    assert result is True, f"Expected True for small transfer, got {result!r}"
    assert alice.balance == 9500, f"Alice balance incorrect (expected 9500): got {alice.balance}"
    assert bob.balance == 500, f"Bob balance incorrect (expected 500): got {bob.balance}"
    assert len(alice.audit_records) == 1
    assert alice.audit_records[0] == {"event": "transfer_out", "account_id": "Alice", "amount": 500}


def test_calculate_fee_boundaries():
    """Verify fee calculation boundaries directly."""
    mod = get_banking_module()
    assert mod.calculate_fee(1000) == 0, f"Boundary 1000 cents should have 0 fee, got {mod.calculate_fee(1000)}"
    assert mod.calculate_fee(1001) == 100, f"1001 cents should incur 100 fee, got {mod.calculate_fee(1001)}"
    assert mod.calculate_fee(999) == 0, f"999 cents should have 0 fee, got {mod.calculate_fee(999)}"
    assert mod.calculate_fee(0) == 0, f"0 cents should have 0 fee, got {mod.calculate_fee(0)}"


def test_exact_balance_transfer_with_fee():
    """Transfer of exact full balance including fee."""
    alice = get_account("Alice", balance=10100)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(10000, bob)

    assert result is True, f"Expected True for full balance transfer with fee, got {result!r}"
    assert alice.balance == 0, f"Alice balance incorrect: expected 0, got {alice.balance}"
    assert bob.balance == 10000, f"Bob balance incorrect: expected 10000, got {bob.balance}"


def test_insufficient_balance_for_fee_rejects():
    """Transfer where balance covers amount but not amount + fee."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(10000, bob)

    assert result is False, f"Expected False when fee exceeds remaining balance, got {result!r}"
    assert alice.balance == 10000, f"Alice balance altered: expected 10000, got {alice.balance}"
    assert bob.balance == 0, f"Bob balance altered: expected 0, got {bob.balance}"
    assert len(alice.audit_records) == 0, "Audit record emitted on failed fee transfer"


def test_audit_log_format_and_immutability():
    """Verify audit_log function return structure and argument ordering."""
    mod = get_banking_module()
    entry = mod.audit_log("custom_event", "acc_42", 1234)
    assert entry == {"event": "custom_event", "account_id": "acc_42", "amount": 1234}


def test_module_level_transfer_delegation():
    """Verify module-level transfer function delegation."""
    mod = get_banking_module()
    alice = mod.Account("Alice", balance=10000)
    bob = mod.Account("Bob", balance=0)

    res = mod.transfer(alice, bob, 500)
    assert res is True
    assert alice.balance == 9500
    assert bob.balance == 500


def test_default_account_balance():
    """Default balance invariant: unassigned initial balance is exactly 10000 cents ($100.00)."""
    mod = get_banking_module()
    charlie = mod.Account("Charlie")
    assert charlie.balance == 10000, f"Default balance must be 10000, got {charlie.balance}"


def test_minimum_transfer_one_cent_succeeds():
    """Minimum valid positive transfer of 1 cent must succeed."""
    alice = get_account("Alice", balance=10000)
    bob = get_account("Bob", balance=0)

    result = alice.transfer(1, bob)

    assert result is True, "1 cent transfer must succeed"
    assert alice.balance == 9999, f"Alice balance incorrect: {alice.balance}"
    assert bob.balance == 1, f"Bob balance incorrect: {bob.balance}"
    assert len(alice.audit_records) == 1
    assert alice.audit_records[0] == {"event": "transfer_out", "account_id": "Alice", "amount": 1}
    assert len(bob.audit_records) == 1
    assert bob.audit_records[0] == {"event": "transfer_in", "account_id": "Bob", "amount": 1}
