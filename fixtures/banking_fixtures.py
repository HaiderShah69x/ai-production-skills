"""
fixtures/banking_fixtures.py — Clean reference banking service.

Serves as the baseline target for dynamic AST mutation testing.
All balances and amounts are represented in integer cents ($100.00 = 10000 cents).
"""

from typing import Dict, List


def calculate_fee(amount_cents: int) -> int:
    """Calculate transfer fee: transfers over $10.00 (1000 cents) incur a $1.00 (100 cents) fee."""
    if amount_cents > 1000:
        return 100
    return 0


def audit_log(event: str, account_id: str, amount_cents: int) -> Dict[str, object]:
    """Generate an immutable audit log entry for a transaction event."""
    return {"event": event, "account_id": account_id, "amount": amount_cents}


class Account:
    def __init__(self, name: str, balance: int = 10000) -> None:
        self.name = name
        self.balance = balance  # in integer cents
        self.audit_records: List[Dict[str, object]] = []

    def transfer(self, amount: int, recipient: "Account") -> bool:
        """
        Transfer amount in integer cents from self to recipient.
        Strict validation rules:
          1. amount must be > 0 (rejects zero and negative)
          2. total deduction (amount + fee) must be <= self.balance (rejects overdraft)
        Returns True on success, False on validation failure.
        """
        if amount <= 0:
            return False
        fee = calculate_fee(amount)
        total = amount + fee
        if total > self.balance:
            return False

        self.balance -= total
        recipient.balance += amount
        self.audit_records.append(audit_log("transfer_out", self.name, amount))
        recipient.audit_records.append(audit_log("transfer_in", recipient.name, amount))
        return True

    def __repr__(self) -> str:
        return f"Account({self.name!r}, balance={self.balance})"


def transfer(source: Account, target: Account, amount_cents: int) -> bool:
    """Module-level transfer delegator."""
    return source.transfer(amount_cents, target)
