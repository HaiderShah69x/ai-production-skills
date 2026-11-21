"""
fixtures/banking_fixtures.py — Clean reference banking service.

Serves as the baseline target for dynamic AST mutation testing.
All balances and amounts are represented in integer cents ($100.00 = 10000 cents).
"""


class Account:
    def __init__(self, name: str, balance: int = 10000) -> None:
        self.name = name
        self.balance = balance  # in integer cents

    def transfer(self, amount: int, recipient: "Account") -> bool:
        """
        Transfer amount in integer cents from self to recipient.
        Strict validation rules:
          1. amount must be > 0 (rejects zero and negative)
          2. amount must be <= self.balance (rejects overdraft)
        Returns True on success, False on validation failure.
        """
        if amount <= 0:
            return False
        if amount > self.balance:
            return False

        self.balance -= amount
        recipient.balance += amount
        return True

    def __repr__(self) -> str:
        return f"Account({self.name!r}, balance={self.balance})"
