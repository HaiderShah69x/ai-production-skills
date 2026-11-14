"""
fixtures/fixed_account_service.py — Hardened account transfer service.

Closes the negative-amount exploit present in account_service.py by
enforcing the full validation contract on every transfer:

  - amount must be > 0          ← explicit guard added (rejects <= 0)
  - amount must be <= balance   ← retained from vulnerable version

All balances and amounts are represented in integer cents ($100.00 = 10000 cents).
Both conditions are checked atomically before any state mutation.
"""


class Account:
    def __init__(self, name: str, balance: int = 10000) -> None:
        self.name    = name
        self.balance = balance  # stored in integer cents

    def transfer(self, amount: int, recipient: "Account") -> bool:
        """
        Transfer *amount* in integer cents from self to *recipient*.

        Returns True on success, False on any validation failure.
        Never raises; never mutates state on a rejected transfer.

        Validation contract (all conditions checked before mutation):
          1. amount > 0            — rejects zero and negative amounts
          2. amount <= self.balance — rejects overdraft
        """
        # Guard 1: reject non-positive amounts (closes the exploit)
        if amount <= 0:
            return False

        # Guard 2: reject overdraft
        if amount > self.balance:
            return False

        # Both guards passed — mutation is safe
        self.balance      -= amount
        recipient.balance += amount
        return True

    def __repr__(self) -> str:
        return f"Account({self.name!r}, balance={self.balance})"
