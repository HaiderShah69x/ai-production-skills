"""
fixtures/account_service.py — Vulnerable account transfer service.

Demonstrates a canonical business-logic blind spot:
  DEFECT: Validates amount > balance (prevents overdraft) but
          omits amount <= 0 check (allows negative-amount transfers).

All balances and amounts are represented in integer cents ($100.00 = 10000 cents).

A negative transfer STEALS funds from the recipient and INFLATES the
sender's balance — a classic signed-integer exploitation pattern.

DO NOT use this in production. It is an intentional attack target.
"""


class Account:
    def __init__(self, name: str, balance: int = 10000) -> None:
        self.name    = name
        self.balance = balance  # stored in integer cents

    def transfer(self, amount: int, recipient: "Account") -> bool:
        """
        Transfer *amount* in integer cents from self to *recipient*.

        INTENDED invariants (only partially implemented):
          - amount must be > 0          ← MISSING CHECK (the defect)
          - amount must be <= balance   ← present
          - on success: self.balance -= amount; recipient.balance += amount

        DEFECT: negative amounts pass the balance check and reverse the
        direction of the transfer, inflating self.balance and draining
        recipient.balance.
        """
        # FLAW: only guards against overdraft; does not reject amount <= 0
        if amount > self.balance:
            return False

        self.balance      -= amount   # negative amount → self.balance GROWS
        recipient.balance += amount   # negative amount → recipient.balance SHRINKS
        return True

    def __repr__(self) -> str:
        return f"Account({self.name!r}, balance={self.balance})"
