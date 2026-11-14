"""
fixtures/mutations.py — Account service with selectable bug mutations.

Used by the Mutation Kill Matrix to benchmark test suite vigilance.
All balances and amounts are stored in integer cents ($100.00 = 10000 cents).

Supported bug types:
  - "negative_bypass": Checks amount > balance, but omits amount <= 0 check.
  - "zero_bypass": Checks amount < 0, but permits amount == 0.
  - "state_leak": Deducts balance upfront, then simulates payment gateway failure
                  without rolling back / refunding state.
  - "fixed": Strictly validates amount > 0 and amount <= balance before atomic transfer.
"""


class AccountMutant:
    def __init__(self, name: str, balance: int = 10000, bug_type: str = "fixed") -> None:
        self.name = name
        self.balance = balance  # in cents
        self.bug_type = bug_type

    def transfer(self, amount: int, recipient: "AccountMutant") -> bool:
        """
        Transfer *amount* in cents to *recipient* with selectable bug injection.
        """
        if self.bug_type == "negative_bypass":
            # BUG: Checks overdraft, but omits non-positive check
            if amount > self.balance:
                return False
            self.balance -= amount
            recipient.balance += amount
            return True

        elif self.bug_type == "zero_bypass":
            # BUG: Rejects strictly negative amounts, but allows amount == 0
            if amount < 0:
                return False
            if amount > self.balance:
                return False
            self.balance -= amount
            recipient.balance += amount
            return True

        elif self.bug_type == "state_leak":
            # BUG: Deducts sender balance first, then simulates gateway failure without refund
            if amount <= 0:
                return False
            if amount > self.balance:
                return False
            self.balance -= amount  # State leaked before external gateway call!
            gateway_success = False  # simulated external gateway failure
            if not gateway_success:
                return False  # Failed, but sender balance was NOT restored!
            recipient.balance += amount
            return True

        elif self.bug_type == "fixed":
            # Production-grade: strict validation before state mutation
            if amount <= 0 or amount > self.balance:
                return False
            self.balance -= amount
            recipient.balance += amount
            return True

        else:
            raise ValueError(f"Unknown bug_type: {self.bug_type}")

    def __repr__(self) -> str:
        return f"AccountMutant({self.name!r}, balance={self.balance}, bug={self.bug_type!r})"
