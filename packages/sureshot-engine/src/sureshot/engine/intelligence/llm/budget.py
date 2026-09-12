from __future__ import annotations

from dataclasses import dataclass, field


class BudgetExceeded(Exception):
    """The scan's token allowance is spent."""


@dataclass
class TokenBudget:
    max_input_tokens: int = 2_000_000
    max_output_tokens: int = 400_000
    spent_input: int = field(default=0, init=False)
    spent_output: int = field(default=0, init=False)

    def check(self, estimated_input: int) -> None:
        if self.spent_input + estimated_input > self.max_input_tokens:
            raise BudgetExceeded(
                f"input budget exhausted: {self.spent_input}/{self.max_input_tokens}"
            )
        if self.spent_output >= self.max_output_tokens:
            raise BudgetExceeded("output budget exhausted")

    def record(self, input_tokens: int, output_tokens: int) -> None:
        self.spent_input += input_tokens
        self.spent_output += output_tokens