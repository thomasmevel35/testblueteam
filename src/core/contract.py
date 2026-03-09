from __future__ import annotations


def execute_transfer(state: dict[str, int], sender: str, recipient: str, amount: int) -> dict[str, int]:
    new_state = dict(state)
    if amount < 0:
        raise ValueError("amount must be >= 0")
    if new_state.get(sender, 0) < amount:
        raise ValueError("insufficient funds")
    new_state[sender] = new_state.get(sender, 0) - amount
    new_state[recipient] = new_state.get(recipient, 0) + amount
    return new_state
