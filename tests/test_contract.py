from core.contract import execute_transfer


def test_contract_execution_is_deterministic() -> None:
    initial = {"alice": 10, "bob": 0}
    out1 = execute_transfer(initial, "alice", "bob", 3)
    out2 = execute_transfer(initial, "alice", "bob", 3)
    assert out1 == out2 == {"alice": 7, "bob": 3}
