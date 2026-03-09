from core.blockchain import Blockchain
from core.models import Block
from core.tx_service import create_signed_transaction
from crypto.wallet import generate_wallet


def test_transaction_nonce_and_balance_validation() -> None:
    chain = Blockchain(difficulty=2)
    alice = generate_wallet()
    bob = generate_wallet()

    chain.state.balances[alice.address] = 100

    tx = create_signed_transaction(alice, bob.address, amount=25, nonce=0)
    assert chain.add_transaction(tx)

    bad_nonce = create_signed_transaction(alice, bob.address, amount=25, nonce=2)
    assert not chain.add_transaction(bad_nonce)


def test_mine_and_validate_chain_integrity() -> None:
    chain = Blockchain(difficulty=2)
    miner = generate_wallet()

    block = chain.mine_pending_transactions(miner.address)
    assert block.block_hash.startswith("00")
    assert chain.validate_chain(chain.chain)

    tampered = Block.from_dict(block.to_dict())
    tampered.transactions[0].amount = 999
    tampered.compute_hash()
    candidate = [*chain.chain[:-1], tampered]
    assert not chain.validate_chain(candidate)


def test_longest_chain_rule() -> None:
    a = Blockchain(difficulty=1)
    b = Blockchain(difficulty=1)
    miner = generate_wallet()

    a.mine_pending_transactions(miner.address)
    b.mine_pending_transactions(miner.address)
    b.mine_pending_transactions(miner.address)

    assert a.replace_chain(b.chain)
    assert len(a.chain) == len(b.chain)
