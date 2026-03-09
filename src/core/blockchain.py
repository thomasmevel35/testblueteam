from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.models import Block, Transaction
from crypto.hash_utils import hash_dict, merkle_root
from crypto.wallet import derive_address, verify_signature


@dataclass
class ChainState:
    balances: dict[str, int] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)


class Blockchain:
    def __init__(self, difficulty: int = 3, mining_reward: int = 50):
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.chain: list[Block] = [self._create_genesis()]
        self.mempool: list[Transaction] = []
        self.seen_tx_ids: set[str] = set()
        self.state = ChainState()

    def _create_genesis(self) -> Block:
        genesis = Block.create(index=0, previous_hash="0" * 64, transactions=[], difficulty=self.difficulty)
        genesis.compute_hash()
        return genesis

    def tip(self) -> Block:
        return self.chain[-1]

    def add_transaction(self, tx: Transaction) -> bool:
        tx.compute_tx_id()
        if tx.tx_id in self.seen_tx_ids:
            return False
        if not self.validate_transaction(tx):
            return False
        self.seen_tx_ids.add(tx.tx_id)
        self.mempool.append(tx)
        return True

    def validate_transaction(self, tx: Transaction) -> bool:
        if tx.amount <= 0:
            return False
        if derive_address(tx.public_key) != tx.sender:
            return False
        message = hash_dict(tx.payload()).encode("utf-8")
        if not verify_signature(tx.public_key, message, tx.signature):
            return False

        expected_nonce = self.state.nonces.get(tx.sender, 0)
        if tx.nonce != expected_nonce:
            return False

        balance = self.state.balances.get(tx.sender, 0)
        if tx.sender != "COINBASE" and balance < tx.amount:
            return False

        return True

    def mine_pending_transactions(self, miner_address: str) -> Block:
        reward_tx = Transaction(
            sender="COINBASE",
            recipient=miner_address,
            amount=self.mining_reward,
            nonce=0,
            public_key="COINBASE",
            signature="COINBASE",
        )
        reward_tx.compute_tx_id()

        transactions = [reward_tx, *self.mempool]
        block = Block.create(
            index=len(self.chain),
            previous_hash=self.tip().block_hash,
            transactions=transactions,
            difficulty=self.difficulty,
        )
        self._proof_of_work(block)
        self.append_block(block)
        self.mempool = []
        return block

    def _proof_of_work(self, block: Block) -> None:
        target = "0" * block.header.difficulty
        while True:
            h = block.compute_hash()
            if h.startswith(target):
                break
            block.header.nonce += 1

    def append_block(self, block: Block) -> bool:
        if not self.validate_new_block(block, self.tip()):
            return False
        self.chain.append(block)
        self._apply_block(block)
        return True

    def _apply_block(self, block: Block) -> None:
        for tx in block.transactions:
            if tx.sender != "COINBASE":
                self.state.balances[tx.sender] = self.state.balances.get(tx.sender, 0) - tx.amount
                self.state.nonces[tx.sender] = self.state.nonces.get(tx.sender, 0) + 1
            self.state.balances[tx.recipient] = self.state.balances.get(tx.recipient, 0) + tx.amount

    def validate_new_block(self, block: Block, previous_block: Block) -> bool:
        if block.header.previous_hash != previous_block.block_hash:
            return False
        if block.header.index != previous_block.header.index + 1:
            return False
        if block.compute_hash() != block.block_hash:
            return False
        if not block.block_hash.startswith("0" * block.header.difficulty):
            return False
        tx_dicts = [tx.to_dict() for tx in block.transactions]
        if block.header.merkle_root != merkle_root(tx_dicts):
            return False
        return True

    def validate_chain(self, candidate_chain: list[Block]) -> bool:
        if not candidate_chain:
            return False
        for i in range(1, len(candidate_chain)):
            if not self.validate_new_block(candidate_chain[i], candidate_chain[i - 1]):
                return False
        return True

    def replace_chain(self, candidate_chain: list[Block]) -> bool:
        if len(candidate_chain) <= len(self.chain):
            return False
        if not self.validate_chain(candidate_chain):
            return False
        self.chain = candidate_chain
        self._rebuild_state()
        return True

    def _rebuild_state(self) -> None:
        self.state = ChainState()
        for block in self.chain[1:]:
            self._apply_block(block)

    def export_chain(self) -> list[dict[str, Any]]:
        return [block.to_dict() for block in self.chain]

    @staticmethod
    def import_chain(serialized: list[dict[str, Any]]) -> list[Block]:
        return [Block.from_dict(item) for item in serialized]
