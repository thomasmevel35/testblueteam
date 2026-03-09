from __future__ import annotations

from dataclasses import asdict, dataclass, field
from time import time
from typing import Any

from crypto.hash_utils import hash_dict, merkle_root


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    nonce: int
    public_key: str
    signature: str = ""
    tx_id: str = ""

    def payload(self) -> dict[str, Any]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "nonce": self.nonce,
            "public_key": self.public_key,
        }

    def compute_tx_id(self) -> str:
        self.tx_id = hash_dict(self.payload())
        return self.tx_id

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Transaction":
        return cls(**data)


@dataclass
class BlockHeader:
    index: int
    previous_hash: str
    merkle_root: str
    timestamp: float
    nonce: int
    difficulty: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Block:
    header: BlockHeader
    transactions: list[Transaction] = field(default_factory=list)
    block_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
        self.block_hash = hash_dict(payload)
        return self.block_hash

    @classmethod
    def create(
        cls,
        index: int,
        previous_hash: str,
        transactions: list[Transaction],
        difficulty: int,
    ) -> "Block":
        tx_dicts = [tx.to_dict() for tx in transactions]
        header = BlockHeader(
            index=index,
            previous_hash=previous_hash,
            merkle_root=merkle_root(tx_dicts),
            timestamp=time(),
            nonce=0,
            difficulty=difficulty,
        )
        return cls(header=header, transactions=transactions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Block":
        header = BlockHeader(**data["header"])
        transactions = [Transaction.from_dict(tx) for tx in data["transactions"]]
        return cls(header=header, transactions=transactions, block_hash=data.get("block_hash", ""))
