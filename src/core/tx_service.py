from __future__ import annotations

from core.models import Transaction
from crypto.hash_utils import hash_dict
from crypto.wallet import Wallet, sign_message


def create_signed_transaction(wallet: Wallet, recipient: str, amount: int, nonce: int) -> Transaction:
    tx = Transaction(
        sender=wallet.address,
        recipient=recipient,
        amount=amount,
        nonce=nonce,
        public_key=wallet.public_key_pem,
    )
    message = hash_dict(tx.payload()).encode("utf-8")
    tx.signature = sign_message(wallet.private_key_pem, message)
    tx.compute_tx_id()
    return tx
