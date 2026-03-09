from crypto.hash_utils import merkle_root
from crypto.wallet import generate_wallet, sign_message, verify_signature


def test_sign_and_verify_roundtrip() -> None:
    wallet = generate_wallet()
    message = b"hello-chain"
    signature = sign_message(wallet.private_key_pem, message)
    assert verify_signature(wallet.public_key_pem, message, signature)


def test_merkle_root_stable() -> None:
    txs = [{"a": 1}, {"b": 2}, {"c": 3}]
    root1 = merkle_root(txs)
    root2 = merkle_root(txs)
    assert root1 == root2
