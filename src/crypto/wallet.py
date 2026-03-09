from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass
class Wallet:
    private_key_pem: str
    public_key_pem: str
    address: str


def generate_wallet() -> Wallet:
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    address = derive_address(public_pem)
    return Wallet(private_pem, public_pem, address)


def derive_address(public_key_pem: str) -> str:
    digest = hashlib.sha256(public_key_pem.encode("utf-8")).digest()
    return binascii.hexlify(digest[:20]).decode("ascii")


def sign_message(private_key_pem: str, message: bytes) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return binascii.hexlify(signature).decode("ascii")


def verify_signature(public_key_pem: str, message: bytes, signature_hex: str) -> bool:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    signature = binascii.unhexlify(signature_hex)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001
        return False
