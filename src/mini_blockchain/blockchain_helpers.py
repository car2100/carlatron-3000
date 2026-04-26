from __future__ import annotations

import secrets

from .crypto.alg_aes_gcm import aes_gcm_encrypt
from .crypto.alg_crypto_common import b64e, canonical_json_bytes
from .crypto.alg_hash import sha256_hex
from .crypto.alg_kdf import derive_key_pbkdf2, generate_salt
from .crypto.alg_totp import generate_totp_secret


def make_block_hash(
    index: int,
    owner: str,
    timestamp: str,
    hash_prev: str,
    nonce_b64: str,
    ciphertext_b64: str,
) -> str:
    payload = {
        "index": index,
        "owner": owner,
        "timestamp": timestamp,
        "hash_prev": hash_prev,
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ciphertext_b64,
    }
    return sha256_hex(canonical_json_bytes(payload))


def demo_user_bundle(password: str) -> dict[str, str]:
    """
    Exemplo de cadastro/login:
    1) deriva KEK da senha
    2) cria bundle com totp_secret + user_data_key
    3) cifra o bundle em AES-GCM
    """
    salt = generate_salt(16)
    kek = derive_key_pbkdf2(password, salt, iterations=300_000, length=32, hash_name="sha256")

    bundle = {
        "totp_secret": generate_totp_secret(),
        "user_data_key_b64": b64e(secrets.token_bytes(32)),
    }
    blob = aes_gcm_encrypt(kek, canonical_json_bytes(bundle))

    return {
        "kdf": "pbkdf2",
        "salt_b64": b64e(salt),
        "bundle_nonce_b64": blob.nonce_b64,
        "bundle_ciphertext_b64": blob.ciphertext_b64,
    }
