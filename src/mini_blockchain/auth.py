from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from .crypto.alg_aes_gcm import aes_gcm_decrypt, aes_gcm_encrypt
from .crypto.alg_crypto_common import CryptoError, b64d, b64e, canonical_json_bytes
from .crypto.alg_kdf import derive_key_pbkdf2, derive_key_scrypt, generate_salt
from .crypto.alg_totp import generate_totp_secret, provisioning_uri, verify_totp
from .storage import load_users, save_users

PBKDF2_ITERATIONS = 300_000


@dataclass(frozen=True)
class Session:
    username: str
    user_data_key: bytes
    totp_secret: str


def _derive_kek(record: dict, password: str) -> bytes:
    salt = b64d(record["salt_password_b64"])
    kdf_name = record.get("kdf", "pbkdf2")

    if kdf_name == "pbkdf2":
        params = record.get("kdf_params", {})
        iterations = int(params.get("iterations", PBKDF2_ITERATIONS))
        hash_name = params.get("hash", "sha256")
        return derive_key_pbkdf2(password, salt, iterations=iterations, length=32, hash_name=hash_name)

    if kdf_name == "scrypt":
        params = record.get("kdf_params", {})
        return derive_key_scrypt(
            password,
            salt,
            n=int(params.get("n", 2048)),
            r=int(params.get("r", 8)),
            p=int(params.get("p", 1)),
            length=32,
        )

    raise ValueError("Unsupported KDF")


def register_user(username: str, password: str, kdf_name: str = "pbkdf2") -> dict[str, str]:
    """
    Cadastra usuario e retorna dados de onboarding do TOTP para demonstracao.

    Seguranca:
    - senha nunca e salva em claro;
    - KEK vem de KDF com salt;
    - segredos do usuario sao armazenados em bundle AES-GCM.
    """
    username = username.strip()
    if not username:
        raise ValueError("Username is required")
    if len(password) < 6:
        raise ValueError("Use uma senha com pelo menos 6 caracteres")

    users = load_users()
    if username in users:
        raise ValueError("Usuario ja existe")

    salt = generate_salt(16)
    if kdf_name == "pbkdf2":
        kek = derive_key_pbkdf2(password, salt, iterations=PBKDF2_ITERATIONS, length=32, hash_name="sha256")
        kdf_params = {"iterations": PBKDF2_ITERATIONS, "hash": "sha256"}
    elif kdf_name == "scrypt":
        kek = derive_key_scrypt(password, salt, n=2048, r=8, p=1, length=32)
        kdf_params = {"n": 2048, "r": 8, "p": 1}
    else:
        raise ValueError("KDF invalida")

    totp_secret = generate_totp_secret()
    user_data_key = secrets.token_bytes(32)

    bundle = {
        "totp_secret": totp_secret,
        "user_data_key_b64": b64e(user_data_key),
    }
    blob = aes_gcm_encrypt(kek, canonical_json_bytes(bundle))

    users[username] = {
        "kdf": kdf_name,
        "kdf_params": kdf_params,
        "salt_password_b64": b64e(salt),
        "bundle_nonce_b64": blob.nonce_b64,
        "bundle_ciphertext_b64": blob.ciphertext_b64,
    }
    save_users(users)

    return {
        "username": username,
        "totp_secret": totp_secret,
        "provisioning_uri": provisioning_uri(totp_secret, account=username, issuer="MiniBlockchainUFSC"),
    }


def login_user(username: str, password: str, totp_code: str) -> Session | None:
    """
    Login em 2 fatores: senha + TOTP.
    Retorna sessao em caso de sucesso ou None em falha.
    """
    users = load_users()
    record = users.get(username)
    if record is None:
        return None

    try:
        kek = _derive_kek(record, password)
        plain = aes_gcm_decrypt(kek, record["bundle_nonce_b64"], record["bundle_ciphertext_b64"])
    except (ValueError, KeyError, CryptoError):
        return None

    try:
        bundle = json.loads(plain.decode("utf-8"))
        totp_secret = bundle["totp_secret"]
        user_data_key = b64d(bundle["user_data_key_b64"])
    except Exception:
        return None

    if not verify_totp(totp_secret, totp_code, valid_window=1):
        return None

    return Session(username=username, user_data_key=user_data_key, totp_secret=totp_secret)
