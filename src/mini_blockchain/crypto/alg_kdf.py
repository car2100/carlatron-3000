from __future__ import annotations

import hashlib
import secrets


def generate_salt(size: int = 16) -> bytes:
    """Salt aleatorio criptograficamente seguro."""
    return secrets.token_bytes(size)


def derive_key_pbkdf2(
    password: str,
    salt: bytes,
    *,
    iterations: int = 300_000,
    length: int = 32,
    hash_name: str = "sha256",
) -> bytes:
    """
    Deriva chave com PBKDF2-HMAC.

    Nota: o exemplo Java usa PBKDF2WithHmacSHA512 com 1000 iteracoes.
    Para producao/academico atual, 300k+ iteracoes com SHA-256/512 e melhor.
    """
    return hashlib.pbkdf2_hmac(
        hash_name,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=length,
    )


def derive_key_scrypt(
    password: str,
    salt: bytes,
    *,
    n: int = 2048,
    r: int = 8,
    p: int = 1,
    length: int = 32,
) -> bytes:
    """Deriva chave com scrypt (N, r, p), igual a parametrizacao dos exemplos."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=length,
    )
