from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .alg_crypto_common import AesGcmBlob, CryptoError, b64d, b64e


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> AesGcmBlob:
    """
    Cifra dados com AES-GCM (nonce de 12 bytes e tag autenticada no ciphertext).
    Em cryptography.AESGCM, retorno = ciphertext || tag.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must have 16, 24, or 32 bytes")

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return AesGcmBlob(nonce_b64=b64e(nonce), ciphertext_b64=b64e(ciphertext))


def aes_gcm_decrypt(
    key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    aad: bytes | None = None,
) -> bytes:
    """Decifra dados AES-GCM; falha de tag levanta CryptoError."""
    nonce = b64d(nonce_b64)
    ciphertext = b64d(ciphertext_b64)

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # InvalidTag e afins
        raise CryptoError("AES-GCM authentication failed") from exc
