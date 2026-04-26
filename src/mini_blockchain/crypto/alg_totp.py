from __future__ import annotations

import pyotp


def generate_totp_secret() -> str:
    """Equivalente ao generateSecretKey() em Java, em Base32."""
    return pyotp.random_base32()


def totp_now(secret_base32: str) -> str:
    """Gera codigo TOTP atual (janela padrao de 30s)."""
    return pyotp.TOTP(secret_base32).now()


def verify_totp(secret_base32: str, code: str, valid_window: int = 1) -> bool:
    """
    Verifica TOTP com tolerancia de janela.
    valid_window=1 aceita codigo da janela atual e vizinhas.
    """
    return bool(pyotp.TOTP(secret_base32).verify(code, valid_window=valid_window))


def provisioning_uri(secret_base32: str, account: str, issuer: str) -> str:
    """Gera URI otpauth:// para app autenticador."""
    return pyotp.TOTP(secret_base32).provisioning_uri(name=account, issuer_name=issuer)
