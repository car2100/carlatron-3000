from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any


class CryptoError(Exception):
    """Erro de operacao criptografica (ex.: falha de autenticacao GCM)."""


@dataclass(frozen=True)
class AesGcmBlob:
    nonce_b64: str
    ciphertext_b64: str


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    """Serializa JSON em formato canonico para hash consistente."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
