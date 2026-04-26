from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .auth import Session
from .blockchain_helpers import make_block_hash
from .crypto.alg_aes_gcm import aes_gcm_decrypt, aes_gcm_encrypt
from .crypto.alg_crypto_common import CryptoError, b64d, b64e, canonical_json_bytes
from .storage import load_chain, save_chain


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def add_block(session: Session, message: str) -> dict[str, Any]:
    """Adiciona bloco cifrado do usuario autenticado."""
    if not message.strip():
        raise ValueError("Mensagem do bloco nao pode ser vazia")

    chain = load_chain()
    index = len(chain)
    hash_prev = "GENESIS" if index == 0 else chain[-1]["block_hash"]
    timestamp = _utc_now_iso()

    aad = {
        "owner": session.username,
        "index": index,
        "timestamp": timestamp,
    }
    aad_bytes = canonical_json_bytes(aad)

    # O payload real fica cifrado; no arquivo persistimos apenas Base64.
    payload = {"message": message}
    blob = aes_gcm_encrypt(session.user_data_key, canonical_json_bytes(payload), aad=aad_bytes)

    block_hash = make_block_hash(
        index=index,
        owner=session.username,
        timestamp=timestamp,
        hash_prev=hash_prev,
        nonce_b64=blob.nonce_b64,
        ciphertext_b64=blob.ciphertext_b64,
    )

    block = {
        "index": index,
        "owner": session.username,
        "timestamp": timestamp,
        "hash_prev": hash_prev,
        "nonce_b64": blob.nonce_b64,
        "ciphertext_b64": blob.ciphertext_b64,
        "aad": aad,
        "block_hash": block_hash,
    }

    chain.append(block)
    save_chain(chain)
    return block


def list_block_metadata() -> list[dict[str, Any]]:
    """Lista apenas metadados publicos, sem descriptografar payload."""
    chain = load_chain()
    output: list[dict[str, Any]] = []
    for block in chain:
        output.append(
            {
                "index": block["index"],
                "owner": block["owner"],
                "timestamp": block["timestamp"],
                "hash_prev": block["hash_prev"],
                "block_hash": block["block_hash"],
            }
        )
    return output


def read_user_blocks(session: Session) -> list[dict[str, Any]]:
    """Retorna os blocos do usuario logado com payload decifrado."""
    chain = load_chain()
    mine: list[dict[str, Any]] = []

    for block in chain:
        if block.get("owner") != session.username:
            continue

        aad = block.get("aad", {})
        try:
            plain = aes_gcm_decrypt(
                session.user_data_key,
                block["nonce_b64"],
                block["ciphertext_b64"],
                aad=canonical_json_bytes(aad),
            )
            message = __import__("json").loads(plain.decode("utf-8")).get("message")
            mine.append({"index": block["index"], "timestamp": block["timestamp"], "message": message})
        except (CryptoError, KeyError, ValueError):
            mine.append(
                {
                    "index": block.get("index", -1),
                    "timestamp": block.get("timestamp", "?"),
                    "message": "<falha de autenticacao do bloco>",
                }
            )

    return mine


def validate_chain(user_keys: dict[str, bytes] | None = None) -> dict[str, Any]:
    """
    Valida encadeamento e hash de todos os blocos.
    Se user_keys for passado, tambem tenta verificar autenticidade AES-GCM
    para os donos cujas chaves estao disponiveis.
    """
    chain = load_chain()
    errors: list[str] = []

    for i, block in enumerate(chain):
        expected_prev = "GENESIS" if i == 0 else chain[i - 1].get("block_hash")
        if block.get("hash_prev") != expected_prev:
            errors.append(f"hash_prev invalido no bloco {i}")

        expected_hash = make_block_hash(
            index=block.get("index"),
            owner=block.get("owner"),
            timestamp=block.get("timestamp"),
            hash_prev=block.get("hash_prev"),
            nonce_b64=block.get("nonce_b64"),
            ciphertext_b64=block.get("ciphertext_b64"),
        )
        if block.get("block_hash") != expected_hash:
            errors.append(f"block_hash invalido no bloco {i}")

        if user_keys is not None:
            owner = block.get("owner")
            key = user_keys.get(owner)
            if key is not None:
                try:
                    aes_gcm_decrypt(
                        key,
                        block.get("nonce_b64", ""),
                        block.get("ciphertext_b64", ""),
                        aad=canonical_json_bytes(block.get("aad", {})),
                    )
                except (CryptoError, ValueError, KeyError):
                    errors.append(f"falha de autenticacao AES-GCM no bloco {i}")

    return {"ok": len(errors) == 0, "errors": errors, "total_blocks": len(chain)}


def tamper_ciphertext_byte(block_index: int) -> None:
    """Laboratorio: altera 1 byte do ciphertext para simular adulteracao."""
    chain = load_chain()
    if block_index < 0 or block_index >= len(chain):
        raise IndexError("Bloco fora do intervalo")

    raw = bytearray(b64d(chain[block_index]["ciphertext_b64"]))
    if not raw:
        raise ValueError("Ciphertext vazio")

    raw[0] ^= 0x01
    chain[block_index]["ciphertext_b64"] = b64e(bytes(raw))
    save_chain(chain)


def tamper_hash_prev(block_index: int, fake_prev_hash: str = "HACKED") -> None:
    """Laboratorio: altera hash_prev para simular quebra do encadeamento."""
    chain = load_chain()
    if block_index < 0 or block_index >= len(chain):
        raise IndexError("Bloco fora do intervalo")

    chain[block_index]["hash_prev"] = fake_prev_hash
    save_chain(chain)


def run_tamper_demo(user_keys: dict[str, bytes]) -> dict[str, Any]:
    """
    Executa duas adulteracoes e devolve o resultado das validacoes.
    O arquivo e restaurado ao estado original ao final da demonstracao.
    """
    original = load_chain()
    if not original:
        return {"ran": False, "reason": "blockchain vazia"}

    baseline = deepcopy(original)
    result: dict[str, Any] = {"ran": True}

    # Caso 1: adultera ciphertext e espera falha de autenticacao/hash.
    tamper_ciphertext_byte(len(original) - 1)
    result["tamper_ciphertext"] = validate_chain(user_keys=user_keys)
    save_chain(deepcopy(baseline))

    # Caso 2: adultera hash_prev (quando existe bloco nao-genesis).
    if len(original) >= 2:
        tamper_hash_prev(1)
        result["tamper_hash_prev"] = validate_chain(user_keys=user_keys)
        save_chain(deepcopy(baseline))
    else:
        result["tamper_hash_prev"] = {"ok": True, "errors": ["Nao ha bloco suficiente para quebrar hash_prev"]}

    return result
