from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# DATA_DIR padrao: pasta data/ na raiz do repositorio.
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
USERS_FILE = "users.json"
CHAIN_FILE = "blockchain.json"


def set_data_dir(path: str | Path) -> None:
    """Permite trocar o diretorio de dados (util em testes)."""
    global DATA_DIR
    DATA_DIR = Path(path)


def _read_json(path: Path, default_value: Any) -> Any:
    if not path.exists():
        return default_value
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return default_value
    return json.loads(text)


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True), encoding="utf-8")


def ensure_data_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    users_path = DATA_DIR / USERS_FILE
    chain_path = DATA_DIR / CHAIN_FILE

    if not users_path.exists():
        _write_json(users_path, {})
    if not chain_path.exists():
        _write_json(chain_path, [])


def load_users() -> dict[str, Any]:
    ensure_data_files()
    users = _read_json(DATA_DIR / USERS_FILE, {})
    if not isinstance(users, dict):
        raise ValueError("users.json is malformed")
    return users


def save_users(users: dict[str, Any]) -> None:
    ensure_data_files()
    _write_json(DATA_DIR / USERS_FILE, users)


def load_chain() -> list[dict[str, Any]]:
    ensure_data_files()
    chain = _read_json(DATA_DIR / CHAIN_FILE, [])
    if not isinstance(chain, list):
        raise ValueError("blockchain.json is malformed")
    return chain


def save_chain(chain: list[dict[str, Any]]) -> None:
    ensure_data_files()
    _write_json(DATA_DIR / CHAIN_FILE, chain)
