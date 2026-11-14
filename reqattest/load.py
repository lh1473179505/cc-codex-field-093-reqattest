from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def load_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def load_nonce_store(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {"nonces": {}}
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "nonces" not in data:
        raise ValueError("nonce store must be an object with nonces")
    if not isinstance(data["nonces"], dict):
        raise ValueError("nonces must be an object")
    return data
