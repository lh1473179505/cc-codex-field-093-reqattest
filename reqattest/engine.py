from __future__ import annotations

from typing import Any


def inspect_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": envelope.get("version"),
        "kid": envelope.get("kid"),
        "ts": envelope.get("ts"),
        "nonce": envelope.get("nonce"),
        "method": envelope.get("method"),
        "path": envelope.get("path"),
        "body_sha256": envelope.get("body_sha256"),
        "scopes": envelope.get("scopes"),
        "audience": envelope.get("audience"),
    }


def admit_request(
    envelope: dict[str, Any],
    body: bytes,
    keys: dict[str, Any],
    policy: dict[str, Any],
    nonce_store: dict[str, Any],
    now_unix: int,
) -> dict[str, Any]:
    """Admit a sealed request. Stub — raise until implemented."""
    raise NotImplementedError(
        "reqattest.engine.admit_request is not implemented yet; inspect works"
    )
