from __future__ import annotations

import base64
import hashlib
import hmac
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
    """Admit a sealed request against keys, policy and the nonce store.

    Returns a report dict per docs/report-schema.md. On allow, the nonce is
    written into ``nonce_store`` (in place); deny paths never mutate it.
    Missing key material raises KeyError, which callers treat as a load
    failure.
    """
    reason_codes: list[str] = []

    kid = envelope.get("kid", "")
    audience = envelope.get("audience", "")
    method = envelope.get("method", "")
    path = envelope.get("path", "")
    nonce = envelope.get("nonce", "")
    ts = envelope.get("ts")
    scopes = envelope.get("scopes") or []
    body_sha256 = envelope.get("body_sha256", "")
    envelope_sig = envelope.get("sig", "")

    matched_scopes = sorted(
        set(scopes) & set(policy.get("allowed_scopes", []))
    )

    if envelope.get("version") != "v1":
        reason_codes.append("version_rejected")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        raise KeyError(f"unknown kid: {kid!r}")
    if key_entry.get("status") == "revoked":
        reason_codes.append("kid_revoked")

    scopes_csv = ",".join(str(scope) for scope in scopes)
    signing_input = "|".join(
        [
            "v1",
            str(kid),
            str(ts),
            str(nonce),
            str(method),
            str(path),
            str(body_sha256),
            scopes_csv,
        ]
    )
    expected_sig = _compute_signature(key_entry.get("secret", ""), signing_input)
    if not hmac.compare_digest(expected_sig, str(envelope_sig)):
        reason_codes.append("bad_signature")

    try:
        skew = abs(int(now_unix) - int(ts))
    except (TypeError, ValueError):
        skew = policy.get("clock_skew_seconds", 0) + 1
    if skew > int(policy.get("clock_skew_seconds", 0)):
        reason_codes.append("timestamp_skew")

    seen_nonces = nonce_store.setdefault("nonces", {})
    if nonce in seen_nonces:
        reason_codes.append("replay")

    if method not in policy.get("allowed_methods", []):
        reason_codes.append("method_denied")

    if policy.get("require_audience", True) and audience not in policy.get(
        "allowed_audiences", []
    ):
        reason_codes.append("audience_mismatch")

    if not _path_allowed(path, audience, policy):
        reason_codes.append("path_denied")

    if not matched_scopes:
        reason_codes.append("scope_mismatch")

    actual_digest = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(actual_digest, str(body_sha256)):
        reason_codes.append("body_mismatch")

    decision = "allow" if not reason_codes else "deny"
    if decision == "allow":
        seen_nonces[nonce] = int(now_unix)

    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kid": kid,
        "audience": audience,
        "method": method,
        "path": path,
        "matched_scopes": matched_scopes,
        "notes": [],
    }


def _compute_signature(secret: str, signing_input: str) -> str:
    key_material = _decode_secret(secret)
    digest = hmac.new(
        key_material, signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_secret(secret: str) -> bytes:
    raw = secret.encode("utf-8")
    if len(secret) % 2 == 0:
        try:
            return bytes.fromhex(secret)
        except ValueError:
            pass
    return raw


def _path_allowed(path: str, audience: str, policy: dict[str, Any]) -> bool:
    for fragment in policy.get("denied_path_substrings", []):
        if fragment and fragment in path:
            return False

    for entry in policy.get("path_allow", []):
        if entry.get("audience") != audience:
            continue
        if "exact" in entry and path == entry["exact"]:
            return True
        if "prefix" in entry and path.startswith(entry["prefix"]):
            return True
    return False
