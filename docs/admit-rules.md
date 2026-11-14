# reqattest admit rules

A sealed request attestation binds an HTTP method/path and the **exact
raw body bytes** to an HMAC signature. Verification is offline.

## Envelope JSON

Required fields:

- `version`: must be the string `v1`
- `kid`: key id
- `ts`: unix seconds (int)
- `nonce`: non-empty string
- `method`: HTTP method string
- `path`: absolute path only (no scheme/host/query); query string if any
  is **not** part of the signed path
- `body_sha256`: lowercase hex SHA-256 of the raw body bytes
- `scopes`: array of strings (issuer already sorted ascending)
- `audience`: string audience name
- `sig`: base64url (no padding) of HMAC-SHA256 over the signing input

## Signing input (normative)

ASCII string, fields joined by `|` with **no** spaces:

```
v1|{kid}|{ts}|{nonce}|{method}|{path}|{body_sha256}|{scopes_csv}
```

`scopes_csv` is `scopes` joined by commas in the envelope order
(already sorted). HMAC key material comes from `keys[kid].secret`
(hex decoded when the secret is valid hex, otherwise UTF-8 bytes).

## Keys (`fixtures/keys.json`)

```json
{
  "keys": {
    "k-active": {"secret": "...", "status": "active"},
    "k-revoked": {"secret": "...", "status": "revoked"}
  }
}
```

- Missing kid → load failure (exit 2).
- `status == "revoked"` → deny `kid_revoked` (do **not** treat as missing).

## Policy (`fixtures/policy.json`)

- `allowed_methods`: method must be an exact member (case-sensitive).
- `allowed_audiences`: envelope `audience` must be a member when
  `require_audience` is true.
- `path_allow`: entries are `{audience, exact?}` or `{audience, prefix?}`.
  Match only entries whose `audience` equals the envelope audience.
  `exact` is equality; `prefix` is literal `path.startswith(prefix)`.
  Never search the path allow value as a substring of a larger URL or of
  `audience + path`.
- `denied_path_substrings`: if any fragment appears in `path` → `path_denied`.
- `allowed_scopes`: `matched_scopes` is the sorted intersection of envelope
  scopes and this list; empty intersection → `scope_mismatch`.
- `clock_skew_seconds`: require `abs(now - ts) <= skew` else `timestamp_skew`.
- `nonce_ttl_seconds`: documented for store GC; admit must still reject any
  nonce already present in the store regardless of age for this lab.

## Nonce store

JSON object `{"nonces": { "<nonce>": <seen_unix_ts>, ... }}`.

- If nonce already present → deny `replay`.
- On **allow only**, write nonce → now into the store and persist atomically
  (write temp file then replace). Deny / load failure must not add the nonce.

## Body binding

Compute SHA-256 over the raw body file bytes. If digest ≠ `body_sha256` →
`body_mismatch`. Do **not** JSON-parse/re-dump the body before hashing.

## Signature

Recompute HMAC over the signing input with the active key. Mismatch →
`bad_signature`.

## Reason codes

Exact strings: `version_rejected`, `kid_revoked`, `bad_signature`,
`timestamp_skew`, `replay`, `method_denied`, `audience_mismatch`,
`path_denied`, `scope_mismatch`, `body_mismatch`.

## Forbidden shortcuts

- Accepting a revoked kid because the secret still verifies.
- Hashing pretty-printed or re-serialized JSON instead of raw body bytes.
- Treating path allow as substring search on `audience+path` or full URLs.
- Recording nonces on deny paths.
- Case-folding HTTP methods (`post` ≠ `POST`).
