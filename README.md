# reqattest

Offline lab for admitting sealed HTTP request attestations.

`python -m reqattest inspect --envelope <file>` prints kid, timestamp,
nonce, method, path, body digest and scopes.

`python -m reqattest admit` must evaluate an envelope + raw body against
keys/policy/nonce-store using `docs/admit-rules.md`. Exit 0 allow, 1 deny,
2 load failure.

Standard library only. No Docker, no network.
