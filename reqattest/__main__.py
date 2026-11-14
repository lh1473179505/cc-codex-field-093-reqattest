from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .engine import admit_request, inspect_envelope
from .load import load_bytes, load_json, load_nonce_store


def _parse_now(value: str) -> int:
    if value.isdigit():
        return int(value)
    # accept Z
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def cmd_inspect(args: argparse.Namespace) -> int:
    envelope = load_json(args.envelope)
    report = inspect_envelope(envelope)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


def cmd_admit(args: argparse.Namespace) -> int:
    try:
        envelope = load_json(args.envelope)
        body = load_bytes(args.body)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_nonce_store(args.nonce_store)
        now_unix = _parse_now(args.now)
        report = admit_request(envelope, body, keys, policy, store, now_unix)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"load failure: {e}", file=sys.stderr)
        return 2
    except NotImplementedError as e:
        print(str(e), file=sys.stderr)
        return 2

    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    # Persist store only when implementation updates it; stub never reaches here.
    if args.nonce_store:
        Path(args.nonce_store).write_text(
            json.dumps(store, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    decision = report.get("decision")
    if decision == "allow":
        return 0
    if decision == "deny":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="reqattest")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_i = sub.add_parser("inspect")
    p_i.add_argument("--envelope", required=True)
    p_i.add_argument("--report")
    p_i.set_defaults(func=cmd_inspect)

    p_a = sub.add_parser("admit")
    p_a.add_argument("--envelope", required=True)
    p_a.add_argument("--body", required=True)
    p_a.add_argument("--keys", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--nonce-store", required=True)
    p_a.add_argument("--now", required=True)
    p_a.add_argument("--report", required=True)
    p_a.set_defaults(func=cmd_admit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
