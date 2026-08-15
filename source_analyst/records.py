"""The JSONL record contract (design §10.4).

Bare records, one per line. Every record carries `v`, `ts`, `id`, `src`.
Facts are content-hashed so re-running a query produces byte-identical ids
(idempotent); hypotheses / beliefs / findings get ULIDs and live elsewhere.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, TextIO

SCHEMA_VERSION = 1

RESERVED = ("v", "type", "id", "ts", "src")


def now_ts() -> str:
    """RFC3339, UTC, second resolution."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fact(payload: dict[str, Any], src: str) -> dict[str, Any]:
    """Wrap a substrate payload in a fact envelope.

    `id` is a content hash over {v, type, src, payload} — deliberately excluding
    `ts`, so the same fact re-derived tomorrow keeps the same id and dedupes.
    """
    clash = [k for k in RESERVED if k in payload]
    if clash:
        raise ValueError(f"payload may not set reserved field(s): {clash}")
    if "kind" not in payload:
        raise ValueError("fact payload must carry a `kind`")
    body = {"v": SCHEMA_VERSION, "type": "fact", "src": src, **payload}
    fid = "f_" + hashlib.sha256(canonical(body)).hexdigest()[:24]
    return {
        "v": SCHEMA_VERSION,
        "type": "fact",
        "id": fid,
        "ts": now_ts(),
        "src": src,
        **payload,
    }


def write_jsonl(records: Iterable[dict[str, Any]], stream: TextIO) -> int:
    n = 0
    for rec in records:
        stream.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        n += 1
    stream.flush()
    return n
