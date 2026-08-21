"""The JSONL record contract (design §10.4).

Bare records, one per line. Every record carries `v`, `ts`, `id`, `src`.
Facts are content-hashed so re-running a query produces byte-identical ids
(idempotent); hypotheses / beliefs / findings get ULIDs and live elsewhere.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
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


# --------------------------------------------------------------- identifiers

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_last_ulid: tuple[int, int] = (0, 0)


def _b32(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        value, rem = divmod(value, 32)
        out.append(CROCKFORD[rem])
    return "".join(reversed(out))


def ulid() -> str:
    """26-char Crockford base32 ULID: 48-bit ms timestamp + 80 bits of entropy.

    Time-sortable, as §10.4 promises. Within a millisecond the random half is
    incremented rather than redrawn, so ids minted in a burst still sort in
    creation order instead of shuffling.

    Note that belief *projection* does not rely on this: latest-wins is decided
    by position in the append-only log, so a clock that jumps cannot silently
    resurrect a superseded verdict.
    """
    global _last_ulid
    ms = int(time.time() * 1000)
    last_ms, last_rand = _last_ulid
    if ms == last_ms:
        rand = last_rand + 1
    elif ms < last_ms:
        # Clock went backwards. Keep issuing sortable ids under the previous
        # millisecond rather than emitting one that sorts before its ancestors.
        ms, rand = last_ms, last_rand + 1
    else:
        rand = secrets.randbits(80)
    if rand >= 1 << 80:  # entropy exhausted within one ms; roll into the next
        ms, rand = ms + 1, secrets.randbits(80)
    _last_ulid = (ms, rand)
    return _b32(ms, 10) + _b32(rand, 16)


def record(rec_type: str, payload: dict[str, Any], src: str) -> dict[str, Any]:
    """Envelope for a non-fact record (§10.4): ULID id, not a content hash.

    Beliefs, hypotheses and findings are *events* — asserting the same belief
    twice is two decisions, and the second supersedes the first. Content-hashing
    them would collapse that history into one line and destroy the audit trail.
    """
    clash = [k for k in RESERVED if k in payload]
    if clash:
        raise ValueError(f"payload may not set reserved field(s): {clash}")
    return {
        "v": SCHEMA_VERSION,
        "type": rec_type,
        "id": f"{rec_type[0]}_{ulid()}",
        "ts": now_ts(),
        "src": src,
        **payload,
    }


BELIEF_KEY = ("subject", "predicate", "object")


def belief(subject: str, predicate: str, object_: str, verdict: str,
           rationale: str, audited_by: str) -> dict[str, Any]:
    """A trust decision (§5), keyed on subject+predicate+object.

    `rationale` is mandatory: a verdict with no stated reason cannot be audited
    later, and this record is precisely what stops the system re-litigating a
    sanitizer on every run.
    """
    for name, value in (("subject", subject), ("predicate", predicate),
                        ("object", object_), ("verdict", verdict),
                        ("rationale", rationale), ("audited_by", audited_by)):
        if not str(value).strip():
            raise ValueError(f"belief requires a non-empty {name}")
    return record(
        "belief",
        {
            "subject": subject,
            "predicate": predicate,
            "object": object_,
            "verdict": verdict,
            "rationale": " ".join(rationale.split()),
            "audited_by": audited_by,
        },
        src=f"belief:{audited_by}",
    )


def belief_key(rec: dict[str, Any]) -> tuple[str, str, str]:
    return tuple(str(rec.get(k, "")) for k in BELIEF_KEY)  # type: ignore[return-value]
