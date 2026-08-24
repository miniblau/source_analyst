"""The append-only log and the belief projection (design §5, §10.4).

One `log.jsonl` holds every record type. It is append-only and never rewritten:
the belief store is a *projection* over it, recomputed on read, so there is no
cache that can drift from the log and "rebuildable from the log" is true by
construction rather than by discipline.

Latest-wins is decided by **position in the log**, not by id or timestamp. A
clock that jumps backwards, or two verdicts minted in the same millisecond,
must never be able to resurrect a superseded belief.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator

import yaml

from .. import records
from ..cpg.workspace import private_dir, private_file, repo_root, var_root

REQUIRED_ENVELOPE = ("v", "type", "id", "ts", "src")


class LogError(Exception):
    """The log or a record offered to it is malformed. Always fatal: a log that
    silently accepts junk is a log nothing can be rebuilt from."""


def log_path() -> Path:
    env = os.environ.get("SOURCE_ANALYST_LOG")
    return Path(env).expanduser().resolve() if env else var_root() / "log.jsonl"


def verdicts() -> dict[str, dict[str, Any]]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    path = base / "verdicts.yaml"
    if not path.is_file():
        raise LogError(f"missing verdict vocabulary: {path}")
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or not doc:
        raise LogError(f"{path}: expected a non-empty mapping of verdict to spec")
    return doc


def validate(rec: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED_ENVELOPE if k not in rec]
    if missing:
        raise LogError(f"record is missing required field(s) {', '.join(missing)}: {rec}")
    if rec["type"] == "belief":
        for k in (*records.BELIEF_KEY, "verdict", "rationale", "audited_by"):
            if not str(rec.get(k, "")).strip():
                raise LogError(f"belief record is missing {k}: {rec}")
        known = verdicts()
        if rec["verdict"] not in known:
            raise LogError(
                f"unknown verdict {rec['verdict']!r}; expected one of "
                f"{', '.join(sorted(known))} (config/verdicts.yaml)")


def read(path: Path | None = None) -> Iterator[dict[str, Any]]:
    """Stream the log in order. A malformed line is fatal, not skipped."""
    p = path or log_path()
    if not p.is_file():
        return
    with p.open() as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError as e:
                raise LogError(f"{p}:{n}: not valid JSON ({e})")


def append(recs: list[dict[str, Any]], path: Path | None = None) -> tuple[int, int]:
    """Append records, skipping facts already in the log. Returns (written, duplicate).

    Facts are content-hashed, so re-running a query must not grow the log — that
    is what makes a fact idempotent in practice and not just in principle.
    Beliefs are never deduped: asserting one twice is two decisions, and the
    second supersedes the first.
    """
    p = path or log_path()
    for rec in recs:
        validate(rec)
    seen = {r["id"] for r in read(p) if r.get("type") == "fact"}

    fresh, dupes = [], 0
    for rec in recs:
        if rec.get("type") == "fact":
            if rec["id"] in seen:
                dupes += 1
                continue
            seen.add(rec["id"])
        fresh.append(rec)

    if fresh:
        # Owner-only: the log carries code excerpts from the tree under review.
        private_dir(p.parent)
        existed = p.exists()
        # One write of whole lines in append mode: concurrent writers interleave
        # records, never fragments of one.
        with p.open("a") as fh:
            fh.write("".join(
                json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in fresh))
        if not existed:
            private_file(p)
    return len(fresh), dupes


def project(path: Path | None = None) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Latest-wins belief projection keyed on subject+predicate+object (§10.4)."""
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in read(path):
        if rec.get("type") == "belief":
            out[records.belief_key(rec)] = rec
    return out


def revised_hypotheses(log: list[dict[str, Any]]) -> set[str]:
    """Ids of hypotheses a later revision has replaced — every id named as a `parent`.

    A chain's leaf is the case as it stands; its ancestors are history. Anything that
    reads "the hypotheses" and means "the cases" has to drop them, or one site is
    counted once per level `trace` took it through. Three readers got this wrong the
    day branching landed, which is why it lives here and not in any one of them.
    """
    return {h["parent"] for h in log
            if h.get("type") == "hypothesis" and h.get("parent")}


def superseded(path: Path | None = None) -> dict[tuple[str, str, str], int]:
    """How many earlier verdicts each live belief replaced — the audit trail the
    projection hides. A key revised repeatedly is a signal in itself."""
    counts: dict[tuple[str, str, str], int] = {}
    for rec in read(path):
        if rec.get("type") == "belief":
            k = records.belief_key(rec)
            counts[k] = counts.get(k, 0) + 1
    return {k: v - 1 for k, v in counts.items()}
