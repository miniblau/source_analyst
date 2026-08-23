"""`admit` — validate what an agent produced, then append it (design §4, §5).

This is the gate on invariant #1. An agent hands over prose and judgements; this
tool refuses anything that asserts more than the substrate can support:

  * every hypothesis must cite evidence, and every cited fact id must EXIST in
    the log — a hallucinated fact reference is the exact failure mode the whole
    architecture exists to prevent;
  * `confirmed` is refused while the run is static-only (§4 v1 ceiling);
  * a finding's tier may not exceed the class ceiling from the manifest;
  * a finding must point at a hypothesis that exists.

It makes no LLM call and forms no opinion. Reads JSONL on stdin.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from .. import records
from ..belief import store
from ..cpg.workspace import repo_root
from ..manifest.loader import ManifestError, load_class, load_patterns, tier_table

HYPOTHESIS_FIELDS = ("statement", "vuln_class", "status", "confidence", "evidence")
# `caveats` is required, not optional prose. A static-only finding that does not say
# where it stops is the overclaiming this whole system exists to prevent, and asking
# for it in the agent prompt was not enough: the first real run produced 23 findings
# with no caveats at all, because the output schema forbade the field the prompt
# demanded. Prompts request; the gate enforces.
FINDING_FIELDS = ("hypothesis", "tier", "severity", "recreation", "refs", "title", "caveats")
SEVERITIES = ("info", "low", "medium", "high", "critical")


class AdmitError(Exception):
    """Agent output that may not enter the log."""


def statuses() -> dict[str, dict[str, Any]]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    path = base / "hypothesis.yaml"
    if not path.is_file():
        raise AdmitError(f"missing hypothesis lifecycle vocabulary: {path}")
    return yaml.safe_load(path.read_text())


def _require(obj: dict, fields: tuple[str, ...], what: str) -> None:
    missing = [f for f in fields if f not in obj or obj[f] in ("", None, [])]
    if missing:
        raise AdmitError(f"{what} is missing required field(s): {', '.join(missing)}")


def check_hypothesis(obj: dict, log_ids: dict[str, str], dynamic: bool,
                     vuln_class: str | None = None) -> None:
    _require(obj, HYPOTHESIS_FIELDS, "hypothesis")
    if vuln_class is not None and obj["vuln_class"] != vuln_class:
        # Observed on the first local-model run: the model wrote the class's human
        # TITLE ("SQL injection") where the briefing's `class` identifier belongs.
        # Every judgement was correct and four of them still fell out of every
        # downstream query keyed on class — a silent partial result, which is worse
        # than a loud failure. The class is not the agent's to name.
        raise AdmitError(
            f"hypothesis is labelled vuln_class {obj['vuln_class']!r} but is being "
            f"admitted under {vuln_class!r} — copy the briefing's `class` verbatim")
    vocab = statuses()
    status = obj["status"]
    if status not in vocab:
        raise AdmitError(f"unknown status {status!r}; expected one of {', '.join(sorted(vocab))}")
    if vocab[status]["requires_dynamic"] and not dynamic:
        raise AdmitError(
            f"status {status!r} requires a dynamic verification tier; this run is "
            f"static-only, whose ceiling is `needs_proof` (§4)")
    conf = obj["confidence"]
    if not isinstance(conf, (int, float)) or not 0.0 <= float(conf) <= 1.0:
        raise AdmitError(f"confidence must be a number in [0,1], got {conf!r}")

    evidence = obj["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise AdmitError("hypothesis must cite at least one fact id as evidence")
    for fid in evidence:
        if fid not in log_ids:
            # The load-bearing check: an id that is not in the log is a fact that
            # was never established. Admitting it would let prose masquerade as
            # ground truth, which is invariant #1 exactly.
            raise AdmitError(f"evidence {fid!r} is not in the log — no such fact was established")
        if log_ids[fid] != "fact":
            raise AdmitError(f"evidence {fid!r} is a {log_ids[fid]}, not a fact")


def check_finding(obj: dict, log_ids: dict[str, str], ceiling: str) -> None:
    _require(obj, FINDING_FIELDS, "finding")
    tiers = tier_table()
    tier = obj["tier"]
    if tier not in tiers:
        raise AdmitError(f"unknown tier {tier!r}; expected one of {', '.join(sorted(tiers))}")
    if tiers[tier]["ordinal"] > tiers[ceiling]["ordinal"]:
        raise AdmitError(
            f"finding claims tier {tier!r}, above the class ceiling {ceiling!r} — the "
            f"substrate that produced this evidence cannot support it")
    if obj["severity"] not in SEVERITIES:
        raise AdmitError(f"severity must be one of {', '.join(SEVERITIES)}")
    hid = obj["hypothesis"]
    if hid not in log_ids:
        raise AdmitError(f"finding references hypothesis {hid!r}, which is not in the log")
    if log_ids[hid] != "hypothesis":
        raise AdmitError(f"finding references {hid!r}, which is a {log_ids[hid]}")
    if not isinstance(obj["refs"], list) or not obj["refs"]:
        raise AdmitError("finding must carry at least one file:line ref")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="admit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--type", required=True, choices=("hypothesis", "finding"))
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--lang", required=True)
    p.add_argument("--src", required=True,
                   help="who produced this: agent:hypothesize, human, ...")
    p.add_argument("--dynamic", action="store_true",
                   help="this run has a dynamic verification tier (Phase 4); off by default")
    p.add_argument("--dry-run", action="store_true", help="validate only, write nothing")
    args = p.parse_args(argv)

    try:
        load_class(args.vuln_class)
        ceiling = load_patterns(args.vuln_class, args.lang).max_static_tier
    except ManifestError as e:
        raise SystemExit(f"admit: {e}")

    objs = []
    for n, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except ValueError as e:
            raise SystemExit(f"admit: stdin:{n}: not valid JSON ({e})")
    if not objs:
        raise SystemExit("admit: nothing on stdin")

    log_ids = {r["id"]: r.get("type", "?") for r in store.read()}

    built = []
    try:
        for obj in objs:
            if args.type == "hypothesis":
                check_hypothesis(obj, log_ids, args.dynamic, args.vuln_class)
            else:
                check_finding(obj, log_ids, ceiling)
            built.append(records.record(args.type, obj, src=args.src))
    except AdmitError as e:
        # Nothing is written: a batch is admitted whole or not at all, so a
        # partially-validated set of judgements never lands in the log.
        raise SystemExit(f"admit: rejected — {e}")

    if not args.dry_run:
        store.append(built)
        records.write_jsonl(built, sys.stdout)
    print(json.dumps({"cmd": "admit", "type": args.type, "admitted": len(built),
                      "dry_run": bool(args.dry_run), "ceiling": ceiling,
                      "src": args.src}, separators=(",", ":")), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
