"""`admit` — validate what an agent produced, then append it (design §4, §5).

This is the gate on invariant #1. An agent hands over prose and judgements; this
tool refuses anything that asserts more than the substrate can support:

  * every hypothesis must cite evidence, and every cited fact id must EXIST in
    the log — a hallucinated fact reference is the exact failure mode the whole
    architecture exists to prevent;
  * `confirmed` is refused while the run is static-only (§4 v1 ceiling);
  * a finding's tier may not exceed the class ceiling from the manifest;
  * a finding must point at a hypothesis that exists;
  * a trace revision must point at a parent hypothesis that exists, and every
    trust verdict it records must name a method the agent was actually SHOWN —
    a belief about code nobody read is the same hallucination wearing a hat.

One agent record is not always one log record. `--type trace` takes the shape the
agent speaks in — a revised case — and expands it into the records the log speaks
in: one child hypothesis plus one belief per verdict. The expansion is mechanical;
this tool still decides nothing.

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
TRACE_FIELDS = ("parent", "statement", "vuln_class", "status", "confidence",
                "evidence", "basis")
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


def _class_aliases(vuln_class: str, class_title: str | None) -> set[str]:
    """Spellings of a class that mean the class. Both come from its manifest, so a
    new class adds no code here and no entry anywhere else."""
    return {vuln_class} | ({class_title} if class_title else set())



def verdict_vocab() -> dict[str, Any]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    path = base / "verdicts.yaml"
    if not path.is_file():
        raise AdmitError(f"missing verdict vocabulary: {path}")
    return yaml.safe_load(path.read_text())


def check_trace(obj: dict, log_recs: dict[str, dict], dynamic: bool,
                vuln_class: str | None = None, class_title: str | None = None) -> None:
    """A revised hypothesis, plus whatever trust decisions reading the code produced."""
    _require(obj, TRACE_FIELDS, "trace revision")
    log_ids = {k: v.get("type", "?") for k, v in log_recs.items()}
    check_hypothesis(obj, log_ids, dynamic, vuln_class, class_title)

    parent = log_recs.get(obj["parent"])
    if parent is None or parent.get("type") != "hypothesis":
        raise AdmitError(
            f"trace revision names parent {obj['parent']!r}, which is not a hypothesis "
            f"in the log — a revision with no ancestor is a new hypothesis, not a child")
    if any(r.get("type") == "hypothesis" and r.get("parent") == obj["parent"]
           for r in log_recs.values()):
        # v1 `trace` revises one case into one child, so a chain has one leaf and
        # `store.revised_hypotheses` can treat "is a parent" as "is history". A second
        # child would make that projection wrong in a way nothing would report: the
        # site would appear twice in every report and scorecard, and neither copy
        # would be marked as the other's sibling.
        #
        # §4.1 does allow a node to spawn several children from new facts. When that
        # arrives it is a deliberate change to the leaf projection, not something to
        # discover from a doubled report — which is why this refuses rather than
        # quietly allowing it.
        raise AdmitError(
            f"hypothesis {obj['parent']!r} already has a revision; a second child would "
            f"fork the chain, and the leaf projection every report and scorecard reads "
            f"cannot express a fork")

    # A revision must still be about the same case. `score` and `render` locate a
    # hypothesis from its evidence facts, and a callee_body carries `file` but no
    # `line`, so a revision citing only bodies resolves to no site at all: it would
    # be dropped as unlabelled by the scorecard and headed `?` in the report, while
    # looking perfectly well-formed here. Losing the anchor is silent; refusing is not.
    facts_by_id = {k: v for k, v in log_recs.items() if v.get("type") == "fact"}
    parent_site = store.site_of(parent, facts_by_id)
    if parent_site is not None:
        site = store.site_of(obj, facts_by_id)
        if site is None:
            raise AdmitError(
                "trace revision cites no fact that locates a sink site — carry the "
                "parent's evidence forward alongside the callee bodies, or the case "
                "cannot be scored or reported against the code it is about")
        if site != parent_site:
            raise AdmitError(
                f"trace revision is about {site} but its parent is about {parent_site} "
                f"— a revision refines one case, it does not move to another")

    # What the agent was actually shown: the callee bodies among its own cited facts.
    # A verdict about anything else is a judgement of code that was never read, which
    # is the failure this whole leg was built to end.
    read = {}
    for fid in obj["evidence"]:
        rec = log_recs.get(fid, {})
        if rec.get("kind") == "callee_body":
            read[rec.get("full_name", "")] = rec
    # A method full name is `pkg.Class.method:ReturnType(ArgTypes)`. Models name the
    # part before the colon — observed live, a verdict on
    # `...SqlInjectionLesson6a.unionQueryChecker` against a fact whose full_name ends
    # `:boolean(java.lang.String)`. That is the same formatting-versus-comprehension
    # split as the class title, and the same answer: accept the shorter form when it
    # picks out exactly one method that was read, and normalise it. When two overloads
    # were read the short form is genuinely ambiguous, so it stays refused — the
    # signature is the only thing that tells them apart.
    by_qualified: dict[str, list[str]] = {}
    for full in read:
        by_qualified.setdefault(full.split(":")[0], []).append(full)
    aliases = {q: names[0] for q, names in by_qualified.items()
               if len(names) == 1 and q not in read}

    vocab = verdict_vocab()
    seen = set()
    for v in obj.get("verdicts") or []:
        if not isinstance(v, dict):
            raise AdmitError("each verdict must be an object")
        for field in ("subject", "verdict", "rationale"):
            if not str(v.get(field, "")).strip():
                raise AdmitError(f"verdict is missing required field: {field}")
        if v["verdict"] not in vocab:
            raise AdmitError(
                f"unknown verdict {v['verdict']!r}; expected one of {', '.join(sorted(vocab))}")
        if vocab[v["verdict"]].get("requires_dynamic") and not dynamic:
            # Same guard as `confirmed` on a status, for the same reason. A static
            # read can show a defence FAILS; it cannot show it holds against every
            # input, and this is the only verdict that prunes.
            raise AdmitError(
                f"verdict {v['verdict']!r} requires a dynamic verification tier; this "
                f"run is static-only. Reading a method can show a defence fails, not "
                f"that it holds — use `unsound`, `partial` or `unknown`")
        subject = aliases.get(v["subject"], v["subject"])
        if subject not in read:
            ambiguous = by_qualified.get(v["subject"], [])
            if len(ambiguous) > 1:
                raise AdmitError(
                    f"verdict names subject {v['subject']!r}, which matches "
                    f"{len(ambiguous)} overloads that were read — give the full name "
                    f"including the signature, since that is all that separates them")
            raise AdmitError(
                f"verdict names subject {v['subject']!r}, but no callee_body fact for it "
                f"is cited in this revision's evidence — a trust decision about a method "
                f"nobody read is a hallucination, and it would be believed by every "
                f"later run")
        # Normalised in place: the belief store keys on the subject string, so a short
        # form surviving into the log would never match the fact it was argued from.
        v["subject"] = subject
        if read[subject].get("status") != "resolved":
            # The signature was known and the body was not. Recording a verdict off
            # that is exactly the gap-as-acquittal the prompt warns about.
            raise AdmitError(
                f"verdict names subject {subject!r}, whose body was not read "
                f"(callee_body status {read[subject].get('status')!r}) — a gap in "
                f"coverage is not a trust decision")
        if subject in seen:
            raise AdmitError(f"two verdicts for the same subject {subject!r}")
        seen.add(subject)


def expand_trace(obj: dict, log_recs: dict[str, dict], vuln_class: str,
                 src: str) -> list[dict]:
    """One revised case -> one child hypothesis + one belief per verdict."""
    parent = log_recs[obj["parent"]]
    payload = {
        "statement": obj["statement"],
        "vuln_class": vuln_class,
        "status": obj["status"],
        "confidence": obj["confidence"],
        "evidence": obj["evidence"],
        "parent": obj["parent"],
        "depth": int(parent.get("depth", 0) or 0) + 1,
        "basis": obj["basis"],
        "read": obj.get("read") or [],
    }
    out = [records.record("hypothesis", payload, src=src)]
    for v in obj.get("verdicts") or []:
        out.append(records.belief(
            subject=v["subject"],
            # Fixed for this leg: the question trace answers about a method is always
            # whether it defends the class under review. The class is data; the
            # predicate is the shape of the question, and is not the agent's to pick.
            predicate="sanitizes",
            object_=vuln_class,
            verdict=v["verdict"],
            rationale=v["rationale"],
            audited_by=src,
        ))
    return out


def check_hypothesis(obj: dict, log_ids: dict[str, str], dynamic: bool,
                     vuln_class: str | None = None,
                     class_title: str | None = None) -> None:
    _require(obj, HYPOTHESIS_FIELDS, "hypothesis")
    if vuln_class is not None and obj["vuln_class"] not in _class_aliases(vuln_class, class_title):
        # Observed on the first local-model run and again on a 0.5B: the model wrote
        # the class's human TITLE ("SQL injection") where the briefing's `class`
        # identifier belongs. Every judgement was correct and four of them still fell
        # out of every downstream query keyed on class — a silent partial result,
        # which is worse than a loud failure.
        #
        # The title is now accepted as an alias, because both spellings come from the
        # same manifest and the mismatch was a formatting slip, not a judgement error
        # — and constrained decoding exists precisely to keep formatting out of the
        # measurement. Naming a DIFFERENT class is still rejected: that is a
        # comprehension failure, and the class is not the agent's to invent.
        raise AdmitError(
            f"hypothesis is labelled vuln_class {obj['vuln_class']!r} but is being "
            f"admitted under {vuln_class!r} — use the briefing's `class` verbatim")
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
    p.add_argument("--type", required=True, choices=("hypothesis", "finding", "trace"),
                   help="`trace` takes a revised case and expands it into a child\n"
                        "hypothesis plus one belief per verdict")
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--lang", required=True)
    p.add_argument("--src", required=True,
                   help="who produced this: agent:hypothesize, human, ...")
    p.add_argument("--dynamic", action="store_true",
                   help="this run has a dynamic verification tier (Phase 4); off by default")
    p.add_argument("--dry-run", action="store_true", help="validate only, write nothing")
    args = p.parse_args(argv)

    try:
        klass = load_class(args.vuln_class)
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

    log_recs = {r["id"]: r for r in store.read()}
    log_ids = {k: v.get("type", "?") for k, v in log_recs.items()}

    built = []
    try:
        for obj in objs:
            if args.type == "hypothesis":
                check_hypothesis(obj, log_ids, args.dynamic, args.vuln_class, klass.title)
                # Normalise to the identifier. An alias is accepted at the door and
                # never survives it, so nothing downstream has to know about one.
                built.append(records.record(
                    args.type, dict(obj, vuln_class=args.vuln_class), src=args.src))
            elif args.type == "trace":
                check_trace(obj, log_recs, args.dynamic, args.vuln_class, klass.title)
                new = expand_trace(obj, log_recs, args.vuln_class, args.src)
                # The snapshot predates this batch, so two revisions of one parent in
                # a single call would both pass the fork check above. Fold each child
                # in as it is built and the second one sees the first.
                log_recs.update({r["id"]: r for r in new})
                built.extend(new)
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
    by_type: dict[str, int] = {}
    for rec in built:
        by_type[rec["type"]] = by_type.get(rec["type"], 0) + 1
    print(json.dumps({"cmd": "admit", "type": args.type, "admitted": len(built),
                      "cases": len(objs), "by_type": dict(sorted(by_type.items())),
                      "dry_run": bool(args.dry_run), "ceiling": ceiling,
                      "src": args.src}, separators=(",", ":")), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
