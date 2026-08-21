"""`brief` — assemble exactly what an agent is allowed to see (design §7).

Deterministic: it reads the log and the manifest and joins them. It makes no LLM
call, decides nothing, and ranks nothing by "severity" — that is the agent's job
and it must be done from the evidence, not from a number this tool invented.

Output is JSONL: one `briefing` header, then one `case` per (source, sink) pair.
Cases are the join of `reachable` and `sanitizer_on_path` facts on
(sink_file, sink_line, source_file, source_line, source_name) — the key the two
queries were deliberately built to share.

    brief --agent hypothesize --class sqli --lang java
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .. import records
from ..belief import store
from ..manifest.loader import ManifestError, load_class, load_patterns, tier_table

CASE_KEY = ("sink_file", "sink_line", "source_file", "source_line", "source_name")


def _key(f: dict) -> tuple:
    return tuple(f.get(k) for k in CASE_KEY)


def _cases(log: list[dict]) -> list[dict]:
    flows = {_key(f): f for f in log if f.get("kind") == "flow"}
    checks = {_key(f): f for f in log if f.get("kind") == "sanitizer_check"}
    # A sink inventory entry lets a case say whether the statement text was
    # runtime-built, which `reachable` alone does not carry.
    sinks = {(f.get("file"), f.get("line")): f for f in log if f.get("kind") == "sink_candidate"}

    out = []
    for key, flow in sorted(flows.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        check = checks.get(key)
        sink = sinks.get((flow.get("sink_file"), flow.get("sink_line")))
        evidence = [flow["id"]] + ([check["id"]] if check else []) + ([sink["id"]] if sink else [])
        out.append({
            "kind": "case",
            "evidence": evidence,
            "source": {
                "name": flow.get("source_name"), "marker": flow.get("source_marker"),
                "origin": flow.get("source_origin"), "code": flow.get("source_code"),
                "file": flow.get("source_file"), "line": flow.get("source_line"),
                "method": flow.get("subject"),
            },
            "sink": {
                "name": flow.get("sink_name"), "full_name": flow.get("sink_full_name"),
                "code": flow.get("sink_code"), "arg_code": flow.get("sink_arg_code"),
                "file": flow.get("sink_file"), "line": flow.get("sink_line"),
                "method": flow.get("object"),
                # From the sink inventory, when present: is the statement text a
                # compile-time literal? A literal sink is a different animal.
                "arg_is_literal": (sink or {}).get("arg_is_literal"),
            },
            "path": {
                "length": flow.get("path_length"), "methods_crossed": flow.get("crosses_methods"),
                "engine_paths": flow.get("path_count"), "steps": flow.get("steps", []),
            },
            "sanitizers": {
                "candidates": (check or {}).get("candidate_sanitizers", []),
                "reported_paths": (check or {}).get("reported_paths"),
                "reported_paths_without_sanitizer":
                    (check or {}).get("reported_paths_without_sanitizer"),
                # Restated per case so it cannot be missed at the point of use.
                "caveat": ("engine paths are representative, not exhaustive: a route with no "
                           "sanitizer may exist without being reported"),
            } if check else None,
        })
    return out


def _beliefs_for(cases: list[dict]) -> list[dict]:
    """Beliefs about sanitizers that actually appear in these cases — so the
    agent prunes what was already audited instead of re-litigating it."""
    names = {c["name"] for case in cases for c in (case["sanitizers"] or {}).get("candidates", [])}
    live = store.project()
    return [rec for key, rec in sorted(live.items())
            if any(n and n in key[0] for n in names) or key[0] in names]


INSTRUCTIONS = {
    "hypothesize": [
        "Every claim about reachability, dataflow or call edges MUST come from a case's"
        " evidence and cite the fact ids. If it did not come from a fact, it is a"
        " hypothesis and must be labelled as one.",
        "You may not assert that a flow is sanitized. A sanitizer candidate on a path is"
        " a fact; its effectiveness is a belief and belongs in the belief store with a"
        " rationale.",
        "Engine paths are representative, not exhaustive. Absence of a clean reported"
        " path is not evidence that every route is sanitized.",
        "Judge each case on its evidence. A sink whose name matched but which is not a"
        " database call at all should be refuted, and say why.",
        "Do not name the vuln class from your own knowledge — the narrative above is the"
        " only description of it you are given.",
    ],
    "report": [
        "One finding per hypothesis you are given; do not invent hypotheses.",
        "The recreation flow must be something a human can follow by hand against the"
        " source: entry point, the parameter to control, the transformation, the sink.",
        "Cite file:line references that came from the evidence, never from memory.",
        "Tier is capped by the briefing's max_static_tier and may not be raised.",
    ],
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="brief", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--agent", required=True, choices=sorted(INSTRUCTIONS))
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--lang", required=True)
    p.add_argument("--limit", type=int, help="first N cases only (for a cheap dry run)")
    p.add_argument("--status", default="proposed",
                   help="report agent: which hypothesis status to brief on")
    args = p.parse_args(argv)

    try:
        vc = load_class(args.vuln_class)
        patterns = load_patterns(args.vuln_class, args.lang)
    except ManifestError as e:
        raise SystemExit(f"brief: {e}")

    log = list(store.read())
    tiers = tier_table()
    ceiling = patterns.max_static_tier

    header: dict[str, Any] = {
        "kind": "briefing", "agent": args.agent,
        "class": vc.name, "title": vc.title, "language": args.lang,
        # The ONLY description of the class an agent gets. Everything the model
        # would otherwise supply from its own priors must come from here.
        "narrative": vc.narrative,
        "seed_hypotheses": vc.seed_hypotheses,
        "max_static_tier": ceiling,
        "tier_claim": tiers[ceiling]["claim"],
        "reachability_assessed": patterns.reachability_assessed(),
        "instructions": INSTRUCTIONS[args.agent],
    }

    if args.agent == "hypothesize":
        cases = _cases(log)
        if args.limit:
            cases = cases[:args.limit]
        beliefs = _beliefs_for(cases)
        header["cases"] = len(cases)
        header["prior_beliefs"] = len(beliefs)
        rows = cases
    else:
        wanted = {h["id"]: h for h in log
                  if h.get("type") == "hypothesis" and h.get("status") == args.status}
        by_id = {r["id"]: r for r in log}
        rows = []
        for hid, h in sorted(wanted.items()):
            rows.append({"kind": "hypothesis", "hypothesis": h,
                         "evidence": [by_id[e] for e in h.get("evidence", []) if e in by_id]})
        beliefs = []
        header["hypotheses"] = len(rows)
        header["status_filter"] = args.status

    print(json.dumps(header, ensure_ascii=False, separators=(",", ":")))
    for b in beliefs:
        print(json.dumps({"kind": "prior_belief", **b}, ensure_ascii=False,
                         separators=(",", ":")))
    for row in rows:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))

    print(json.dumps({"cmd": "brief", "agent": args.agent, "rows": len(rows),
                      "beliefs": len(beliefs), "log": str(store.log_path())},
                     separators=(",", ":")), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
