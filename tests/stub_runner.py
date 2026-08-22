#!/usr/bin/env python3
"""A model that isn't one — the deterministic double behind the `run_agent` seam.

Reads prompt+briefing on stdin exactly as a real runner does and emits the
dullest defensible output: one hypothesis per case, one finding per hypothesis,
citing evidence copied verbatim from the briefing. It judges nothing.

Two jobs:
  1. the whole brief -> run_agent -> admit -> render chain is testable with zero
     model calls, which is what keeps CLAUDE.md's "determinism first" honest;
  2. it is the null baseline a real model has to beat. A model that produces the
     same 26 undifferentiated `needs_proof` rows as this script has added nothing,
     and that is only visible if the floor is something you can actually run.

It deliberately emits a little prose too, because real models do, and discarding
that is behaviour `run_agent` has to get right.
"""

import json
import sys


def main() -> int:
    agent = sys.argv[1] if len(sys.argv) > 1 else "hypothesize"
    rows = []
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue

    header = next((r for r in rows if r.get("kind") == "briefing"), {})
    vuln_class = header.get("class", "unknown")
    out = []

    if agent == "hypothesize":
        for case in [r for r in rows if r.get("kind") == "case"]:
            src, snk = case["source"], case["sink"]
            out.append({
                "statement": f"{src['name']} reaches {snk['name']} at "
                             f"{snk['file']}:{snk['line']}",
                "vuln_class": vuln_class,
                "status": "needs_proof",
                "confidence": 0.5,
                "evidence": case["evidence"],
                "case": f"{snk['file']}:{snk['line']}",
                "reasoning": "Stub runner: reported verbatim from the case evidence, "
                             "with no judgement applied.",
            })
    else:
        for row in [r for r in rows if r.get("kind") == "hypothesis"]:
            h = row["hypothesis"]
            refs = sorted({f"{e.get('sink_file') or e.get('file')}:"
                           f"{e.get('sink_line') or e.get('line')}"
                           for e in row.get("evidence", [])
                           if e.get("sink_file") or e.get("file")})
            out.append({
                "hypothesis": h["id"],
                "title": h["statement"][:120],
                "tier": header.get("max_static_tier", "static_pattern"),
                "severity": "medium",
                "refs": refs or ["unknown:0"],
                "recreation": "Stub runner: no recreation flow was reasoned about.",
            })

    print(f"Here are the {len(out)} records:")   # prose `run_agent` must discard
    print("```json")
    for obj in out:
        print(json.dumps(obj, separators=(",", ":")))
    print("```")
    return 0


if __name__ == "__main__":
    sys.exit(main())
