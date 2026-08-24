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
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from .. import records
from ..belief import store
from ..cpg.workspace import repo_root
from ..manifest.loader import ManifestError, load_class, load_patterns, tier_table

CASE_KEY = ("sink_file", "sink_line", "source_file", "source_line", "source_name")

# Fields a path step repeats from the step before it. Measured on WebGoat: steps are
# 67% of the briefing, and inside them `file` (~95 chars) and the fully-qualified
# `method` (~150 chars) are restated on every step while the `code` that carries the
# actual meaning tops out at 79. Consecutive steps almost always share both.
CARRIED_STEP_FIELDS = ("file", "method")


def _slim_steps(steps: list[dict]) -> list[dict]:
    """Drop a step field when it is unchanged from the previous step.

    Lossless — a reader carries the last stated value forward — and worth 39% of the
    whole briefing on WebGoat. That is a third off the prefill, but the reason to do
    it is that 44KB of repeated boilerplate is 44KB the model reads past to find the
    three lines that matter.
    """
    out, prev = [], {}
    for step in steps:
        out.append({k: v for k, v in step.items()
                    if not (k in CARRIED_STEP_FIELDS and prev.get(k) == v)})
        prev = step
    return out


def _key(f: dict) -> tuple:
    return tuple(f.get(k) for k in CASE_KEY)


def _cases(log: list[dict]) -> list[dict]:
    flows = {_key(f): f for f in log if f.get("kind") == "flow"}
    checks = {_key(f): f for f in log if f.get("kind") == "sanitizer_check"}
    # A sink inventory entry lets a case say whether the statement text was
    # runtime-built, which `reachable` alone does not carry.
    #
    # BOTH substrates emit `sink_candidate` at the same file:line — opengrep rules
    # declare that kind too — and the design encourages both to accrete into one
    # log. A plain last-wins dict therefore lets an opengrep fact (which has no
    # `arg_is_literal`) displace the CPG one, silently dropping the field on every
    # case. Prefer whichever record actually carries what this case will read.
    sinks: dict[tuple, dict] = {}
    for f in log:
        if f.get("kind") != "sink_candidate":
            continue
        key = (f.get("file"), f.get("line"))
        prev = sinks.get(key)
        if prev is None or ("arg_is_literal" not in prev and "arg_is_literal" in f):
            sinks[key] = f

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
                # The static type of the tainted argument, and whether the frontend
                # actually resolved it. Sinks are matched on a short name, so this is
                # the one piece of evidence that settles "is this even the right kind
                # of call" without appealing to what anything is named.
                "arg_type": flow.get("sink_arg_type"),
                "arg_type_resolved": flow.get("sink_arg_type_resolved"),
                "file": flow.get("sink_file"), "line": flow.get("sink_line"),
                "method": flow.get("object"),
                # From the sink inventory, when present: is the statement text a
                # compile-time literal? A literal sink is a different animal.
                "arg_is_literal": (sink or {}).get("arg_is_literal"),
            },
            "path": {
                "length": flow.get("path_length"), "methods_crossed": flow.get("crosses_methods"),
                "engine_paths": flow.get("path_count"),
                "steps": _slim_steps(flow.get("steps", [])),
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


def _beliefs_for_trace(rows: list[dict]) -> list[dict]:
    """Beliefs about the methods THIS batch is about to read.

    `trace` is the agent that produces beliefs, which makes it the one that most
    needs to see them: the store exists so a later run prunes instead of re-auditing,
    and an agent shown none will cheerfully re-litigate a sanitizer someone already
    settled — and may contradict it, leaving two verdicts and no way to tell which
    the reviewer meant. Keyed on the exact method full name, because that is what a
    verdict's subject is.
    """
    subjects = {c.get("full_name") for row in rows for c in row.get("callees", [])
                if c.get("full_name")}
    live = store.project()
    return [rec for key, rec in sorted(live.items()) if key[0] in subjects]



# --------------------------------------------------------------------- trace

def depth_config() -> dict[str, Any]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    path = base / "depth.yaml"
    if not path.is_file():
        raise SystemExit(f"brief: missing depth control config: {path}")
    doc = yaml.safe_load(path.read_text()) or {}
    d = doc.get("depth") or {}
    gate = d.get("spend_gate", "rising_confidence")
    if gate not in ("rising_confidence", "always"):
        raise SystemExit(f"brief: config/depth.yaml: unknown spend_gate {gate!r}")
    return {"max": int(d.get("max", 3)), "spend_gate": gate,
            "checkpoint_every": int(d.get("checkpoint_every", 0))}


def callees_of(h: dict, by_id: dict[str, dict]) -> list[str]:
    """Which methods this hypothesis needs read, decided mechanically from its own
    evidence — the sink it lands in, and every sanitizer candidate on the path.

    The SUBSTRATE picks what to read, not the model. An agent that chose its own
    reading list would be steering the deterministic layer, and a name it invented
    would come back `not_in_cpg` looking like a fact about the code.
    """
    names: set[str] = set()
    for fid in h.get("evidence", []):
        f = by_id.get(fid)
        if not f:
            continue
        # The sink itself, and every candidate sanitizer on the path. On a JDK-heavy
        # class these are mostly library methods and come back `external_stub` — a
        # stated gap, which is the honest answer and not the same as "nothing there".
        if f.get("sink_full_name"):
            names.add(f["sink_full_name"])
        for cand in f.get("candidate_sanitizers", []) or []:
            if cand.get("full_name"):
                names.add(cand["full_name"])
        # The methods the flow actually passes THROUGH, which is where the readable
        # code lives. Measured on WebGoat SQLi: every sink and every sanitizer
        # candidate resolves into java.sql or java.lang and has no body in the tree,
        # so a reading list of those alone would have returned eight stubs and taught
        # the agent nothing. `subject` and `object` are the enclosing methods of the
        # source and the sink; the steps carry each hop between them.
        for key in ("subject", "object"):
            if f.get(key):
                names.add(f[key])
        for step in f.get("steps", []) or []:
            if step.get("method"):
                names.add(step["method"])
    return sorted(names)


def traceable(log: list[dict], status: str, cfg: dict[str, Any]) -> list[dict]:
    """Hypotheses this round may descend into (§4.2).

    Three gates, and each one is a different reason to stop:
      * a leaf only — a hypothesis that already has a child was traced already,
        and re-tracing it would fork the tree instead of deepening it;
      * `depth < max` — the hard stop, without which "and what does THAT call"
        never terminates;
      * the spend gate — descend only where the last level made the case stronger.
    """
    hyps = [h for h in log if h.get("type") == "hypothesis"]
    by_id = {h["id"]: h for h in hyps}
    has_child = store.revised_hypotheses(log)
    out = []
    for h in hyps:
        if h.get("status") != status or h["id"] in has_child:
            continue
        depth = int(h.get("depth", 0) or 0)
        if depth >= cfg["max"]:
            continue
        if cfg["spend_gate"] == "rising_confidence":
            parent = by_id.get(h.get("parent") or "")
            if parent is not None and float(h.get("confidence", 0)) <= float(
                    parent.get("confidence", 0)):
                # The last level cost budget and did not make the case stronger.
                # Descending again is how a rabbit hole eats an afternoon.
                continue
        out.append(h)
    return sorted(out, key=lambda h: h["id"])


def _slim_evidence(f: dict) -> dict:
    """A fact as an agent should see it: path steps carry forward, as in `_cases`."""
    if not f.get("steps"):
        return f
    return {**f, "steps": _slim_steps(f["steps"])}


def _slim_callee(c: dict) -> dict:
    """Drop what the body already says.

    Measured on a two-case WebGoat trace briefing: the `calls` list was 47% of the
    whole thing (26KB of 55KB), and with the method's own source right beside it most
    of that is the same text twice — each call's `code`, and every `<operator>` entry
    for a concatenation the reader can see written out. What the list adds over the
    body is the *resolved* callee name, so that is what is kept.

    Only when the body is actually there. When it is not, `statements` and `calls` are
    the only view of the method that exists and every field earns its place.
    """
    if c.get("status") != "resolved" or not str(c.get("body", "")).strip():
        return c
    out = {k: v for k, v in c.items() if k != "statements"}
    # Deduped: a lesson method calls `build`, `feedback` and `failed` three or four
    # times each, and the list repeats every one. What a reader needs is *which*
    # methods this one calls and whether the frontend resolved them — that is a set,
    # not a sequence, and the sequence is in the body anyway.
    seen: dict[tuple, dict] = {}
    for x in c.get("calls", []):
        if x.get("is_operator"):
            continue
        key = (x.get("name"), x.get("full_name"))
        if key in seen:
            seen[key]["times"] += 1
            continue
        seen[key] = {"name": x.get("name"), "full_name": x.get("full_name"),
                     "line": x.get("line"), "resolved": x.get("resolved"), "times": 1}
    out["calls"] = list(seen.values())
    # Say what was dropped, so a short list is not read as a short method.
    out["calls_omitted_operators"] = sum(1 for x in c.get("calls", []) if x.get("is_operator"))
    return out


def _trace_rows(log: list[dict], status: str, cfg: dict[str, Any]) -> list[dict]:
    by_id = {r["id"]: r for r in log}
    bodies: dict[str, dict] = {}
    for f in log:
        if f.get("kind") == "callee_body":
            # Latest wins: a re-run after a source change supersedes the old read.
            bodies[f.get("full_name", "")] = f
    rows = []
    for h in traceable(log, status, cfg):
        wanted = callees_of(h, by_id)
        rows.append({
            "kind": "trace_case",
            "hypothesis": {k: h.get(k) for k in
                           ("id", "statement", "status", "confidence", "depth", "parent")},
            # Same step-slimming the flat pass gets: on a trace briefing the path
            # steps were 36% of the whole thing, and a step repeats the previous
            # step's file and fully-qualified method far more often than not.
            #
            # Callee bodies are EXCLUDED here because `callees` below carries them in
            # full, with their ids. Once a revision cites the bodies it read, they
            # land in its own evidence — so re-tracing it sent every body twice and
            # the briefing went from ~20KB to 44KB (~19k tokens against a 16384
            # context). Depth 2 was unreachable for that reason alone.
            "evidence": [_slim_evidence(by_id[e]) for e in h.get("evidence", [])
                         if e in by_id and by_id[e].get("kind") != "callee_body"],
            # One entry per method asked for, present or not. A callee the substrate
            # could not read is a GAP, and it must be visible as one — an agent that
            # sees a short list infers the missing ones were unremarkable.
            "callees": [_slim_callee(bodies.get(n, {"full_name": n, "status": "not_queried"}))
                        for n in wanted],
        })
    return rows


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
    "trace": [
        "You are shown a method's real source. Argue from what the code does — the"
        " calls it makes, the type of the value it receives — and never from what a"
        " file, package or method is named. A name is the weakest argument there is.",
        "A callee with status `external_stub`, `not_in_cpg`, `source_unavailable` or"
        " `not_queried` was NOT read. That is a gap in coverage, never evidence that"
        " the code is harmless; if the gap is what decides the case, say `inconclusive`.",
        "Deciding a sanitizer works is a belief, not a fact: give a verdict from the"
        " vocabulary and a rationale that quotes the code you read.",
        "Confidence must move for a stated reason. If the body changed nothing, keep"
        " the number and say what you looked for and did not find.",
        "Every fact id you cite must be one you were given, including the callee bodies.",
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
    p.add_argument("--status",
                   help="report/trace agents: which hypothesis status to brief on"
                        " (default: proposed for report, needs_proof for trace)")
    p.add_argument("--chunk-size", type=int, metavar="N",
                   help="emit rows in batches of N; see --chunk")
    p.add_argument("--chunk", type=int, default=0, metavar="I",
                   help="which batch to emit, 0-based (default 0)")
    p.add_argument("--chunks", action="store_true",
                   help="print how many batches --chunk-size yields, and exit")
    p.add_argument("--callees", action="store_true",
                   help="trace agent: emit a callee_body params object and exit, so the"
                        " substrate can be asked for the bodies BEFORE the briefing is"
                        " assembled (`brief --callees | cpg query --params-from -`)")
    args = p.parse_args(argv)
    if args.chunk_size is not None and args.chunk_size < 1:
        raise SystemExit("brief: --chunk-size must be at least 1")
    if args.chunk and args.chunk_size is None:
        raise SystemExit("brief: --chunk needs --chunk-size")
    if args.callees and args.agent != "trace":
        raise SystemExit("brief: --callees is only meaningful for --agent trace")
    if args.status is None:
        args.status = "needs_proof" if args.agent == "trace" else "proposed"

    try:
        vc = load_class(args.vuln_class)
        patterns = load_patterns(args.vuln_class, args.lang)
    except ManifestError as e:
        raise SystemExit(f"brief: {e}")

    log = list(store.read())

    if args.callees:
        cfg = depth_config()
        by_id = {r["id"]: r for r in log}
        wanted = sorted({n for h in traceable(log, args.status, cfg)
                         for n in callees_of(h, by_id)})
        if not wanted:
            # A params object with no methods would make `callee_body` throw, which
            # is the right end but the wrong message. Say which of the two happened:
            # no hypothesis was eligible, or the eligible ones named no callee.
            raise SystemExit(
                f"brief: nothing to read — no hypothesis at status {args.status!r} is"
                f" eligible to descend (depth max {cfg['max']}, spend_gate"
                f" {cfg['spend_gate']}), or none names a callee")
        print(json.dumps({"methods": wanted}, ensure_ascii=False, separators=(",", ":")))
        print(json.dumps({"cmd": "brief", "agent": "trace", "callees": len(wanted),
                          "status": args.status, "log": str(store.log_path())},
                         separators=(",", ":")), file=sys.stderr)
        return 0
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
        # Stated once per briefing rather than on every step, which is the point.
        "step_fields_carry_forward": list(CARRIED_STEP_FIELDS),
    }

    if args.agent == "hypothesize":
        rows = _cases(log)
        # Already judged. This leg reads cases off FACTS, so nothing removed a case
        # once a hypothesis existed for it: re-running the pass — after an
        # interruption, or just twice — wrote a second hypothesis for every case, and
        # hypotheses are ULID events so nothing dedupes them. `score` then counts one
        # site twice and calibration gets duplicate points.
        #
        # To compare two models, give each its own log. That is what `--src` filtering
        # cannot do for you once both have written to the same one.
        judged = {e for h in log if h.get("type") == "hypothesis"
                  for e in h.get("evidence", [])}
        rows = [r for r in rows if not (set(r["evidence"]) & judged)]
        if args.limit:
            rows = rows[:args.limit]
        header["status_filter"] = None
    elif args.agent == "trace":
        cfg = depth_config()
        rows = _trace_rows(log, args.status, cfg)
        if args.limit:
            rows = rows[:args.limit]
        header["status_filter"] = args.status
        header["depth"] = cfg
        # The trust vocabulary is data; the agent must pick from it, not invent one.
        header["verdicts"] = {k: v.get("claim", "") for k, v in store.verdicts().items()}
    else:
        # Leaves only. After a trace level every site has a hypothesis at each depth
        # it was traced through, all of them at the same status: briefing the lot
        # writes the same site up once per level and the report reads as though the
        # substrate found twice what it found. Measured on WebGoat: 23 sites, 46 rows.
        stale = store.revised_hypotheses(log)
        # Already written up. Unlike `trace`, this leg is not self-consuming — a
        # finding does not remove its hypothesis from the selection — so a pass that
        # died halfway used to re-brief everything on the next run and write a SECOND
        # finding for every case it had already done. Findings are ULID events, so
        # nothing dedupes them and the report simply doubles. Skipping them makes the
        # pass resumable and idempotent, which is what every other leg already is.
        reported = {r["hypothesis"] for r in log
                    if r.get("type") == "finding" and r.get("hypothesis")}
        wanted = {h["id"]: h for h in log
                  if h.get("type") == "hypothesis" and h.get("status") == args.status
                  and h["id"] not in stale and h["id"] not in reported}
        by_id = {r["id"]: r for r in log}
        rows = []
        for hid, h in sorted(wanted.items()):
            # Slimmed the same way trace's rows are. This leg never had it, and once
            # `trace` puts callee bodies into a hypothesis's evidence the report
            # briefing inherits them: 14.2k tokens for four cases, against 4k before
            # branching existed. A pass that has run fine for weeks can be pushed over
            # a context limit by a change two legs upstream.
            rows.append({"kind": "hypothesis", "hypothesis": h,
                         "evidence": [_slim_callee(_slim_evidence(by_id[e]))
                                      for e in h.get("evidence", []) if e in by_id]})
        if args.limit:
            rows = rows[:args.limit]
        header["status_filter"] = args.status

    total = len(rows)
    # Chunked: 0 when nothing is left, so a driver drains by looping until this reaches
    # zero — `max(1, ...)` would make an exhausted queue look like one more batch.
    # Unchunked: always one batch, even an empty one, because that caller asked for the
    # whole selection and an empty selection is an answer.
    n_chunks = 1 if args.chunk_size is None else -(-total // args.chunk_size)
    if args.chunks:
        # A driver needs the batch count before it can loop. Deliberately on stdout
        # and nothing else, so `for i in $(seq 0 $(($(brief ... --chunks) - 1)))`
        # works without parsing JSON.
        print(n_chunks)
        return 0
    if args.chunk >= n_chunks:
        raise SystemExit(f"brief: --chunk {args.chunk} is past the last batch "
                         f"({n_chunks} batch(es) of {args.chunk_size} over {total} row(s))")
    if args.chunk_size is not None:
        start = args.chunk * args.chunk_size
        rows = rows[start:start + args.chunk_size]

    # An agent given four cases must not conclude that four is all there is —
    # it changes what "this is the only one of its kind" would mean.
    header["chunk"] = {"index": args.chunk, "of": n_chunks, "rows": len(rows),
                       "rows_total": total}
    if args.agent == "hypothesize":
        beliefs = _beliefs_for(rows)
    elif args.agent == "trace":
        beliefs = _beliefs_for_trace(rows)
    else:
        beliefs = []
    header["cases" if args.agent == "hypothesize" else "hypotheses"] = len(rows)
    header["prior_beliefs"] = len(beliefs)

    written = 0
    for obj in [header] + [{"kind": "prior_belief", **b} for b in beliefs] + rows:
        line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        print(line)
        written += len(line.encode()) + 1

    # `bytes` because rows are a bad proxy for size and this is the number that
    # actually fails: a two-case trace briefing carrying callee source ran to 15.4k
    # tokens against a 16384 context and the batch died mid-record. Note that
    # bytes/4 is the wrong conversion for source — Java identifiers and code
    # measured about 2.3 chars per token, so budget against the smaller number.
    print(json.dumps({"cmd": "brief", "agent": args.agent, "rows": len(rows),
                      "rows_total": total, "chunk": args.chunk, "chunks": n_chunks,
                      "beliefs": len(beliefs), "bytes": written,
                      "log": str(store.log_path())},
                     separators=(",", ":")), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
