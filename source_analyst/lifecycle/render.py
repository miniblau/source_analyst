"""`render` — findings in the log to a document a human reads (design §7).

Deterministic and last in the chain: it reformats records and adds nothing. No
severity is invented here, no claim is upgraded, and anything the finding does
not say is not said.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from ..belief import store
from ..cpg.workspace import repo_root
from ..manifest.loader import load_class, tier_table

ORDER = {s: i for i, s in enumerate(("critical", "high", "medium", "low", "info"))}


class RenderError(Exception):
    """The report cannot be produced correctly. Always fatal — a report that is
    quietly missing a section is worse than no report."""


def bands() -> list[dict[str, Any]]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    doc = yaml.safe_load((base / "triage.yaml").read_text())
    rows = (doc or {}).get("bands")
    if not rows:
        raise RenderError("config/triage.yaml: expected a non-empty `bands` list")
    rows = sorted(rows, key=lambda b: -float(b["min"]))
    if float(rows[-1]["min"]) != 0.0:
        raise RenderError("config/triage.yaml: the last band must have min 0.0, or a "
                          "finding can fall through the summary and be omitted")
    return rows


def band_of(conf: Any, table: list[dict[str, Any]]) -> str:
    """Which band a confidence falls in. A missing confidence is its own bucket —
    silently filing it under the weakest band would invent a judgement."""
    if not isinstance(conf, (int, float)):
        return "unscored"
    for b in table:
        if float(conf) >= float(b["min"]):
            return b["name"]
    return "unscored"


def site_of(rec: dict, by_id: dict[str, dict]) -> str:
    """Where this is, from the evidence facts. Only a *report* falls back to the
    agent's own `case` string — a heading has to say something, whereas `score` must
    not grade a site the model merely asserted."""
    return store.site_of(rec, by_id) or str(rec.get("case", "?"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="render", description=__doc__)
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--target", default="the reviewed source tree")
    args = p.parse_args(argv)

    log = list(store.read())
    by_id = {r["id"]: r for r in log}
    # Leaves only. A traced log holds one hypothesis per level per site: counting the
    # whole chain inflates every status tally, lists a refuted case once per level it
    # was traced through, and makes "every candidate was refuted" fire on a set that
    # is mostly its own history.
    stale = store.revised_hypotheses(log)
    all_findings = [r for r in log if r.get("type") == "finding"]
    # A finding is a write-up OF a hypothesis. When a later level revised that
    # hypothesis the write-up describes a judgement that has been superseded, and
    # rendering both puts the same site in the report twice — once with the old
    # confidence. Dropped, and counted, because a report that is quietly shorter than
    # the log is its own kind of lie.
    findings = [f for f in all_findings if f.get("hypothesis") not in stale]
    stale_findings = len(all_findings) - len(findings)
    hyps = [r for r in log if r.get("type") == "hypothesis" and r["id"] not in stale]
    refuted = [h for h in hyps if h.get("status") == "refuted"]
    unsettled = [h for h in hyps if h.get("status") == "inconclusive"]
    beliefs = store.project()
    vc = load_class(args.vuln_class)
    tiers = tier_table()

    findings.sort(key=lambda f: (ORDER.get(f.get("severity", "info"), 9), f.get("title", "")))
    counts = Counter(f.get("severity") for f in findings)
    facts = Counter(r.get("kind", "?") for r in log if r.get("type") == "fact")
    by_status = Counter(h.get("status", "?") for h in hyps)

    w = sys.stdout.write
    w(f"# {vc.title} — review of {args.target}\n\n")
    if findings:
        w(f"{len(findings)} finding(s): "
          + ", ".join(f"{n} {s}"
                      for s, n in sorted(counts.items(), key=lambda kv: ORDER.get(kv[0], 9)))
          + f". {len(refuted)} candidate(s) refuted during triage.\n\n")
    else:
        w("**No findings — and that is not the same as a clean result.**\n\n")
    w(f"> **What this is.** {vc.narrative}\n\n")
    # With no findings there are no tiers to describe, so fall back to the class
    # ceiling — otherwise this sentence renders as "static-only.  means: .".
    shown = sorted({f["tier"] for f in findings if f.get("tier") in tiers}) or [vc.max_static_tier]
    w("> **What this is not.** Every finding below is static-only. "
      + " ".join(shown)
      + " means: " + "; ".join(tiers[x]["claim"] for x in shown if x in tiers)
      + ". Nothing was executed against a running target, so no finding here is confirmed."
      + " The dataflow engine enumerates *representative* paths, not every route, so the"
      + " paths quoted below are examples rather than an inventory.\n\n")

    # ---- Triage summary -----------------------------------------------------
    # Deterministic: counted off the log, never asked of a model. Confidence comes
    # from the hypothesis the finding rests on, so the table reports how much of the
    # evidence survived, not how likely a bug is to be real.
    table = bands()
    conf_of = {f["id"]: by_id.get(f.get("hypothesis"), {}).get("confidence") for f in findings}
    grid: dict[str, Counter] = {}
    for f in findings:
        grid.setdefault(band_of(conf_of[f["id"]], table), Counter())[f.get("severity", "info")] += 1

    sevs = sorted({f.get("severity", "info") for f in findings}, key=lambda s: ORDER.get(s, 9))
    order = [b["name"] for b in table] + ["unscored"]
    sites = {site_of(by_id.get(f.get("hypothesis"), {}), by_id) for f in findings}

    w("## At a glance\n\n")
    if findings:
        w(f"**{len(findings)} finding(s)** across **{len(sites)} distinct site(s)**"
          + (" \u2014 more findings than sites means several tainted parameters reach the "
             "same sink." if len(findings) > len(sites) else ".")
          + (f" **{len(refuted)}** further candidate(s) were refuted; they are listed at "
             f"the end and are worth a look." if refuted else "")
          + "\n\n")
        # Also on a report that HAS findings. It was originally only in the
        # zero-findings branch, which is precisely the reader who does not need it:
        # someone holding 21 findings off a log containing 23 is the one entitled to
        # know why two are missing.
        if stale:
            w(f"> **{len(stale)}** hypothesis/es"
              + (f" and **{stale_findings}** finding(s)" if stale_findings else "")
              + " in this log were superseded by a later `trace` level and are not"
                " shown; what appears below is each case as it now stands.\n\n")
    else:
        # Invariant #8 at the last mile. Every tool in this repo refuses to let zero
        # results read as "nothing here"; the report a human actually reads must do
        # the same, and it is the one place the mistake is expensive.
        w("Zero findings has several meanings and only the numbers say which:\n\n")
        w(f"- substrate facts in this log: **{sum(facts.values())}**"
          + (f" ({', '.join(f'{n} {k}' for k, n in sorted(facts.items()))})" if facts else "")
          + "\n")
        w(f"- hypotheses: **{len(hyps)}**"
          + (f" ({', '.join(f'{n} {s}' for s, n in sorted(by_status.items()))})"
             if hyps else "") + "\n")
        if stale:
            w(f"- superseded by a later `trace` level and not counted above: "
              f"**{len(stale)}** hypothesis/es"
              + (f", **{stale_findings}** finding(s)" if stale_findings else "") + "\n")
        w("\n")
        if not facts:
            w("**Nothing was analysed.** No query has written a fact to this log, so this "
              "document reports on nothing at all. Run the substrate queries first.\n\n")
        elif not hyps:
            w("**Nothing was judged.** The substrate found candidates and no agent has "
              "assessed them. Run the hypothesize pass.\n\n")
        elif len(refuted) == len(hyps):
            w("**Every candidate was refuted.** The substrate did find paths; an agent "
              "judged all of them not to be instances of this class. Those judgements are "
              "listed below and are exactly what to check \u2014 this is the shape a "
              "false-negative run takes.\n\n")
        else:
            w("**Judged but not written up.** Hypotheses survived triage and no finding "
              "was produced from them. Run the report pass.\n\n")
        w("None of these is evidence that the code is safe. A sink shape no query can "
          "reach produces the same silence as a clean tree.\n\n")
    if findings:
        w("| confidence | " + " | ".join(sevs) + " | total |\n")
        w("|---" * (len(sevs) + 2) + "|\n")
        for name in [n for n in order if n in grid]:
            row = grid[name]
            spec = next((b for b in table if b["name"] == name), None)
            label = f"**{name}**" + (f" (\u2265{spec['min']:g})" if spec else " (no confidence)")
            w(f"| {label} | " + " | ".join(str(row.get(s, 0)) for s in sevs)
              + f" | {sum(row.values())} |\n")
        w("| **total** | " + " | ".join(str(sum(g.get(s, 0) for g in grid.values()))
                                        for s in sevs) + f" | **{len(findings)}** |\n\n")
        for b in table:
            if b["name"] in grid:
                w(f"- **{b['name']}** \u2014 {' '.join(str(b.get('guidance', '')).split())}\n")
        if "unscored" in grid:
            w("- **unscored** \u2014 the hypothesis carried no usable confidence. Unranked, "
              "not low priority.\n")
        w("\n")
    w("---\n\n")

    for i, f in enumerate(findings, 1):
        h = by_id.get(f.get("hypothesis"), {})
        w(f"## {i}. {f.get('title')}\n\n")
        w(f"**Severity** {f.get('severity')} · **Tier** {f.get('tier')} · "
          f"**Confidence** {h.get('confidence', '?')} · `{f['id']}`\n\n")
        if str(f.get("impact", "")).strip():
            w(f"{f['impact'].strip()}\n\n")
        if h.get("reasoning"):
            w(f"**Why this was flagged.** {h['reasoning']}\n\n")
        # Deterministic, because it is a property of the engine and not a judgement:
        # asking an agent to remember it produced 0 mentions in 23 findings. A
        # sanitizer seen on a reported path says nothing about the routes the engine
        # did not enumerate, and reading it as coverage makes a live bug look safer.
        cands = sorted({c.get("name") for fid in h.get("evidence", [])
                        for c in (by_id.get(fid, {}).get("candidate_sanitizers") or [])
                        if c.get("name")})
        if cands:
            w(f"**Sanitizer note.** `{'`, `'.join(cands)}` appeared on the reported "
              "path(s) and has *not* been audited — presence is a substrate fact, "
              "effectiveness is not. Because reported paths are representative rather "
              "than exhaustive, a route reaching this sink with no sanitizer at all may "
              "exist and simply not have been enumerated.\n\n")
        # What a trace level actually established, stated deterministically. If the
        # loop read a method and the report does not say so, the reader cannot tell a
        # judgement made from the code from one made from the call site alone — which
        # is the distinction the whole leg exists to create. `depth` is the honest
        # measure of how much work stands behind the number above.
        if int(h.get("depth", 0) or 0) > 0:
            read = [n for n in (h.get("read") or []) if str(n).strip()]
            bodies = sorted({by_id.get(fid, {}).get("full_name")
                             for fid in h.get("evidence", [])
                             if by_id.get(fid, {}).get("kind") == "callee_body"
                             and by_id.get(fid, {}).get("status") == "resolved"} - {None})
            w(f"**Traced to depth {h['depth']}.** ")
            if bodies:
                w(f"The source of {len(bodies)} method(s) on this path was read: "
                  + ", ".join(f"`{b.split(':')[0]}`" for b in bodies[:8])
                  + ("," if len(bodies) > 8 else "")
                  + (f" and {len(bodies) - 8} more." if len(bodies) > 8 else ".") + " ")
            else:
                # The gap, said out loud. A trace level that read nothing must not
                # look like one that read everything and found nothing wrong.
                w("No callee body on this path could be read — every method the "
                  "substrate was asked for lay outside the analysed tree. This level "
                  "added no code the agent could argue from. ")
            if str(h.get("basis", "")).strip():
                w(f"{h['basis'].strip()}")
            if read and not bodies:
                w(f" (Claimed read: {', '.join(f'`{r}`' for r in read[:4])}.)")
            w("\n\n")
        w("**Recreation**\n\n```\n" + f.get("recreation", "") + "\n```\n\n")
        w("**References**\n\n" + "".join(f"- `{r}`\n" for r in f.get("refs", [])) + "\n")
        # Never render a bare heading: an empty caveats section reads as "nothing to
        # caveat", which is the opposite of true for a static-only finding.
        caveats = str(f.get("caveats", "")).strip()
        w(f"**Caveats.** {caveats}\n\n" if caveats else
          "**Caveats.** _None recorded — this finding predates the caveats"
          " requirement; read the tier limits above._\n\n")
        # Provenance is part of the finding, not a footnote: every claim above
        # traces to substrate facts by id.
        w(f"<sub>Evidence: {', '.join(h.get('evidence', []))} · "
          f"hypothesis {h.get('id','?')} via {h.get('src','?')} · finding via {f.get('src','?')}</sub>\n\n---\n\n")

    if unsettled:
        # A case the agent investigated and could not settle belongs to neither list:
        # it is not written up as a finding and it was not excluded. Without a section
        # of its own it appears only as a number in the summary and vanishes from the
        # document — which is the silent incompleteness every other tool here refuses.
        w("## Investigated, not settled \u2014 these need a human\n\n")
        w(f"{len(unsettled)} case(s) were traced and came back `inconclusive`: the "
          "substrate could not settle them either way, so the agent declined to call "
          "them and declined to drop them. They produce no finding above and appear in "
          "no exclusion list. They are the cases where reading the code was not "
          "enough, which makes them the ones most worth your time.\n\n")
        for h in sorted(unsettled, key=lambda x: site_of(x, by_id)):
            conf = h.get("confidence")
            why = str(h.get("reasoning") or h.get("basis") or "").strip()
            w(f"- `{site_of(h, by_id)}` \u2014 **confidence {conf if conf is not None else '?'}**"
              f" \u2014 {why or '(no reasoning recorded)'}\n")
            w(f"  <sub>Evidence: {', '.join(h.get('evidence', []))} \u00b7 {h.get('id','?')}"
              f" via {h.get('src','?')}</sub>\n")
        w("\n")

    if refuted:
        w("## Refuted during triage \u2014 verify these\n\n")
        w(f"The substrate found {len(refuted)} more tainted path(s) to a sink and the "
          "agent judged each one not to be an instance of this class. Every exclusion "
          "is listed with its reasoning so it can be checked rather than trusted.\n\n")
        w("**Weakest refutations first.** The confidence shown is the agent's confidence "
          "*in the refutation*, so the top of this list is where it was least sure it was "
          "right to drop the case \u2014 which is exactly where to spend a few minutes. A "
          "refusal here is a model judgement, not a substrate fact: the path itself was "
          "proven.\n\n")
        rows = sorted(
            refuted,
            key=lambda h: (h.get("confidence") if isinstance(h.get("confidence"), (int, float))
                           else -1.0, site_of(h, by_id)))
        for h in rows:
            conf = h.get("confidence")
            # `reasoning` comes from the flat pass, `basis` from a trace revision.
            # A traced refutation has the latter, and printing "(no reasoning
            # recorded)" against the one exclusion someone actually read the code for
            # would bury the best-argued entry in the list.
            why = str(h.get("reasoning") or h.get("basis") or "").strip()
            w(f"- `{site_of(h, by_id)}` \u2014 **confidence "
              f"{conf if conf is not None else '?'}** \u2014 "
              f"{why or '(no reasoning recorded)'}\n")
            # Derivable from the facts, so the renderer owes it. The agent is never
            # shown the body of the method being called, so a refutation can rest on
            # a resolved argument type (sound) or on what things are named (a guess
            # about code nobody looked at). Those read identically in prose; they are
            # not the same claim, and the weaker one is where a real bug hides.
            arg_type, resolved = "", False
            for fid in h.get("evidence", []):
                f0 = by_id.get(fid, {})
                if f0.get("sink_arg_type"):
                    arg_type = f0["sink_arg_type"]
                    resolved = bool(f0.get("sink_arg_type_resolved"))
                    break
            # Strongest available, in order. Once `trace` has read a body, saying the
            # implementation "was never examined" is simply false — and it is the one
            # sentence in this section a reviewer acts on.
            bodies = sorted({by_id.get(fid, {}).get("name")
                             for fid in h.get("evidence", [])
                             if by_id.get(fid, {}).get("kind") == "callee_body"
                             and by_id.get(fid, {}).get("status") == "resolved"} - {None})
            if bodies:
                w(f"  **Basis:** the source of {len(bodies)} method(s) on this path was "
                  f"read \u2014 " + ", ".join(f"`{b}`" for b in bodies[:6])
                  + (f" and {len(bodies) - 6} more" if len(bodies) > 6 else "")
                  + ". This exclusion rests on the code, not on naming.\n")
            elif arg_type and resolved:
                w(f"  **Basis:** the tainted argument is `{arg_type}` \u2014 a resolved "
                  f"type, so this exclusion does not rest on naming.\n")
            else:
                w("  **Basis:** call site only \u2014 the callee's implementation was "
                  "never examined and its argument type is "
                  + (f"`{arg_type}`, unresolved" if arg_type else "unknown")
                  + ". Treat this exclusion as unverified.\n")
            # Derivable from the facts, so the renderer owes it — and it is the one
            # warning that does NOT correlate with low confidence. Observed on a live
            # traced run: a case was refuted at 0.95 whose own basis ended "the
            # vulnerability exists because the input is still concatenated into the
            # query string regardless of the sanitizer's outcome". The prose argued
            # the bug and the status field said otherwise. Weakest-first ordering
            # buries exactly that entry, so flag it on the evidence instead.
            sanitized_path = any((by_id.get(fid, {}).get("candidate_count") or 0) > 0
                                 for fid in h.get("evidence", []))
            if sanitized_path:
                w("  **Check this one.** The path carries a sanitizer candidate. Presence "
                  "is a substrate fact; effectiveness is not, and no tool here can assert "
                  "it. If this exclusion rests on that call working, it is a belief that "
                  "was never recorded \u2014 and a confident refutation is not evidence "
                  "of a careful one.\n")
            w(f"  <sub>Evidence: {', '.join(h.get('evidence', []))} \u00b7 {h.get('id','?')}"
              f" via {h.get('src','?')}</sub>\n")
        w("\n")

    if beliefs:
        w("## Trust decisions recorded\n\n")
        for key, b in sorted(beliefs.items()):
            w(f"- `{key[0]}` **{b['verdict']}** for {key[2]} — {b['rationale']} "
              f"<sub>({b['audited_by']})</sub>\n")
        w("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
