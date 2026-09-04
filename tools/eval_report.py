#!/usr/bin/env python3
"""Turn N eval runs into a distribution, because a point is not a measurement.

The thing this exists to prevent: reading one number off one run and calling a
change an improvement. On this stack temperature 0 is not reproducible — the
clear-cut cases are stable and the marginal ones flip — so the only honest way to
compare two versions is to ask whether a metric moved OUTSIDE the band the same
code produces against itself.

So every metric is reported as min/median/max across runs, and every case is
reported with the verdicts it actually received. A case that flipped is the noise
band made concrete; a case that never flips is one a change can be judged on.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def load(out: Path):
    scores: dict[tuple[str, str], list[dict]] = defaultdict(list)
    verdicts: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for f in sorted(out.glob("run*.score.json")):
        # run<i>.<class>.<lang>.score.json
        parts = f.name.split(".")
        run, cls, lang = parts[0], parts[1], parts[2]
        try:
            scores[(cls, lang)].append(json.loads(f.read_text()))
        except ValueError:
            continue
    runs_per_set: dict[tuple[str, str], set] = defaultdict(set)
    for f in sorted(out.glob("run*.jsonl")):
        parts = f.name.split(".")
        if len(parts) < 3:
            continue
        run, cls, lang = parts[0], parts[1], parts[2]
        runs_per_set[(cls, lang)].add(run)
        facts, hyps = {}, []
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("type") == "fact":
                facts[r["id"]] = r
            elif r.get("type") == "hypothesis" and r.get("src") == "agent:hypothesize":
                hyps.append(r)
        for r in hyps:
            site = site_of(r, facts)
            verdicts[(cls, lang, site)].append(f"{r.get('status')}@{r.get('confidence')}")
    return scores, verdicts, runs_per_set


def site_of(hyp: dict, facts: dict) -> str:
    """The site a hypothesis is ABOUT, resolved from its evidence facts.

    Not `hyp["case"]`, which is prose the agent wrote about itself. Keying on that
    string cost this report its whole point: measured 2026-09-04, the agent called
    one WebGoat site `JWTToken.java:98` in run 1 and `JWTController.java:...` in
    runs 2 and 3. Keyed on the prose those are two cases, each seen with one
    verdict, so both counted STABLE — and the genuine flip behind them
    (refuted@0.9 -> inconclusive@0.5, which is exactly what moved open_redirect
    precision from 1.0 to 0.5) was reported nowhere. A harness that exists to
    measure noise was under-reporting it.

    `score` has always resolved sites this way and says why in its own docstring.
    Evidence ids are content hashes over facts built once and shared by every run,
    so this key is stable by construction.
    """
    for fid in hyp.get("evidence", []):
        f = facts.get(fid)
        if not f:
            continue
        file, line = f.get("sink_file"), f.get("sink_line")
        if file is None:
            file, line = f.get("file"), f.get("line")
        if file is not None and line is not None:
            return f"{file}:{line}"
    # No resolvable evidence is not "one anonymous case": collapsing them would
    # merge unrelated hypotheses into a single fake-stable key.
    return f"<unresolved:{hyp.get('id')}>"


def band(vals: list) -> str:
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return "n/a"
    if len(set(vals)) == 1:
        return f"{vals[0]:.3f} (stable)"
    return f"{min(vals):.3f}–{max(vals):.3f} (median {statistics.median(vals):.3f})"


def main() -> int:
    return report(Path(sys.argv[1]))


def report(out: Path) -> int:
    scores, verdicts, runs_per_set = load(out)
    if not scores:
        # An eval that scored nothing is not an eval that found nothing wrong.
        print(f"eval_report: no scorecards under {out} — every run failed, or the "
              f"set produced no cases. This is not a result.", file=sys.stderr)
        return 2

    print(f"\n# eval — {out.name}\n")
    for (cls, lang), cards in sorted(scores.items()):
        n = len(cards)
        print(f"## {cls}/{lang}  ({n} run(s))")
        for metric in ("precision", "recall", "site_recall"):
            print(f"  {metric:<12} {band([c.get(metric) for c in cards])}")
        for key in ("true_positive", "false_positive", "false_negative"):
            print(f"  {key:<12} {band([c['cases'][key] for c in cards])}")
        aq: dict[str, list] = defaultdict(list)
        for c in cards:
            for k, v in ((c.get("argument_quality") or {}).get("signals") or {}).items():
                aq[k].append(v)
        for k, v in sorted(aq.items()):
            print(f"  aq.{k:<9} {band(v)}")
        print()

    print("## per-case stability — a case that flips cannot judge a change\n")
    flipped = stable = 0
    for (cls, lang, site), vs in sorted(verdicts.items()):
        uniq = sorted(set(vs))
        short = site.split("/")[-1]
        n_runs = len(runs_per_set.get((cls, lang), ()))
        # A case the agent judged in some runs and not others is as damaging to a
        # measurement as one that changed its mind, and it is NOT stable — it was
        # simply absent. Counting it stable on the strength of the runs where it
        # did appear is how a disappearing case hides inside a clean band.
        missing = n_runs - len(vs)
        if len(uniq) == 1 and missing <= 0:
            stable += 1
        else:
            flipped += 1
            print(f"  FLIPPED  {cls}/{lang} {short}")
            for u in uniq:
                print(f"             {vs.count(u)}x {u}")
            if missing > 0:
                print(f"             {missing}x ABSENT — not judged in that run")
    print(f"\n  {stable} stable, {flipped} flipped across runs.")
    if flipped:
        print("  Any metric movement smaller than these flips is noise, not a result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
