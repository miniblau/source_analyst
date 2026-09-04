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
    for f in sorted(out.glob("run*.jsonl")):
        parts = f.name.split(".")
        if len(parts) < 3:
            continue
        run, cls, lang = parts[0], parts[1], parts[2]
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("type") != "hypothesis" or r.get("src") != "agent:hypothesize":
                continue
            site = r.get("case") or "?"
            verdicts[(cls, lang, site)].append(f"{r.get('status')}@{r.get('confidence')}")
    return scores, verdicts


def band(vals: list) -> str:
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return "n/a"
    if len(set(vals)) == 1:
        return f"{vals[0]:.3f} (stable)"
    return f"{min(vals):.3f}–{max(vals):.3f} (median {statistics.median(vals):.3f})"


def main() -> int:
    out = Path(sys.argv[1])
    scores, verdicts = load(out)
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
        if len(uniq) == 1:
            stable += 1
        else:
            flipped += 1
            print(f"  FLIPPED  {cls}/{lang} {short}")
            for u in uniq:
                print(f"             {vs.count(u)}x {u}")
    print(f"\n  {stable} stable, {flipped} flipped across runs.")
    if flipped:
        print("  Any metric movement smaller than these flips is noise, not a result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
