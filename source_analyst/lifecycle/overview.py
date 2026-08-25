"""`overview` — one page across every class, to decide which report to open.

Deterministic and last in the chain, exactly like `render`: it reformats records
and adds nothing. No severity is invented here and no class is ranked as more
important than another — the only ordering is the agents' own `severity` labels
and the counts underneath them.

WHAT THIS PAGE IS FOR. `render` writes one document per class and assumes you
already know you care about that class. This is the page before those: a reader
who has not looked yet, scanning for where to start. It is therefore mostly
counts and headings, and it links out rather than explaining.

THE THING IT MUST NOT DO is let "nothing here" and "nothing looked" render the
same. An index is exactly where that mistake becomes invisible: a class showing
zero findings reads as a clean class, and a reader who has not been told the leg
failed will believe it. So every class lands in one of five states, and four of
them are not "clean":

    no_log          no log for this class — it was not part of the run at all
    not_scanned     a log, but no substrate facts: nothing was ever queried
    not_judged      facts, but no hypothesis: the hypothesize leg did not run
    not_written_up  hypotheses, but no finding: judged, nothing written
    reported        findings exist

Only `reported` and a `not_written_up` whose hypotheses are all refuted are
answers. The rest are gaps in the run, and they are printed FIRST, above the
findings, because a reader who scrolls past them has been misled.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from ..manifest.loader import ManifestError, available_classes, load_class, tier_table
from .render import ORDER, RenderError


def read_log(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            # A malformed line is a broken log, not a slightly shorter one.
            raise RenderError(f"{path}: line is not JSON: {line[:120]}")
    return out


# Facts a substrate query produced, as opposed to anything an agent said. Used
# only to tell "nothing was queried" from "nothing was found", which is the whole
# point of the state machine above.
FACT_KINDS = ("flow", "sink_candidate", "source_candidate", "sanitizer_check")


def summarize(records: list[dict]) -> dict[str, Any]:
    facts = [r for r in records if r.get("kind") in FACT_KINDS]
    hyps = [r for r in records if r.get("type") == "hypothesis"]
    findings = [r for r in records if r.get("type") == "finding"]

    by_status = Counter(h.get("status", "?") for h in hyps)
    by_sev = Counter(f.get("severity", "info") for f in findings)
    tiers = sorted({f.get("tier") for f in findings if f.get("tier")})

    if not records:
        state = "no_log"
    elif not facts:
        state = "not_scanned"
    elif not hyps:
        state = "not_judged"
    elif not findings:
        state = "not_written_up"
    else:
        state = "reported"

    return {"state": state, "facts": len(facts), "hypotheses": len(hyps),
            "findings": len(findings), "by_status": by_status, "by_severity": by_sev,
            "tiers": tiers,
            "titles": [(f.get("severity", "info"), f.get("title", "(untitled)"))
                       for f in findings]}


# How many findings a class lists before deferring to its own report. This page
# is for choosing what to read; 26 titles is not a summary, it is the report
# again, and a reader who has to scroll it has lost the thing they came for.
PREVIEW = 5


# A narrative with neither break would otherwise be printed whole, and a paragraph
# per class turns the index back into the thing it exists to replace.
GIST_MAX = 220


def first_sentence(text: str) -> str:
    """The narrative's opening clause, which is the part written for a human.

    Narratives are prose written for the class manifest, not for this page, so this
    cuts at the first natural break and falls back to a hard cap rather than
    trusting that one exists.
    """
    flat = " ".join((text or "").split())
    cut = flat.find(", so ")
    if cut != -1:
        return flat[:cut] + "."
    cut = flat.find(". ")
    if cut != -1:
        return flat[: cut + 1]
    return shorten(flat, GIST_MAX)


def shorten(s: str, limit: int = 100) -> str:
    """Trim a finding title without slicing a path in half mid-segment."""
    s = " ".join((s or "").split())
    if len(s) <= limit:
        return s
    head = s[:limit]
    for sep in (" ", "/"):
        i = head.rfind(sep)
        if i > limit * 0.6:
            return head[:i] + "…"
    return head + "…"


GAP_NOTE = {
    "no_log": "no records for this class — the run never reached it",
    "not_scanned": "a log exists but holds no substrate facts — nothing was ever queried",
    "not_judged": "facts are present but nothing judged them — the hypothesize leg did not run",
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="overview", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--logs", type=Path, required=True,
                   help="directory of per-class logs, named <class>.log.jsonl")
    p.add_argument("--target", default="the target", help="what was reviewed")
    p.add_argument("--reports", default=".",
                   help="path prefix the per-class report links point at")
    args = p.parse_args(argv)

    if not args.logs.is_dir():
        raise SystemExit(f"overview: not a directory: {args.logs}")
    logs = sorted(args.logs.glob("*.log.jsonl"))
    if not logs:
        # An index over nothing is the purest form of the mistake this tool is
        # built to avoid: it would render as a clean bill of health for every
        # class at once.
        raise SystemExit(f"overview: no *.log.jsonl in {args.logs} — refusing to "
                         "render an index over nothing")

    tiers = tier_table()

    # A class with NO log does not appear in the glob at all, so without this it
    # would be missing from the page rather than reported as unassessed — the same
    # "absent reads as clean" failure this tool exists to prevent, one level up.
    # Every class the manifest knows gets a row whether or not the run reached it.
    try:
        known = set(available_classes())
    except ManifestError:
        known = set()
    found = {log.name[: -len(".log.jsonl")]: log for log in logs}
    missing = sorted(known - set(found))

    rows = []
    for name in missing:
        s = summarize([])
        s["class"] = name
        try:
            vc = load_class(name)
            s["title"], s["gist"] = vc.title, first_sentence(vc.narrative)
        except (ManifestError, OSError):
            s["title"], s["gist"] = name, ""
        rows.append(s)

    for name, log in sorted(found.items()):
        s = summarize(read_log(log))
        try:
            vc = load_class(name)
            s["title"] = vc.title
            # The manifest narrative is the only plain-English description of the
            # class that exists, and it was written for a human. One sentence of it
            # is what turns a row in a table into something a reader recognises.
            s["gist"] = first_sentence(vc.narrative)
        except (ManifestError, OSError):
            # A log whose class is no longer in the manifest still gets a row —
            # dropping it would shorten the page silently.
            s["title"], s["gist"] = name, ""
        s["class"] = name
        rows.append(s)

    w = sys.stdout.write
    w(f"# Security review of {args.target}\n\n")
    w("_Where to start. One line per vulnerability class; open the linked report "
      "for the detail._\n\n")

    gaps = [r for r in rows if r["state"] in GAP_NOTE]
    if gaps:
        w("## Read this first — what was not assessed\n\n")
        w("These classes produced no findings **because nothing looked**, not "
          "because nothing is there. Treat them as unreviewed:\n\n")
        for r in gaps:
            w(f"- **{r['title']}** — {GAP_NOTE[r['state']]}\n")
        w("\n")

    w("## Classes\n\n")
    w("| Class | Findings | Highest | Judged | Status |\n")
    w("|---|---|---|---|---|\n")
    for r in sorted(rows, key=lambda r: (-r["findings"], r["class"])):
        if r["state"] in GAP_NOTE:
            w(f"| {r['title']} | — | — | — | **not assessed** |\n")
            continue
        if r["state"] == "not_written_up":
            refuted = r["by_status"].get("refuted", 0)
            verdict = ("all candidates refuted" if refuted == r["hypotheses"]
                       else "judged, nothing written up")
            w(f"| {r['title']} | 0 | — | {r['hypotheses']} | {verdict} |\n")
            continue
        top = min(r["by_severity"], key=lambda s: ORDER.get(s, 9))
        link = f"{args.reports.rstrip('/')}/{r['class']}.report.md"
        w(f"| [{r['title']}]({link}) | {r['findings']} | {top} | "
          f"{r['hypotheses']} | reported |\n")
    w("\n")

    for r in sorted(rows, key=lambda r: (-r["findings"], r["class"])):
        if r["state"] != "reported":
            continue
        link = f"{args.reports.rstrip('/')}/{r['class']}.report.md"
        w(f"### {r['title']} — {r['findings']} finding(s)\n\n")
        if r.get("gist"):
            w(f"{r['gist']}\n\n")
        counts = ", ".join(f"{n} {s}" for s, n in
                           sorted(r["by_severity"].items(),
                                  key=lambda kv: ORDER.get(kv[0], 9)))
        w(f"{counts}. [Full report]({link})\n\n")
        ordered = sorted(r["titles"], key=lambda t: ORDER.get(t[0], 9))
        for sev, title in ordered[:PREVIEW]:
            w(f"- **{sev}** — {shorten(title)}\n")
        if len(ordered) > PREVIEW:
            rest = len(ordered) - PREVIEW
            w(f"- _…and {rest} more — see the [full report]({link})._\n")
        w("\n")

    # The one claim this page makes about all of them, and it is a limit, not a
    # result. Derivable from the tier table, so the renderer owes it rather than
    # asking an agent to remember it.
    shown = sorted({t for r in rows for t in r["tiers"]})
    w("## What these findings are, and are not\n\n")
    if shown:
        claims = [tiers[t]["claim"] for t in shown if t in tiers]
        joined = "; ".join(c[0].upper() + c[1:] for c in claims)
        w("Every finding here was reached by reading code, never by running it. "
          f"What that establishes: {joined}.\n\n")
    w("Nothing on this page is confirmed. A static review shows that a defence "
      "*fails*, never that it holds against every input, so each item is a "
      "hypothesis with the evidence attached — the per-class reports carry the "
      "recreation steps for checking them.\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
