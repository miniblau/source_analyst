"""`render` — findings in the log to a document a human reads (design §7).

Deterministic and last in the chain: it reformats records and adds nothing. No
severity is invented here, no claim is upgraded, and anything the finding does
not say is not said.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from ..belief import store
from ..manifest.loader import load_class, tier_table

ORDER = {s: i for i, s in enumerate(("critical", "high", "medium", "low", "info"))}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="render", description=__doc__)
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--target", default="the reviewed source tree")
    args = p.parse_args(argv)

    log = list(store.read())
    by_id = {r["id"]: r for r in log}
    findings = [r for r in log if r.get("type") == "finding"]
    hyps = [r for r in log if r.get("type") == "hypothesis"]
    refuted = [h for h in hyps if h.get("status") == "refuted"]
    beliefs = store.project()
    vc = load_class(args.vuln_class)
    tiers = tier_table()

    findings.sort(key=lambda f: (ORDER.get(f.get("severity", "info"), 9), f.get("title", "")))
    counts = Counter(f.get("severity") for f in findings)

    w = sys.stdout.write
    w(f"# {vc.title} — review of {args.target}\n\n")
    w(f"{len(findings)} finding(s): "
      + ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda kv: ORDER.get(kv[0], 9)))
      + f". {len(refuted)} candidate(s) refuted during triage.\n\n")
    w(f"> **What this is.** {vc.narrative}\n\n")
    w("> **What this is not.** Every finding below is static-only. "
      + " ".join(sorted({f.get("tier", "") for f in findings})).strip()
      + " means: " + "; ".join(sorted({tiers[f["tier"]]["claim"] for f in findings if f.get("tier") in tiers}))
      + ". Nothing was executed against a running target, so no finding here is confirmed.\n\n---\n\n")

    for i, f in enumerate(findings, 1):
        h = by_id.get(f.get("hypothesis"), {})
        w(f"## {i}. {f.get('title')}\n\n")
        w(f"**Severity** {f.get('severity')} · **Tier** {f.get('tier')} · "
          f"**Confidence** {h.get('confidence', '?')} · `{f['id']}`\n\n")
        w(f"{f.get('impact','')}\n\n")
        if h.get("reasoning"):
            w(f"**Why this was flagged.** {h['reasoning']}\n\n")
        w("**Recreation**\n\n```\n" + f.get("recreation", "") + "\n```\n\n")
        w("**References**\n\n" + "".join(f"- `{r}`\n" for r in f.get("refs", [])) + "\n")
        w(f"**Caveats.** {f.get('caveats','')}\n\n")
        # Provenance is part of the finding, not a footnote: every claim above
        # traces to substrate facts by id.
        w(f"<sub>Evidence: {', '.join(h.get('evidence', []))} · "
          f"hypothesis {h.get('id','?')} via {h.get('src','?')} · finding via {f.get('src','?')}</sub>\n\n---\n\n")

    if refuted:
        w("## Refuted during triage\n\n")
        w("Reported by the substrate, judged not to be instances of this class. "
          "Listed so the exclusion is reviewable rather than silent.\n\n")
        for h in refuted:
            w(f"- **{h.get('case','?')}** — {h.get('reasoning','')}\n")
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
