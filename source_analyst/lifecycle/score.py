"""`score` — measure an agent against corpus ground truth (design §8, Phase 1).

The agent layer is the only nondeterministic part of the system, so it is the one
part that needs measuring rather than testing. This reads a labelled case set from
`corpus/ground_truth/<target>.<class>.yaml` and reports how a run's hypotheses
landed against it. It is deterministic, makes no LLM call, and forms no opinion
about what a label means — the labels and the lifecycle vocabulary own that.

Three things it refuses to conflate, because collapsing any of them flatters the
model:

  * a case the agent DROPPED that was really vulnerable is a false negative, the
    expensive error, and it is counted separately from noise;
  * a labelled site the SUBSTRATE never reached was never offered to the agent.
    That is a substrate gap and is reported as one, never as a miss;
  * a hypothesis about a site with no label is unscored, not correct.

Sites are resolved from the hypothesis's *evidence facts*, never from the `case`
string the agent wrote — that string is prose, and prose does not get to decide
which site it is being graded on.

    score --class sqli --target webgoat --src agent:hypothesize
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from pathlib import Path
from typing import Any

import yaml

from ..belief import store
from ..cpg.workspace import repo_root
from ..manifest.loader import ManifestError, load_class

NAME_RE = re.compile(r"^[a-z0-9_]+$")


class ScoreError(Exception):
    """The oracle is missing or unusable. Always fatal: scoring against a broken
    label set produces a number that looks like a measurement and is not."""


def ground_truth_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_GROUND_TRUTH")
    return Path(env).expanduser().resolve() if env else repo_root() / "corpus" / "ground_truth"


def load_labels(target: str, vuln_class: str) -> dict[str, Any]:
    for name in (target, vuln_class):
        if not NAME_RE.match(name):
            raise ScoreError(f"invalid name {name!r}")
    path = ground_truth_dir() / f"{target}.{vuln_class}.yaml"
    if not path.is_file():
        raise ScoreError(f"no ground truth for {target}/{vuln_class}: {path}")
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or not doc.get("sites"):
        raise ScoreError(f"{path}: expected a non-empty `sites` list")
    known = set(doc.get("labels") or [])
    sites = {}
    for site in doc["sites"]:
        if "sink" not in site or "label" not in site:
            raise ScoreError(f"{path}: every site needs `sink` and `label`: {site}")
        if known and site["label"] not in known:
            raise ScoreError(f"{path}: unknown label {site['label']!r} at {site['sink']}")
        sites[site["sink"]] = site
    doc["by_sink"] = sites
    return doc


def statuses() -> dict[str, dict[str, Any]]:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    base = Path(env).expanduser().resolve() if env else repo_root() / "config"
    doc = yaml.safe_load((base / "hypothesis.yaml").read_text())
    for name, spec in doc.items():
        if "retains_case" not in spec:
            raise ScoreError(f"config/hypothesis.yaml: {name} has no `retains_case`")
    return doc


def site_of(rec: dict, facts: dict[str, dict]) -> str | None:
    """Which sink site a hypothesis is about, taken from its evidence facts."""
    for fid in rec.get("evidence", []):
        f = facts.get(fid)
        if not f:
            continue
        file, line = f.get("sink_file"), f.get("sink_line")
        if file is None:
            file, line = f.get("file"), f.get("line")
        if file is not None and line is not None:
            return f"{file}:{line}"
    return None


def score(log: list[dict], truth: dict, vuln_class: str, src: str | None) -> dict[str, Any]:
    vocab = statuses()
    facts = {r["id"]: r for r in log if r.get("type") == "fact"}
    mine = [r for r in log if r.get("type") == "hypothesis"
            and (src is None or r.get("src") == src)]
    hyps = [r for r in mine if r.get("vuln_class") == vuln_class]
    # Counted and named, never dropped in silence. A run where four judgements
    # carried a mistyped class scored 22/26 and looked flawless; the four missing
    # ones were invisible because this filter said nothing about what it removed.
    other_class = sorted({r.get("vuln_class") for r in mine} - {vuln_class})

    rows, unlabelled, unknown_status = [], [], []
    for h in hyps:
        sink = site_of(h, facts)
        label = truth["by_sink"].get(sink, {}).get("label")
        if label is None:
            unlabelled.append({"id": h["id"], "sink": sink, "status": h.get("status")})
            continue
        spec = vocab.get(h.get("status"))
        if spec is None:
            unknown_status.append(h.get("status"))
            continue
        rows.append({"id": h["id"], "sink": sink, "label": label, "status": h["status"],
                     "kept": bool(spec["retains_case"]),
                     "confidence": h.get("confidence")})

    if unknown_status:
        raise ScoreError(f"hypotheses carry unknown status(es): {sorted(set(unknown_status))}")

    vuln = [r for r in rows if r["label"] == "vulnerable"]
    other = [r for r in rows if r["label"] != "vulnerable"]
    tp = [r for r in vuln if r["kept"]]
    fn = [r for r in vuln if not r["kept"]]
    fp = [r for r in other if r["kept"]]
    tn = [r for r in other if not r["kept"]]

    seen_sinks = {r["sink"] for r in rows}
    # Reached-ness is a property of the FACTS, not of which hypotheses happened to
    # be scored. Deriving it from scored rows made a mislabelled judgement look like
    # a substrate that never found the site — blaming the tool for a data defect is
    # exactly the conflation this scorer exists to refuse.
    reached = set()
    for f in facts.values():
        file, line = f.get("sink_file"), f.get("sink_line")
        if file is None:
            file, line = f.get("file"), f.get("line")
        if file is not None and line is not None:
            reached.add(f"{file}:{line}")
    unreached = sorted(s for s in truth["by_sink"] if s not in reached)
    # Denominated over vulnerable sites the agent was actually offered. Using every
    # labelled site would fold substrate gaps back into the model's recall — the
    # exact conflation this tool exists to refuse, and a bug this file has had.
    vuln_sites = {s for s in seen_sinks
                  if truth["by_sink"].get(s, {}).get("label") == "vulnerable"}
    kept_sites = {r["sink"] for r in tp}

    def rate(num: int, den: int) -> float | None:
        return round(num / den, 3) if den else None

    def mean_conf(rs: list[dict]) -> float | None:
        vals = [r["confidence"] for r in rs if isinstance(r["confidence"], (int, float))]
        return round(statistics.fmean(vals), 3) if vals else None

    sep = None
    if mean_conf(tp) is not None and mean_conf(fp) is not None:
        sep = round(mean_conf(tp) - mean_conf(fp), 3)

    return {
        "kind": "scorecard", "class": vuln_class, "target": truth["target"],
        "commit": truth.get("commit"), "src": src,
        "scored": len(rows), "unlabelled": len(unlabelled),
        "skipped_other_class": other_class,
        "cases": {"true_positive": len(tp), "false_negative": len(fn),
                  "false_positive": len(fp), "true_negative": len(tn)},
        "precision": rate(len(tp), len(tp) + len(fp)),
        "recall": rate(len(tp), len(tp) + len(fn)),
        # What a reviewer actually cares about: was every vulnerable *site* kept by
        # at least one hypothesis. A site can survive on one source and be lost on
        # another, and case recall alone hides that.
        "site_recall": rate(len(kept_sites & vuln_sites), len(vuln_sites)),
        "confidence": {"mean_on_vulnerable": mean_conf(tp), "mean_on_noise": mean_conf(fp),
                       # The signal that separates a model from the null baseline:
                       # not whether it kept things, but whether its confidence
                       # tracks the label at all. A flat scorer separates by 0.
                       "separation": sep},
        "sites_never_reached_by_substrate": unreached,
        "labelled_sites": len(truth["by_sink"]),
    }, rows, unlabelled


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="score", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--class", dest="vuln_class", required=True)
    p.add_argument("--target", required=True, help="corpus target, e.g. the fixture name")
    p.add_argument("--src", help="score only hypotheses from this producer, e.g. agent:stub")
    p.add_argument("--detail", action="store_true", help="also emit one row per scored case")
    args = p.parse_args(argv)

    try:
        load_class(args.vuln_class)
        truth = load_labels(args.target, args.vuln_class)
        card, rows, unlabelled = score(list(store.read()), truth, args.vuln_class, args.src)
    except (ManifestError, ScoreError) as e:
        raise SystemExit(f"score: {e}")

    print(json.dumps(card, ensure_ascii=False, separators=(",", ":")))
    if args.detail:
        for row in sorted(rows, key=lambda r: (r["label"], r["sink"], r["id"])):
            print(json.dumps({"kind": "scored_case", **row}, ensure_ascii=False,
                             separators=(",", ":")))
        for row in unlabelled:
            print(json.dumps({"kind": "unscored_case", **row}, ensure_ascii=False,
                             separators=(",", ":")))

    if card["sites_never_reached_by_substrate"]:
        print(f"score: {len(card['sites_never_reached_by_substrate'])} labelled site(s) produced "
              f"no hypothesis — the substrate did not offer them, so they are NOT counted as "
              f"model misses", file=sys.stderr)
    if unlabelled:
        print(f"score: {len(unlabelled)} hypothesis/es are about unlabelled sites and were not "
              f"scored", file=sys.stderr)
    if card["skipped_other_class"]:
        print(f"score: skipped hypotheses labelled {card['skipped_other_class']} — if that is "
              f"not another class you are also reviewing, those judgements are mislabelled and "
              f"are missing from this scorecard", file=sys.stderr)
    if not card["scored"]:
        # Nothing was measured. A zero-row scorecard prints plausible-looking nulls,
        # and the one thing it must not do is read as a result.
        print("score: nothing was scored — no hypothesis matched the class"
              + (f" and src {args.src!r}" if args.src else ""), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
