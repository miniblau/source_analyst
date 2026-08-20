"""`manifest` — the loader/validator for vuln knowledge (design §10.1, §10.2).

    manifest detect   --src PATH
    manifest classes  [--meta]
    manifest show     --class NAME [--lang LANG]
    manifest params   --class NAME --lang LANG --query QUERY
    manifest plan     --src PATH [--class NAME]
    manifest validate

`params` is the seam that ends hand-typed sink lists: it prints the exact
params object a named query takes, so the pair composes —

    manifest params --class sqli --lang java --query reachable \\
      | cpg query --src PATH --query reachable --params-from -

stdout carries JSONL and nothing else; human/metadata chatter goes to stderr.
This tool interprets nothing: it reads data files and reports what they say.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import records
from . import detect
from .loader import (
    ManifestError,
    applicable,
    available_classes,
    available_patterns,
    language_map,
    load_class,
    load_patterns,
    validate_all,
)


def _emit(obj: dict, to_stdout: bool = True) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    print(line, file=sys.stdout if to_stdout else sys.stderr)


def cmd_detect(args: argparse.Namespace) -> int:
    src = Path(args.src).expanduser().resolve()
    if not src.is_dir():
        raise SystemExit(f"manifest: --src {src} is not a directory")
    rows = detect.counts(src, language_map())
    src_id = "manifest:detect"
    n = records.write_jsonl((records.fact(r, src_id) for r in rows), sys.stdout)
    _emit({"cmd": "detect", "src": str(src), "languages": n,
           "detected": [r["language"] for r in rows]}, to_stdout=False)
    return 0


def cmd_classes(args: argparse.Namespace) -> int:
    _emit({"cmd": "classes", "classes": available_classes(),
           "patterns": available_patterns()}, args.meta)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    vc = load_class(args.vuln_class)
    out = {
        "cmd": "show", "class": vc.name, "title": vc.title,
        "applies_to": vc.applies_to, "narrative": vc.narrative,
        "seed_hypotheses": vc.seed_hypotheses,
        "max_static_tier": vc.max_static_tier, "references": vc.references,
        "source": str(vc.path),
    }
    if args.lang:
        p = load_patterns(vc.name, args.lang)
        out |= {
            "language": p.language, "blocks": p.blocks,
            "queries": p.queries, "rules": p.rules, "patterns_source": str(p.path),
        }
    _emit(out)
    return 0


def cmd_params(args: argparse.Namespace) -> int:
    p = load_patterns(args.vuln_class, args.lang)
    # Bare params object on stdout: this is input for another tool, so it stays
    # unwrapped. Provenance goes to stderr, where the pipe does not carry it.
    print(json.dumps(p.params_for(args.query), ensure_ascii=False, separators=(",", ":")))
    _emit({"cmd": "params", "class": args.vuln_class, "language": args.lang,
           "query": args.query, "blocks": p.queries[args.query],
           "source": str(p.path)}, to_stdout=False)
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """What would run against this tree, and why — read and confirmed by the
    operator before anything executes (§10.2)."""
    src = Path(args.src).expanduser().resolve()
    if not src.is_dir():
        raise SystemExit(f"manifest: --src {src} is not a directory")
    rows = detect.counts(src, language_map())
    languages = [r["language"] for r in rows]
    wanted = [args.vuln_class] if args.vuln_class else None

    plan, gaps = [], []
    for vc, realized, unrealized in applicable(languages):
        if wanted and vc.name not in wanted:
            continue
        for lang in realized:
            p = load_patterns(vc.name, lang)
            plan.append({
                "class": vc.name, "language": lang,
                "queries": sorted(p.queries), "rules": p.rules,
                "max_static_tier": vc.max_static_tier,
            })
        # The language is present in the tree and the class claims it, but no
        # patterns exist yet. Loud, because it is uncovered ground that would
        # otherwise read as a clean result.
        for lang in unrealized:
            gaps.append({"class": vc.name, "language": lang,
                         "reason": f"no manifests/patterns/{lang}/{vc.name}.yaml"})

    # A class that applies to none of the detected languages is reported as
    # skipped rather than omitted: "nothing ran" and "nothing applied" are
    # different answers and the operator must be able to tell them apart.
    covered = {e["class"] for e in plan} | {g["class"] for g in gaps}
    skipped = [
        {"class": name, "applies_to": load_class(name).applies_to}
        for name in available_classes() if name not in covered
    ]
    _emit({"cmd": "plan", "src": str(src), "languages": rows,
           "plan": plan, "coverage_gaps": gaps, "skipped": skipped})
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    problems, gaps = validate_all()
    _emit({"cmd": "validate", "classes": available_classes(),
           "patterns": available_patterns(), "problems": problems,
           "coverage_gaps": gaps, "ok": not problems}, args.meta or not problems)
    return 0 if not problems else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="manifest", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--meta", action="store_true",
                        help="write metadata to stdout instead of stderr")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", parents=[common], help="count files by language (§10.2)")
    d.add_argument("--src", required=True)
    d.set_defaults(fn=cmd_detect)

    c = sub.add_parser("classes", parents=[common], help="list the vuln class vocabulary")
    c.set_defaults(fn=cmd_classes)

    s = sub.add_parser("show", parents=[common], help="print a class, optionally with its patterns")
    s.add_argument("--class", dest="vuln_class", required=True)
    s.add_argument("--lang", help="also load patterns/<lang>/<class>.yaml")
    s.set_defaults(fn=cmd_show)

    q = sub.add_parser("params", parents=[common],
                       help="print the params object a named query takes")
    q.add_argument("--class", dest="vuln_class", required=True)
    q.add_argument("--lang", required=True)
    q.add_argument("--query", required=True)
    q.set_defaults(fn=cmd_params)

    pl = sub.add_parser("plan", parents=[common],
                        help="what applies to a source tree, and what is skipped")
    pl.add_argument("--src", required=True)
    pl.add_argument("--class", dest="vuln_class", help="restrict to one class")
    pl.set_defaults(fn=cmd_plan)

    v = sub.add_parser("validate", parents=[common], help="load every manifest and report problems")
    v.set_defaults(fn=cmd_validate)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except ManifestError as e:
        raise SystemExit(f"manifest: {e}")


if __name__ == "__main__":
    sys.exit(main())
