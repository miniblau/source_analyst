"""`belief` — the append-only log and its trust projection (design §5, §10.4).

    belief assert  --subject S --predicate P --object O --verdict V
                   --rationale R --audited-by WHO
    belief append  [--dry-run]        # records on stdin -> log
    belief project [--subject S] [--predicate P] [--object O] [--verdict V]
    belief get     --subject S --predicate P --object O
    belief log     [--type T]
    belief verdicts

stdout carries bare JSONL and nothing else; metadata goes to stderr. The tool
decides nothing — it records decisions others made and replays them.

`append` takes any record type, so facts accrete through the same door:

    manifest params --class sqli --lang java --query reachable \\
      | cpg query --src PATH --query reachable --params-from - \\
      | belief append
"""

from __future__ import annotations

import argparse
import json
import sys

from .. import records
from . import store


def _emit_meta(obj: dict, to_stdout: bool = False) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    print(line, file=sys.stdout if to_stdout else sys.stderr)


def _matches(rec: dict, args: argparse.Namespace) -> bool:
    for field in ("subject", "predicate", "object", "verdict"):
        want = getattr(args, field, None)
        if want and rec.get(field) != want:
            return False
    return True


def cmd_assert(args: argparse.Namespace) -> int:
    rec = records.belief(args.subject, args.predicate, args.object, args.verdict,
                         args.rationale, args.audited_by)
    store.validate(rec)          # reject an unknown verdict before it reaches the log
    prior = store.project().get(records.belief_key(rec))
    written, _ = store.append([rec])
    records.write_jsonl([rec], sys.stdout)
    meta = {"cmd": "assert", "written": written, "log": str(store.log_path())}
    if prior:
        # Superseding is normal and is the point of the store, but it is never
        # silent: an operator must see that a previous verdict was replaced.
        meta["superseded"] = {"id": prior["id"], "verdict": prior["verdict"],
                              "audited_by": prior.get("audited_by", ""), "ts": prior["ts"]}
    _emit_meta(meta)
    return 0


def cmd_append(args: argparse.Namespace) -> int:
    recs = []
    for n, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        try:
            recs.append(json.loads(line))
        except ValueError as e:
            raise SystemExit(f"belief: stdin:{n}: not valid JSON ({e})")
    try:
        for rec in recs:
            store.validate(rec)
        if args.dry_run:
            known = {r["id"] for r in store.read() if r.get("type") == "fact"}
            dupes = sum(1 for r in recs if r.get("type") == "fact" and r["id"] in known)
            written = len(recs) - dupes
        else:
            written, dupes = store.append(recs)
    except store.LogError as e:
        raise SystemExit(f"belief: {e}")
    by_type: dict[str, int] = {}
    for rec in recs:
        by_type[rec.get("type", "?")] = by_type.get(rec.get("type", "?"), 0) + 1
    _emit_meta({"cmd": "append", "read": len(recs), "written": written,
                "duplicate_facts": dupes, "by_type": dict(sorted(by_type.items())),
                "dry_run": bool(args.dry_run), "log": str(store.log_path())})
    return 0


def cmd_project(args: argparse.Namespace) -> int:
    live = store.project()
    revisions = store.superseded()
    rows = [r for _, r in sorted(live.items()) if _matches(r, args)]
    for rec in rows:
        # The projection is a view, not new records: ids and provenance are the
        # originals, with the audit count attached.
        out = dict(rec)
        out["superseded_count"] = revisions.get(records.belief_key(rec), 0)
        records.write_jsonl([out], sys.stdout)
    _emit_meta({"cmd": "project", "beliefs": len(rows), "total_keys": len(live),
                "log": str(store.log_path())})
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    key = (args.subject, args.predicate, args.object)
    rec = store.project().get(key)
    if rec is None:
        # Exit 1, not an empty success: "no belief recorded" and "belief says no"
        # are different answers and a caller must not conflate them.
        _emit_meta({"cmd": "get", "found": False, "key": list(key)})
        return 1
    records.write_jsonl([rec], sys.stdout)
    _emit_meta({"cmd": "get", "found": True, "key": list(key)})
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    n = 0
    for rec in store.read():
        if args.type and rec.get("type") != args.type:
            continue
        records.write_jsonl([rec], sys.stdout)
        n += 1
    _emit_meta({"cmd": "log", "records": n, "log": str(store.log_path())})
    return 0


def cmd_verdicts(args: argparse.Namespace) -> int:
    _emit_meta({"cmd": "verdicts", "verdicts": store.verdicts()}, to_stdout=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="belief", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assert", help="record a trust decision")
    a.add_argument("--subject", required=True, help="e.g. a sanitizer's name")
    a.add_argument("--predicate", required=True, help="e.g. sanitizes")
    a.add_argument("--object", required=True, help="e.g. the vuln class")
    a.add_argument("--verdict", required=True, help="see `belief verdicts`")
    a.add_argument("--rationale", required=True, help="why — a verdict without one cannot be audited")
    a.add_argument("--audited-by", required=True, help="who decided: trace, human, ...")
    a.set_defaults(fn=cmd_assert)

    ap = sub.add_parser("append", help="append records from stdin to the log")
    ap.add_argument("--dry-run", action="store_true", help="validate and report, write nothing")
    ap.set_defaults(fn=cmd_append)

    pr = sub.add_parser("project", help="latest-wins belief projection")
    for f in ("subject", "predicate", "object", "verdict"):
        pr.add_argument(f"--{f}", help=f"filter on {f}")
    pr.set_defaults(fn=cmd_project)

    g = sub.add_parser("get", help="one belief by key; exit 1 if none is recorded")
    g.add_argument("--subject", required=True)
    g.add_argument("--predicate", required=True)
    g.add_argument("--object", required=True)
    g.set_defaults(fn=cmd_get)

    lg = sub.add_parser("log", help="stream the raw append-only log")
    lg.add_argument("--type", help="filter: fact, belief, hypothesis, finding")
    lg.set_defaults(fn=cmd_log)

    v = sub.add_parser("verdicts", help="the verdict vocabulary (config/verdicts.yaml)")
    v.set_defaults(fn=cmd_verdicts)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except store.LogError as e:
        raise SystemExit(f"belief: {e}")


if __name__ == "__main__":
    sys.exit(main())
