"""`struct_grep` — the opengrep substrate wrapper (design §2.1).

    struct_grep scan  --src PATH --rules <lang>/<class> [--rules ...] [--timeout N]
    struct_grep rules [--meta]

stdout carries bare JSONL fact records (§10.4) and nothing else; every human /
metadata line goes to stderr. The tool answers "does this pattern occur here",
interprets nothing, and tiers nothing.

**What a fact from here does and does not mean.** A hit proves a sink *exists*
at a location. It says nothing about whether an attacker reaches it — opengrep
has no call graph and no inter-procedural dataflow. Reachability facts come from
`cpg` (§10.3); anything this tool emits stays below `static_reachability` in the
§6 tier table.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .. import records
from ..cpg.workspace import repo_root
from . import rules as ruleset

OPENGREP = os.environ.get("OPENGREP_BIN", "opengrep")
SCAN_TIMEOUT = int(os.environ.get("STRUCT_GREP_TIMEOUT", "900"))


def log(msg: str) -> None:
    print(f"struct_grep: {msg}", file=sys.stderr)


def _emit_meta(obj: dict, to_stdout: bool) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    print(line, file=sys.stdout if to_stdout else sys.stderr)


def _clip(s: str, n: int = 300) -> str:
    return s if len(s) <= n else s[:n] + "…"


def _binary() -> str:
    exe = shutil.which(OPENGREP)
    if not exe:
        raise SystemExit(
            f"struct_grep: {OPENGREP!r} not found on PATH (set OPENGREP_BIN to override)")
    return exe


def opengrep_version() -> str:
    try:
        out = subprocess.run([_binary(), "--version"], capture_output=True, text=True, timeout=60)
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else "unknown"
    except Exception:
        return "unknown"


def _run(src: Path, rule_files: list[Path], timeout: int) -> dict:
    """Invoke opengrep from the repo root so `check_id` prefixes stay stable."""
    cmd = [_binary(), "scan", "--quiet", "--json", "--error"]
    for f in rule_files:
        cmd += ["--config", str(f.relative_to(repo_root()))]
    cmd.append(str(src))

    proc = subprocess.run(cmd, cwd=repo_root(), capture_output=True, text=True, timeout=timeout)
    if not proc.stdout.strip():
        print(proc.stderr.strip(), file=sys.stderr)
        raise SystemExit(f"struct_grep: opengrep produced no output (exit {proc.returncode})")
    try:
        return json.loads(proc.stdout)
    except ValueError as e:
        print(proc.stderr.strip(), file=sys.stderr)
        raise SystemExit(f"struct_grep: opengrep output was not JSON ({e})")


def _strip_prefix(check_id: str, rule_files: list[Path]) -> str:
    """opengrep prefixes rule ids with the config path (`rules.java.foo`).

    That prefix is an artifact of how the file was loaded, not part of the rule's
    identity — and it would leak into `src`, so a fact's provenance would change
    if the rules moved. Strip it back to the id the rule file declares.
    """
    for f in rule_files:
        prefix = ".".join(f.relative_to(repo_root()).parent.parts) + "."
        if check_id.startswith(prefix):
            return check_id[len(prefix):]
    return check_id


def _payloads(doc: dict, src: Path, rule_files: list[Path]) -> list[dict]:
    out = []
    for r in doc.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = dict(extra.get("metadata", {}) or {})
        # `kind` and `vuln_class` are promoted onto the fact; whatever else the
        # rule declares rides along untouched — the tool reads none of it.
        kind = meta.pop("kind", "match")
        vuln_class = meta.pop("vuln_class", "")

        path = Path(r.get("path", ""))
        try:
            rel = path.resolve().relative_to(src.resolve())
        except ValueError:
            rel = path
        start, end = r.get("start", {}), r.get("end", {})
        metavars = {
            k: (v or {}).get("abstract_content", "")
            for k, v in (extra.get("metavars", {}) or {}).items()
        }
        out.append({
            "kind": kind,
            "rule": _strip_prefix(r.get("check_id", ""), rule_files),
            "vuln_class": vuln_class,
            "file": str(rel),
            "line": int(start.get("line", -1)),
            "column": int(start.get("col", -1)),
            "end_line": int(end.get("line", -1)),
            "end_column": int(end.get("col", -1)),
            "code": _clip((extra.get("lines") or "").strip()),
            "message": " ".join((extra.get("message") or "").split()),
            "severity": extra.get("severity", ""),
            "metavars": dict(sorted(metavars.items())),
            "rule_meta": meta,
        })
    # opengrep scans files in parallel; its result order is not a contract.
    # Facts are content-hashed but the JSONL *sequence* must be reproducible.
    out.sort(key=lambda p: (p["file"], p["line"], p["column"], p["rule"]))
    return out


# ----------------------------------------------------------------- commands


def cmd_scan(args: argparse.Namespace) -> int:
    src = Path(args.src).expanduser().resolve()
    if not src.is_dir():
        raise SystemExit(f"struct_grep: --src {src} is not a directory")
    rule_files = [ruleset.resolve(n) for n in args.rules]

    started = time.time()
    doc = _run(src, rule_files, args.timeout)
    elapsed = round(time.time() - started, 2)

    payloads = _payloads(doc, src, rule_files)
    by_rule: dict[str, int] = {}
    for p in payloads:
        by_rule[p["rule"]] = by_rule.get(p["rule"], 0) + 1

    n = 0
    for p in payloads:
        n += records.write_jsonl([records.fact(p, f"opengrep:{p['rule']}")], sys.stdout)

    errors = doc.get("errors", []) or []
    scanned = (doc.get("paths", {}) or {}).get("scanned", []) or []
    _emit_meta(
        {
            "cmd": "scan", "src": str(src), "rules": args.rules, "facts": n,
            "seconds": elapsed,
            # Disambiguation (invariant #8): zero facts over zero scanned files,
            # or with parse errors, is NOT the same claim as zero facts over a
            # cleanly parsed tree. Never report "no vuln" without reading these.
            "scan_meta": {
                "files_scanned": len(scanned),
                "parse_errors": len(errors),
                "errors": [
                    {"type": e.get("type", ""), "path": e.get("path", ""),
                     "message": _clip(str(e.get("message", "")), 200)}
                    for e in errors[:20]
                ],
                "skipped_rules": len(doc.get("skipped_rules", []) or []),
                "by_rule": dict(sorted(by_rule.items())),
                "opengrep_version": doc.get("version", ""),
            },
        },
        to_stdout=False,
    )
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    _emit_meta({"cmd": "rules", "dir": str(ruleset.rules_dir()),
                "available": ruleset.available()}, args.meta)
    return 0


# --------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="struct_grep", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--meta", action="store_true",
                        help="write metadata to stdout instead of stderr (never for `scan`)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", parents=[common], help="run a rule set, emit fact JSONL on stdout")
    s.add_argument("--src", required=True, help="source tree to scan")
    s.add_argument("--rules", action="append", required=True, metavar="LANG/CLASS",
                   help="named rule set from rules/ (repeatable; fixed vocabulary)")
    s.add_argument("--timeout", type=int, default=SCAN_TIMEOUT)
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("rules", parents=[common], help="list the named rule vocabulary")
    r.set_defaults(fn=cmd_rules)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
