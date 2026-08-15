"""`cpg` — the Joern substrate wrapper.

    cpg build  --src PATH [--lang JAVASRC] [--force]
    cpg serve  --src PATH
    cpg status --src PATH [--meta]
    cpg stop   --src PATH | --all
    cpg query  --src PATH --query NAME [--param k=v] [--param-json k=JSON]
    cpg queries [--meta]

stdout carries bare JSONL fact records (§10.4) and nothing else; every human /
metadata line goes to stderr. The tool answers factual queries and interprets
nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .. import records
from . import queries, server
from .workspace import Workspace, var_root


def _emit_meta(obj: dict, to_stdout: bool) -> None:
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    print(line, file=sys.stdout if to_stdout else sys.stderr)


def _params(args: argparse.Namespace) -> dict:
    out: dict = {}
    for item in args.param or []:
        k, sep, v = item.partition("=")
        if not sep:
            raise SystemExit(f"cpg: --param expects k=v, got {item!r}")
        out[k] = v
    for item in args.param_json or []:
        k, sep, v = item.partition("=")
        if not sep:
            raise SystemExit(f"cpg: --param-json expects k=JSON, got {item!r}")
        try:
            out[k] = json.loads(v)
        except ValueError as e:
            raise SystemExit(f"cpg: --param-json {k}: invalid JSON ({e})")
    return out


# ----------------------------------------------------------------- commands


def cmd_build(args: argparse.Namespace) -> int:
    ws = Workspace.of(args.src)
    built = server.build(ws, language=args.lang, force=args.force,
                         frontend_args=args.frontend_arg)
    if not built:
        server.log(f"cache hit {ws.root} (source {ws.source_hash[:16]})")
    _emit_meta({"cmd": "build", "built": built, **_ws_meta(ws)}, args.meta)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    ws = Workspace.of(args.src)
    if not ws.is_built():
        server.build(ws, language=args.lang, frontend_args=args.frontend_arg)
    port = server.ensure_server(ws)
    _emit_meta({"cmd": "serve", "port": port, **_ws_meta(ws)}, args.meta)
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if args.all:
        stopped = []
        for d in server.running_workspaces(var_root() / "cpg"):
            ws = Workspace(src=Path(d.name), source_hash=d.name, root=d)
            if server.stop(ws):
                stopped.append(d.name)
        _emit_meta({"cmd": "stop", "stopped": stopped}, args.meta)
        return 0
    if not args.src:
        raise SystemExit("cpg: stop needs --src PATH or --all")
    ws = Workspace.of(args.src)
    _emit_meta({"cmd": "stop", "stopped": server.stop(ws), **_ws_meta(ws)}, args.meta)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ws = Workspace.of(args.src)
    info = {"cmd": "status", "running": server.is_running(ws), **_ws_meta(ws)}
    if info["running"] and args.overlays:
        ovl = server.overlays(ws)
        info["overlays"] = ovl
        info["dataflow"] = "dataflowOss" in ovl
    _emit_meta(info, args.meta)
    return 0 if ws.is_built() else 1


def cmd_queries(args: argparse.Namespace) -> int:
    _emit_meta({"cmd": "queries", "dir": str(queries.queries_dir()),
                "available": queries.available()}, args.meta)
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    ws = Workspace.of(args.src)
    queries.resolve(args.query)  # fail fast on an unknown name, before any JVM work
    if not ws.is_built():
        if args.no_build:
            raise SystemExit(f"cpg: no CPG for {ws.src} and --no-build given")
        server.build(ws, language=args.lang, frontend_args=args.frontend_arg)

    ws.query_dir.mkdir(parents=True, exist_ok=True)
    out_file = ws.query_dir / f"{args.query}.{os.getpid()}.{time.monotonic_ns()}.json"
    out_file.unlink(missing_ok=True)
    code = queries.source(args.query, out_file, _params(args))

    started = time.time()
    repl = server.run_scala(ws, code, timeout=args.timeout)
    elapsed = round(time.time() - started, 2)

    if not out_file.is_file():
        # `success: true` is meaningless here — no output file means the query
        # failed to compile or threw. Surface the REPL text verbatim.
        print(repl.strip(), file=sys.stderr)
        raise SystemExit(f"cpg: query {args.query!r} produced no result (see REPL output above)")

    try:
        rows, meta = queries.read_result(out_file)
    finally:
        out_file.unlink(missing_ok=True)

    src = f"cpg:{args.query}"
    n = records.write_jsonl((records.fact(r, src) for r in rows), sys.stdout)
    _emit_meta(
        {"cmd": "query", "query": args.query, "src": src, "facts": n,
         "seconds": elapsed, "params": _params(args), "query_meta": meta,
         "source_hash": ws.source_hash},
        to_stdout=False,
    )
    return 0


def _ws_meta(ws: Workspace) -> dict:
    m = ws.read_meta()
    return {
        "source": str(ws.src),
        "source_hash": ws.source_hash,
        "workspace": str(ws.root),
        "built": ws.is_built(),
        "built_at": m.get("built_at"),
        "language": m.get("language"),
        "frontend_args": m.get("frontend_args"),
        "joern_version": m.get("joern_version"),
        "port": int(ws.port_file.read_text()) if ws.port_file.is_file() else None,
    }


# --------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cpg", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--meta", action="store_true",
                        help="write metadata to stdout instead of stderr (never for `query`)")
    buildable = argparse.ArgumentParser(add_help=False)
    buildable.add_argument("--lang", help="joern frontend, e.g. JAVASRC (default: joern auto-detect)")
    buildable.add_argument("--frontend-arg", action="append", metavar="ARG",
                           help="verbatim frontend arg; replaces the per-language defaults "
                                f"({server.FRONTEND_DEFAULTS})")
    sub = p.add_subparsers(dest="cmd", required=True)

    def src_arg(sp, required=True):
        sp.add_argument("--src", required=required, help="source tree to analyse")

    b = sub.add_parser("build", parents=[common, buildable],
                       help="build + cache the CPG (no-op on cache hit)")
    src_arg(b)
    b.add_argument("--force", action="store_true", help="rebuild even on a cache hit")
    b.set_defaults(fn=cmd_build)

    s = sub.add_parser("serve", parents=[common, buildable],
                       help="start the warm joern server for a source tree")
    src_arg(s)
    s.set_defaults(fn=cmd_serve)

    t = sub.add_parser("status", parents=[common], help="cache + server state for a source tree")
    src_arg(t)
    t.add_argument("--overlays", action="store_true",
                   help="also report CPG overlays (needs a running server)")
    t.set_defaults(fn=cmd_status)

    k = sub.add_parser("stop", parents=[common], help="stop the warm server")
    src_arg(k, required=False)
    k.add_argument("--all", action="store_true", help="stop every running server")
    k.set_defaults(fn=cmd_stop)

    q = sub.add_parser("query", parents=[common, buildable],
                       help="run a named query, emit fact JSONL on stdout")
    src_arg(q)
    q.add_argument("--query", required=True, help="named query from queries/ (fixed vocabulary)")
    q.add_argument("--param", action="append", metavar="k=v", help="string parameter")
    q.add_argument("--param-json", action="append", metavar="k=JSON", help="structured parameter")
    q.add_argument("--timeout", type=int, default=server.QUERY_TIMEOUT)
    q.add_argument("--no-build", action="store_true", help="fail instead of building on a miss")
    q.set_defaults(fn=cmd_query)

    ql = sub.add_parser("queries", parents=[common], help="list the named query vocabulary")
    ql.set_defaults(fn=cmd_queries)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
