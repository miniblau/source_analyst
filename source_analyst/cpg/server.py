"""Joern lifecycle: build (cache-miss) -> load -> warm-query* (design §10.5).

One detached `joern --server` per workspace, addressed through pid/port files in
the cache dir, so a 20-query burst from `trace` hits a warm JVM and never a cold
rebuild. Nothing here reasons about code; it moves Scala in and JSON out.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .workspace import Workspace, private_dir, private_file, var_root

JOERN = os.environ.get("JOERN_BIN", "joern")
JOERN_PARSE = os.environ.get("JOERN_PARSE_BIN", "joern-parse")

START_TIMEOUT = int(os.environ.get("CPG_START_TIMEOUT", "300"))
QUERY_TIMEOUT = int(os.environ.get("CPG_QUERY_TIMEOUT", "300"))
BUILD_TIMEOUT = int(os.environ.get("CPG_BUILD_TIMEOUT", "3600"))

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)


def log(msg: str) -> None:
    print(f"cpg: {msg}", file=sys.stderr)


# --------------------------------------------------------------------- build


def joern_version() -> str:
    """Read the version off the installed jar — `joern-parse --version` throws,
    and `joern --version` drops into the REPL instead of exiting."""
    exe = shutil.which(JOERN)
    if not exe:
        return "unknown"
    lib = Path(exe).resolve().parent / "lib"
    for jar in sorted(lib.glob("io.joern.joern-cli-*.jar")):
        m = re.search(r"io\.joern\.joern-cli-(.+)\.jar$", jar.name)
        if m:
            return m.group(1)
    return "unknown"


# javasrc2cpg's default delombok mode analyses *delomboked* source, so every
# line number on a Lombok project points into a rewritten file (verified on
# WebGoat: Servers.java reported line 92 in a 71-line file). `types-only` keeps
# delombok's type information but analyses the real source, so file:line refs
# in findings match what the reviewer opens.
FRONTEND_DEFAULTS = {"JAVASRC": ["--delombok-mode", "types-only"]}


def build(
    ws: Workspace,
    language: str | None = None,
    force: bool = False,
    frontend_args: list[str] | None = None,
) -> bool:
    """Build the CPG if the cache misses. Returns True if a build ran."""
    if ws.is_built() and not force:
        return False
    if is_running(ws):
        stop(ws)
    private_dir(ws.root)
    tmp = ws.root / "cpg.bin.tmp"
    tmp.unlink(missing_ok=True)
    cmd = [JOERN_PARSE, str(ws.src), "--output", str(tmp)]
    if language:
        cmd += ["--language", language]
    fargs = frontend_args if frontend_args else FRONTEND_DEFAULTS.get((language or "").upper(), [])
    if fargs:
        cmd += ["--frontend-args", *fargs]
    log(f"building CPG for {ws.src} ({ws.source_hash[:16]}) — this is the slow path")
    started = time.time()
    with ws.build_log.open("w") as lf:
        proc = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, timeout=BUILD_TIMEOUT)
    if proc.returncode != 0 or not tmp.is_file():
        raise SystemExit(f"cpg: build failed (exit {proc.returncode}); see {ws.build_log}")
    tmp.replace(ws.cpg_bin)

    # A frontend that parsed NOTHING still exits 0 and still writes a graph.
    # Measured 2026-09-04 on two Juice Shop `codefixes/*.ts` snippets, which are
    # spliced fragments with one unclosed brace: jssrc2cpg emitted a 4,660-byte
    # CPG holding zero files, said nothing on stderr, and returned success. The
    # same tree minus those two files produced 60KB and parsed fine.
    #
    # Left alone that is the worst failure this system can have. Every later query
    # answers "0 facts" honestly, `brief` finds no cases, the report is empty, and
    # the whole run reads as a clean bill of health for code nobody ever parsed —
    # and because cpg.bin was cached, it would read that way on every future run
    # too. So the empty CPG is deleted rather than cached, and the build fails.
    meta = {
        "source": str(ws.src),
        "source_hash": ws.source_hash,
        "language": language or "auto",
        "frontend_args": fargs,
        "joern_version": joern_version(),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build_seconds": round(time.time() - started, 1),
    }
    # Written before counting because counting needs a server, and `ensure_server`
    # refuses to start for a workspace that is not `is_built()` — which is cpg.bin
    # AND meta.json. Both are removed again if the count comes back empty.
    ws.write_meta(meta)

    files, methods = _cpg_counts(ws)
    if files == 0:
        stop(ws)
        ws.cpg_bin.unlink(missing_ok=True)
        ws.meta_json.unlink(missing_ok=True)
        raise SystemExit(
            f"cpg: build produced an EMPTY CPG for {ws.src} (0 files, 0 methods) — "
            f"the frontend exited 0 but parsed nothing, so this is a frontend or "
            f"source problem, NOT a codebase with no vulnerabilities. Check that "
            f"--lang matches the tree and that the sources parse standalone; "
            f"see {ws.build_log}. The empty CPG was discarded, not cached."
        )

    # Recorded so `cpg status` can show what was actually parsed. A tree whose file
    # count is far below what you expected is the partial-parse case: not empty, so
    # not fatal, but not the whole codebase either.
    meta["cpg_files"] = files
    meta["cpg_methods"] = methods
    ws.write_meta(meta)
    log(f"built {ws.cpg_bin} in {round(time.time() - started, 1)}s "
        f"({files} files, {methods} methods)")
    return True


COUNTS = re.compile(r"CPGCOUNTS (\d+) (\d+)")


def _cpg_counts(ws: Workspace) -> tuple[int, int]:
    """(files, methods) in the built CPG, via the server.

    REPL stdout is diagnostics, not a success signal (see `run_scala`), so the
    marker must be found and parsed or this raises. Reading a missing marker as
    "zero" would fail an otherwise good build; reading it as "fine" would restore
    exactly the silence this exists to break.
    """
    # An EXPRESSION, not a println: what comes back is the REPL's value echo
    # (`val res0: String = "CPGCOUNTS 4 40"`), the same way `overlays` reads its
    # answer. A println's side-effect output does not reach this stdout at all.
    out = run_scala(ws, 's"CPGCOUNTS ${cpg.file.size} ${cpg.method.size}"')
    m = COUNTS.search(out)
    if not m:
        raise SystemExit(
            f"cpg: could not count the CPG just built for {ws.src} — the server "
            f"answered without the marker, so whether it parsed anything is "
            f"unknown and must not be assumed. Output:\n{out[:500]}"
        )
    return int(m.group(1)), int(m.group(2))


# -------------------------------------------------------------------- server


def _pid(ws: Workspace) -> int | None:
    try:
        return int(ws.pid_file.read_text().strip())
    except (OSError, ValueError):
        return None


def _port(ws: Workspace) -> int | None:
    try:
        return int(ws.port_file.read_text().strip())
    except (OSError, ValueError):
        return None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def is_running(ws: Workspace) -> bool:
    pid = _pid(ws)
    return bool(pid and _alive(pid) and _port(ws))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# The CPGQL server evaluates arbitrary Scala, so an unauthenticated one is a local
# remote-code-execution endpoint that stays open for the length of a review — any
# process on the box can drive it. Binding to loopback is not enough on a shared
# host, a build agent, or a laptop running someone else's postinstall script. Joern
# takes basic auth; a per-workspace random credential costs nothing.
AUTH_USER = "source_analyst"


def _auth_file(ws: Workspace) -> Path:
    return ws.root / "server.auth"


def _read_auth(ws: Workspace) -> str | None:
    try:
        return _auth_file(ws).read_text().strip() or None
    except OSError:
        return None


def _new_auth(ws: Workspace) -> str:
    secret = secrets.token_urlsafe(32)
    private_dir(ws.root)
    f = _auth_file(ws)
    f.write_text(secret + "\n")
    private_file(f)
    return secret


def _post(port: int, code: str, timeout: int, secret: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if secret:
        token = base64.b64encode(f"{AUTH_USER}:{secret}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/query-sync",
        data=json.dumps({"query": code}).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def reap_others(ws: Workspace) -> list[str]:
    """Stop every OTHER workspace's server. Returns the hashes stopped.

    The cache is keyed on a source hash, so every rebuild — a corpus edit, a new
    target, a fixture tweak — mints a new workspace and leaves the previous
    server running with its whole CPG resident. Nothing ever reaped them.

    Measured 2026-09-04: fifteen live servers had accumulated over fifteen days
    holding 13.1GB. On this 30GB box that left the 20.2GB model unable to stay
    resident, paging experts out of swap on every token — generation fell from a
    benchmarked 11.65 t/s to 0.68, a 17x tax on every agent call. It was
    invisible in the logs because nothing failed: each query still answered and
    each call still returned, only ~17x slower, which reads as "the model is
    slow" rather than "the substrate is holding the model's memory".

    So: one CPG server at a time. A warm server is worth keeping (design §10.5)
    precisely because loading is expensive; a warm server for a tree nobody is
    analysing is worth nothing and costs the model its residency. The model host
    is held to the same one-at-a-time rule for the same reason, in the place that
    is allowed to know about model hosts: config/runners.yaml.
    """
    stopped = []
    for d in running_workspaces(var_root() / "cpg"):
        if d.name == ws.source_hash:
            continue
        other = Workspace(src=Path(d.name), source_hash=d.name, root=d)
        if stop(other):
            stopped.append(d.name)
    if stopped:
        log(f"reaped {len(stopped)} idle server(s) to free memory: {', '.join(stopped)}")
    return stopped


def ensure_server(ws: Workspace, timeout: int = START_TIMEOUT) -> int:
    """Return the port of a live server for this workspace, starting one if needed."""
    if is_running(ws):
        port = _port(ws)
        assert port is not None
        return port
    if not ws.is_built():
        raise SystemExit(f"cpg: no CPG for {ws.src} — run `cpg build --src {ws.src}` first")

    # Before paying for a JVM + CPG load, give back the memory the last one holds.
    reap_others(ws)

    ws.pid_file.unlink(missing_ok=True)
    ws.port_file.unlink(missing_ok=True)
    port = _free_port()
    secret = _new_auth(ws)
    cmd = [
        JOERN,
        "--server",
        "--server-host",
        "127.0.0.1",
        "--server-port",
        str(port),
        "--server-auth-username",
        AUTH_USER,
        "--server-auth-password",
        secret,
        "--nocolors",
        str(ws.cpg_bin),
    ]
    log(f"starting joern server on 127.0.0.1:{port} (loading {ws.cpg_bin})")
    logfh = ws.server_log.open("w")
    proc = subprocess.Popen(
        cmd, stdout=logfh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        start_new_session=True, cwd=str(ws.root),
    )
    ws.pid_file.write_text(f"{proc.pid}\n")
    ws.port_file.write_text(f"{port}\n")

    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(
                f"cpg: joern server exited ({proc.returncode}) during load; see {ws.server_log}"
            )
        try:
            _post(port, "1", timeout=10, secret=secret)
            log(f"server ready (pid {proc.pid}, port {port})")
            return port
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            time.sleep(1.0)
    stop(ws)
    raise SystemExit(f"cpg: server did not become ready in {timeout}s; see {ws.server_log}")


def stop(ws: Workspace) -> bool:
    pid = _pid(ws)
    stopped = False
    if pid and _alive(pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        for _ in range(50):
            if not _alive(pid):
                break
            time.sleep(0.2)
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        stopped = True
        log(f"stopped server pid {pid}")
    ws.pid_file.unlink(missing_ok=True)
    ws.port_file.unlink(missing_ok=True)
    _auth_file(ws).unlink(missing_ok=True)
    return stopped


def running_workspaces(var_cpg: Path) -> list[Path]:
    if not var_cpg.is_dir():
        return []
    return sorted(d for d in var_cpg.iterdir() if (d / "server.pid").is_file())


# --------------------------------------------------------------------- query


def run_scala(ws: Workspace, code: str, timeout: int = QUERY_TIMEOUT) -> str:
    """Execute Scala on the warm server, returning the REPL's stdout (de-ANSI'd).

    The server answers `success: true` even for compile errors and thrown
    exceptions, so this text is diagnostics only — never a success signal.
    Callers decide success by whether the query produced its output file.
    """
    port = ensure_server(ws)
    # None when the server predates this credential or was started by hand: Joern
    # ignores the header it did not ask for, so an older warm server keeps working.
    try:
        resp = _post(port, code, timeout=timeout, secret=_read_auth(ws))
    except urllib.error.URLError as e:
        raise SystemExit(f"cpg: query transport failed on port {port}: {e}")
    return strip_ansi(resp.get("stdout") or "")


def overlays(ws: Workspace) -> list[str]:
    """Applied CPG overlays — `dataflowOss` must be present for reachability."""
    out = run_scala(ws, 'cpg.metaData.overlays.l.mkString(",")', timeout=60)
    m = re.search(r'"([^"]*)"', out)
    return [o for o in m.group(1).split(",") if o] if m else []
