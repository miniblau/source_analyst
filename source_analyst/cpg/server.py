"""Joern lifecycle: build (cache-miss) -> load -> warm-query* (design §10.5).

One detached `joern --server` per workspace, addressed through pid/port files in
the cache dir, so a 20-query burst from `trace` hits a warm JVM and never a cold
rebuild. Nothing here reasons about code; it moves Scala in and JSON out.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .workspace import Workspace

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
    ws.root.mkdir(parents=True, exist_ok=True)
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
    ws.write_meta(
        {
            "source": str(ws.src),
            "source_hash": ws.source_hash,
            "language": language or "auto",
            "frontend_args": fargs,
            "joern_version": joern_version(),
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "build_seconds": round(time.time() - started, 1),
        }
    )
    log(f"built {ws.cpg_bin} in {round(time.time() - started, 1)}s")
    return True


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


def _post(port: int, code: str, timeout: int) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/query-sync",
        data=json.dumps({"query": code}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def ensure_server(ws: Workspace, timeout: int = START_TIMEOUT) -> int:
    """Return the port of a live server for this workspace, starting one if needed."""
    if is_running(ws):
        port = _port(ws)
        assert port is not None
        return port
    if not ws.is_built():
        raise SystemExit(f"cpg: no CPG for {ws.src} — run `cpg build --src {ws.src}` first")

    ws.pid_file.unlink(missing_ok=True)
    ws.port_file.unlink(missing_ok=True)
    port = _free_port()
    cmd = [
        JOERN,
        "--server",
        "--server-host",
        "127.0.0.1",
        "--server-port",
        str(port),
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
            _post(port, "1", timeout=10)
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
    try:
        resp = _post(port, code, timeout=timeout)
    except urllib.error.URLError as e:
        raise SystemExit(f"cpg: query transport failed on port {port}: {e}")
    return strip_ansi(resp.get("stdout") or "")


def overlays(ws: Workspace) -> list[str]:
    """Applied CPG overlays — `dataflowOss` must be present for reachability."""
    out = run_scala(ws, 'cpg.metaData.overlays.l.mkString(",")', timeout=60)
    m = re.search(r'"([^"]*)"', out)
    return [o for o in m.group(1).split(",") if o] if m else []
