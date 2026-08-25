#!/usr/bin/env python3
"""Runner shim: stdin -> `opencode run` -> stdout.

Why a shim exists at all: `opencode run` takes its message as an argv positional
and never reads stdin (verified against 1.18.23 — a piped payload hangs until the
timeout kills it), while `run_agent`'s contract is to write the composed prompt to
the runner's stdin. Nothing in `runners.yaml` can bridge that, because `cmd` is an
argv list and not a shell. So this file is the bridge, and it is out here in
`tools/` for the same reason `openai_chat.py` is: it is one possible runner among
many and `run_agent` must not care which one you use.

Three things it fixes beyond the stdin gap, each of them measured rather than
assumed, on the local MoE:

  * **`--dir <scratch home>`.** opencode injects every `AGENTS.md`/`CLAUDE.md` it
    finds in the working tree into the system prompt. Run inside this repo that is
    the 16KB operating contract — 18.5KB of system prompt to answer "reply PONG",
    which cost 86s against 12s from a directory without one. That is a fixed tax
    on *every* case in a chunk, paid to feed the agent a document about how to
    write code in this repo, which is not the question it was asked. The run home
    therefore holds the agent definition and nothing else.

  * **`--title`.** With no title opencode spends a *second* model call generating
    one from the prompt. On this box that is a whole extra inference per batch.

  * **`--agent`.** The default `build` agent ships opencode's entire coding
    toolset in the request. The agent used here (`config/opencode/judge.md`) has
    every tool switched off, which is what makes the call a single-shot completion
    instead of an agent loop.

**THE BRIEFING GOES IN ARGV, WHICH IS PUBLIC ON THIS MACHINE.** `opencode run`
takes its message as a positional argument and there is nowhere else to put it, so
for as long as the process runs — minutes per batch on local hardware — the full
prompt sits in `/proc/<pid>/cmdline`, which is mode 0444 and readable by every
account on the box. That prompt is the briefing: client source, verbatim. It is the
exact material `run_agent` writes to a 0600 transcript and `belief` keeps under a
0700 directory, and this runner hands it to `ps`.

Consequences, stated plainly rather than buried: do NOT use this runner on a shared
or multi-user host, and prefer `openai_compat`, which writes the prompt to a pipe
and never exposes it. The fix, if this runner ever needs to be safe there, is
opencode's `-f/--file` attachment — put the briefing in a 0600 file and pass a
short instruction in argv instead. That is untested here and is not done, because
changing it silently would be worse than saying so.

**No constrained decoding.** opencode exposes no hook for a JSON schema, so this
runner is the equivalent of `openai_compat_free`, never of `openai_compat`. What
the model returns is what it chose to return, and the format is part of what you
are measuring. Do not compare a scorecard from this runner against a constrained
one and call the difference judgement.

Provider and model live in opencode's own **global** config
(`~/.config/opencode/opencode.jsonc`). They must not be put in a project-level
`.opencode/opencode.json`: a `provider` block there sends opencode looking for the
provider's npm package in a directory that has none, and with no package manager
on PATH it hangs silently rather than failing.

Env:
    OPENCODE_BIN     path to the binary; default `opencode` on PATH
    OPENCODE_AGENT   opencode agent name; default `judge`
    OPENCODE_HOME    run home; default <repo>/var/opencode_home
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# opencode paints its stdout. A stray escape sequence wrapped around an otherwise
# good record is the difference between a parsed hypothesis and a discarded line,
# so strip them here rather than letting `run_agent` count them as model slop.
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def resolve_bin() -> str:
    """The binary, which is commonly installed outside PATH (~/.opencode/bin)."""
    env = os.environ.get("OPENCODE_BIN")
    if env:
        return env
    found = shutil.which("opencode")
    if found:
        return found
    fallback = Path.home() / ".opencode" / "bin" / "opencode"
    return str(fallback) if fallback.is_file() else "opencode"


def build_home(repo: Path, agent: str) -> Path:
    """A directory holding the agent definition and deliberately nothing else.

    Rebuilt every run from `config/opencode/`, so the committed definition is the
    only source of truth and a stale copy cannot quietly serve a different prompt.
    """
    home = Path(os.environ.get("OPENCODE_HOME") or (repo / "var" / "opencode_home"))
    dest = home / ".opencode" / "agent"
    dest.mkdir(parents=True, exist_ok=True)
    src = repo / "config" / "opencode" / f"{agent}.md"
    if not src.is_file():
        raise SystemExit(f"opencode_run: no agent definition: {src}")
    shutil.copyfile(src, dest / f"{agent}.md")
    # An AGENTS.md/CLAUDE.md reaching this directory would silently reintroduce the
    # prompt tax this isolation exists to remove, so assert it is not there.
    for stray in ("AGENTS.md", "CLAUDE.md"):
        if (home / stray).exists():
            raise SystemExit(f"opencode_run: {stray} in the run home defeats isolation: {home}")
    return home


def main() -> int:
    p = argparse.ArgumentParser(prog="opencode_run")
    p.add_argument("--repo", required=True, help="repo root; supplies config/opencode/")
    p.add_argument("--model", help="provider/model as opencode names it")
    p.add_argument("--title", default="source_analyst",
                   help="session title; supplying one avoids a second model call")
    args = p.parse_args()

    payload = sys.stdin.read()
    if not payload.strip():
        print("opencode_run: nothing on stdin", file=sys.stderr)
        return 2

    repo = Path(args.repo).resolve()
    agent = os.environ.get("OPENCODE_AGENT", "judge")
    home = build_home(repo, agent)

    cmd = [resolve_bin(), "run", "--dir", str(home), "--agent", agent,
           "--title", args.title]
    if args.model:
        cmd += ["-m", args.model]
    cmd.append(payload)

    print(f"opencode_run: {' '.join(cmd[:-1])} (+{len(payload)} bytes of prompt)",
          file=sys.stderr)
    # Said every run, not just documented: the prompt is about to be visible in
    # /proc to every account on this machine, and whoever is running it is entitled
    # to know that before the source of a client's repo goes there.
    print("opencode_run: WARNING the briefing is passed in argv and is readable via "
          "/proc/<pid>/cmdline while this runs — not safe on a shared host; use "
          "openai_compat there", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print(f"opencode_run: not installed: {cmd[0]}", file=sys.stderr)
        return 2

    if proc.stderr.strip():
        print(proc.stderr.strip()[-2000:], file=sys.stderr)
    if proc.returncode != 0:
        # Same discipline as openai_chat: on a failure the raw text is the one
        # artifact that explains the run, so it goes where the transcript catches it.
        print("opencode_run: raw output follows ---8<---", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        print("---8<--- end raw output", file=sys.stderr)
        return proc.returncode

    sys.stdout.write(ANSI.sub("", proc.stdout))
    return 0


if __name__ == "__main__":
    sys.exit(main())
