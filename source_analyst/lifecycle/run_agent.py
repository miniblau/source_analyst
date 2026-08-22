"""`run_agent` — hand a briefing to a model and get JSONL back (design §7).

This is the seam. Everything on one side of it is byte-reproducible; everything
on the other side is a language model. The tool itself is on the deterministic
side: it spawns a command from `config/runners.yaml`, writes the agent prompt and
the briefing to its stdin, and reads JSON objects off its stdout. It forms no
opinion, edits nothing the model said, and writes nothing to the log — `admit`
is still the only door into the log, and it re-validates everything.

Consequences worth stating, because they are the point:

  * No provider, model name, API key or SDK appears in this file or anywhere else
    under `source_analyst/`. Pointing an agent at a different model is a config
    edit (§7, decided 2026-08-21).
  * A model that hallucinates a fact id gets through here and is rejected by
    `admit`. That is by design — this tool is a transport, not a gate.

    brief --agent hypothesize --class sqli --lang java \
      | run_agent --agent hypothesize \
      | admit --type hypothesis --class sqli --lang java --src agent:hypothesize
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from .. import records
from ..cpg.workspace import repo_root, var_root

PLACEHOLDERS = ("agent", "model", "prompt", "repo")


class RunnerError(Exception):
    """The runner is misconfigured or could not be run. Always fatal."""


def config_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    return Path(env).expanduser().resolve() if env else repo_root() / "config"


def load_runners() -> dict[str, Any]:
    path = config_dir() / "runners.yaml"
    if not path.is_file():
        raise RunnerError(f"missing runner config: {path}")
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or not isinstance(doc.get("runners"), dict) or not doc["runners"]:
        raise RunnerError(f"{path}: expected a non-empty `runners` mapping")
    return doc


def select(doc: dict[str, Any], agent: str, override: str | None) -> tuple[str, dict[str, Any]]:
    """Which runner serves this agent. Explicit flag > env > per-agent > default."""
    name = override or os.environ.get("SOURCE_ANALYST_RUNNER") \
        or (doc.get("agents") or {}).get(agent) or doc.get("default")
    if not name:
        raise RunnerError("no runner selected and no `default` in runners.yaml")
    if name not in doc["runners"]:
        raise RunnerError(
            f"unknown runner {name!r}; configured: {', '.join(sorted(doc['runners']))}")
    spec = doc["runners"][name] or {}
    if not isinstance(spec.get("cmd"), list) or not spec["cmd"]:
        raise RunnerError(f"runner {name!r} has no `cmd` list")
    return name, spec


def prompt_path(agent: str) -> Path:
    # Same name discipline as the manifest loader: an agent name is a vocabulary
    # item, not a path fragment, so a traversal can never reach outside agents/.
    if not agent.replace("_", "").isalnum():
        raise RunnerError(f"invalid agent name {agent!r}")
    path = repo_root() / "agents" / f"{agent}.md"
    if not path.is_file():
        raise RunnerError(f"no prompt for agent {agent!r}: {path}")
    return path


def build_cmd(spec: dict[str, Any], agent: str) -> list[str]:
    values = {
        "agent": agent,
        "model": str(spec.get("model", "")),
        "prompt": str(prompt_path(agent)),
        "repo": str(repo_root()),
    }
    out = []
    for part in spec["cmd"]:
        s = str(part)
        for key in PLACEHOLDERS:
            s = s.replace("{" + key + "}", values[key])
        if "{model}" in str(part) and not values["model"]:
            raise RunnerError("runner cmd uses {model} but the runner spec sets no `model`")
        out.append(s)
    return out


def compose(agent: str, briefing: str) -> str:
    """Prompt then briefing, one string on stdin.

    Deliberately not a chat structure: the lowest common denominator across every
    runner worth supporting is one blob of text on stdin. An agent that needs
    system/user separation gets a runner that splits on the delimiter — which is
    a config decision, not a change here. (No runner is named in this file on
    purpose; tests/test_run_agent.py enforces that.)
    """
    return (f"{prompt_path(agent).read_text().rstrip()}\n\n"
            f"---\n\n# Briefing (JSONL)\n\n{briefing.strip()}\n")


def extract(stdout: str) -> tuple[list[dict], list[str]]:
    """JSON objects out of whatever the model actually emitted.

    Models fence code and narrate around it. Fences are stripped, non-JSON lines
    are discarded and RETURNED, not dropped silently — how much slop a model
    produced is a fact about that model, and it belongs in the run meta where it
    can be compared across models rather than being quietly cleaned up.
    """
    objs, junk = [], []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("```"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            junk.append(line)
            continue
        if isinstance(obj, dict):
            objs.append(obj)
        else:
            junk.append(line)
    return objs, junk


def transcript_dir() -> Path:
    return var_root() / "agent_runs"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="run_agent", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--agent", required=True, help="agent name; must have agents/<name>.md")
    p.add_argument("--runner", help="runner from config/runners.yaml (overrides config)")
    p.add_argument("--timeout", type=int, help="seconds; overrides the runner's own timeout")
    p.add_argument("--dry-run", action="store_true",
                   help="print the resolved command and composed input, run nothing")
    args = p.parse_args(argv)

    try:
        doc = load_runners()
        name, spec = select(doc, args.agent, args.runner)
        cmd = build_cmd(spec, args.agent)
        briefing = sys.stdin.read()
        payload = compose(args.agent, briefing)
    except RunnerError as e:
        raise SystemExit(f"run_agent: {e}")

    if not briefing.strip():
        raise SystemExit("run_agent: nothing on stdin — expected a briefing")

    if args.dry_run:
        print(json.dumps({"cmd": "run_agent", "runner": name, "argv": cmd,
                          "input_bytes": len(payload), "dry_run": True},
                         separators=(",", ":")), file=sys.stderr)
        sys.stdout.write(payload)
        return 0

    timeout = args.timeout or int(spec.get("timeout", 900))
    started = time.time()
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True, text=True,
                              timeout=timeout, cwd=repo_root())
    except FileNotFoundError:
        raise SystemExit(f"run_agent: runner {name!r} not installed: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise SystemExit(f"run_agent: runner {name!r} exceeded {timeout}s")
    elapsed = round(time.time() - started, 3)

    # The transcript is provenance for a nondeterministic step: the exact bytes in
    # and out, so a surprising hypothesis can be traced to what the model was
    # actually shown. It stays out of log.jsonl — it is not a fact.
    run_id = records.ulid()
    tdir = transcript_dir()
    tdir.mkdir(parents=True, exist_ok=True)
    transcript = tdir / f"{run_id}.{args.agent}.txt"
    transcript.write_text(
        f"# runner: {name}\n# argv: {json.dumps(cmd)}\n# rc: {proc.returncode}\n"
        f"# elapsed_s: {elapsed}\n\n===== STDIN =====\n{payload}\n"
        f"===== STDOUT =====\n{proc.stdout}\n===== STDERR =====\n{proc.stderr}\n")

    objs, junk = extract(proc.stdout)
    meta = {"cmd": "run_agent", "runner": name, "agent": args.agent, "model": spec.get("model"),
            "rc": proc.returncode, "elapsed_s": elapsed, "records": len(objs),
            "discarded_lines": len(junk), "run_id": run_id, "transcript": str(transcript)}

    if proc.returncode != 0:
        print(proc.stderr.strip()[-2000:], file=sys.stderr)
        print(json.dumps(meta, separators=(",", ":")), file=sys.stderr)
        print(f"run_agent: runner {name!r} exited {proc.returncode} — see {transcript}",
              file=sys.stderr)
        return 2

    for obj in objs:
        print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    print(json.dumps(meta, separators=(",", ":")), file=sys.stderr)

    if not objs:
        # Same discipline as an empty scan: producing nothing is not a result.
        # A silent exit 0 here would let an empty `admit` read as "the model
        # judged there was nothing to say", which it did not.
        print(f"run_agent: the runner emitted no JSON records ({len(junk)} lines discarded)"
              f" — this run established nothing; see {transcript}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
