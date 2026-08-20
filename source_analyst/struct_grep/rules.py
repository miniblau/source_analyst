"""Rule catalog — the `struct_grep` vocabulary (design §10.3, rule side).

Rules are opengrep YAML files at `rules/<lang>/<class>.yaml`. They carry every
bit of vuln knowledge; `struct_grep` carries none (invariant #3). Agents select
a rule set by name — `java/sqli` — and never hand the tool rule text, the same
fixed-vocabulary posture the `.sc` queries have on the Joern side.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..cpg.workspace import repo_root

NAME_RE = re.compile(r"^[a-z0-9_]+/[a-z0-9_]+$")


def rules_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_RULES")
    return Path(env).expanduser().resolve() if env else repo_root() / "rules"


def available() -> list[str]:
    d = rules_dir()
    if not d.is_dir():
        return []
    return sorted(f"{p.parent.name}/{p.stem}" for p in d.glob("*/*.yaml"))


def resolve(name: str) -> Path:
    """Rule set name → path. The name shape forbids traversal by construction."""
    if not NAME_RE.match(name):
        raise SystemExit(
            f"struct_grep: invalid rule set {name!r} (expected <lang>/<class>, [a-z0-9_]+)")
    path = rules_dir() / f"{name}.yaml"
    if not path.is_file():
        raise SystemExit(
            f"struct_grep: unknown rule set {name!r}; available: {', '.join(available()) or '(none)'}")
    return path
