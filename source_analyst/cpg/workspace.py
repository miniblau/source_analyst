"""CPG cache layout and source-tree identity (design §10.5).

The cache is keyed on a content hash of the source tree and nothing else: a
source change invalidates it, a Joern upgrade does not (the version is recorded
in meta.json and reported by `cpg status`, which is where a mismatch surfaces).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git"}
KEY_LEN = 16

# This tool ingests client source and writes it back out: the log holds code
# excerpts, agent transcripts hold whole briefings verbatim, and the CPG holds
# the tree. Default 0644/0755 makes all of that readable by every account on the
# box — wrong for material that is usually under NDA, and free to fix.
DIR_MODE = 0o700
FILE_MODE = 0o600


def private_dir(path: Path) -> Path:
    """mkdir -p, owner-only. chmod after the fact because umask masks mode=."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass  # a mode we cannot set is not a reason to fail the run
    return path


def private_file(path: Path) -> Path:
    """Tighten an existing file to owner-only."""
    try:
        os.chmod(path, FILE_MODE)
    except OSError:
        pass
    return path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def var_root() -> Path:
    env = os.environ.get("SOURCE_ANALYST_VAR")
    return Path(env).expanduser().resolve() if env else repo_root() / "var"


def source_hash(src: Path) -> str:
    """sha256 over (relpath, file content) for every non-VCS file, path-sorted.

    Symlinks are recorded by target string, never followed — a symlink loop must
    not be able to hang a cache-key computation.
    """
    h = hashlib.sha256()
    entries: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            entries.append((str(p.relative_to(src)), p))
    for rel, p in sorted(entries):
        h.update(rel.encode())
        h.update(b"\0")
        if p.is_symlink():
            h.update(b"L" + os.readlink(p).encode())
        else:
            try:
                h.update(b"F" + _file_hash(p))
            except OSError:
                h.update(b"?")
        h.update(b"\0")
    return h.hexdigest()


def _file_hash(p: Path) -> bytes:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


@dataclass(frozen=True)
class Workspace:
    src: Path
    source_hash: str
    root: Path

    @classmethod
    def of(cls, src: str | Path) -> "Workspace":
        s = Path(src).expanduser().resolve()
        if not s.is_dir():
            raise SystemExit(f"cpg: source path is not a directory: {s}")
        sh = source_hash(s)
        return cls(src=s, source_hash=sh, root=var_root() / "cpg" / sh[:KEY_LEN])

    @property
    def cpg_bin(self) -> Path:
        return self.root / "cpg.bin"

    @property
    def meta_json(self) -> Path:
        return self.root / "meta.json"

    @property
    def pid_file(self) -> Path:
        return self.root / "server.pid"

    @property
    def port_file(self) -> Path:
        return self.root / "server.port"

    @property
    def server_log(self) -> Path:
        return self.root / "server.log"

    @property
    def build_log(self) -> Path:
        return self.root / "build.log"

    @property
    def query_dir(self) -> Path:
        return self.root / "q"

    def is_built(self) -> bool:
        return self.cpg_bin.is_file() and self.meta_json.is_file()

    def read_meta(self) -> dict:
        try:
            return json.loads(self.meta_json.read_text())
        except (OSError, ValueError):
            return {}

    def write_meta(self, meta: dict) -> None:
        self.meta_json.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
