"""Language detection (design §10.2) — a static extension map and a count.

No linguist, no shell-out, no vendoring heuristics. The output is read and
confirmed by the operator; auto-detect-and-run is Phase 3+.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..cpg.workspace import SKIP_DIRS

# Directories that are somebody else's code. Counting them makes a Java service
# with a vendored JS bundle look like a JS repo, which would then load the wrong
# pattern files — so the skip list is part of the contract, not an optimisation.
SKIP_TREES = SKIP_DIRS | {
    "node_modules", "vendor", "third_party", "target", "build", "dist",
    "out", ".gradle", ".idea", "venv", ".venv", "__pycache__", "Pods",
}


def counts(src: Path, ext_map: dict[str, list[str]]) -> list[dict]:
    """Count files per language, most files first. Ties break on name so the
    output is a stable ordering, not an accident of directory traversal."""
    by_ext = {e.lower(): lang for lang, exts in ext_map.items() for e in exts}
    tally: dict[str, int] = {lang: 0 for lang in ext_map}
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        pruned = [d for d in dirnames if d in SKIP_TREES]
        skipped += len(pruned)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_TREES)
        for name in filenames:
            lang = by_ext.get(Path(name).suffix.lower())
            if lang:
                tally[lang] += 1

    rows = [
        {"kind": "language", "language": lang, "file_count": n,
         "extensions": sorted(ext_map[lang])}
        for lang, n in tally.items() if n
    ]
    rows.sort(key=lambda r: (-r["file_count"], r["language"]))
    return rows
