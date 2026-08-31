"""Language detection (design §10.2) — a static extension map and a count.

No linguist, no shell-out, no vendoring heuristics. The output is read and
confirmed by the operator; auto-detect-and-run is Phase 3+.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..cpg.workspace import SKIP_DIRS

# Directories that are somebody else's code. Counting them makes a Java service
# with a vendored JS bundle look like a JS repo, which would then load the wrong
# pattern files — so the skip list is part of the contract, not an optimisation.
SKIP_TREES = SKIP_DIRS | {
    "node_modules", "vendor", "third_party", "target", "build", "dist",
    "out", ".gradle", ".idea", "venv", ".venv", "__pycache__", "Pods",
}


def counts(src: Path, ext_map: dict[str, list[str]], report: dict | None = None) -> list[dict]:
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
    if report is not None:
        # How much of the tree was excluded as somebody else's code. The skip
        # list changes what languages are detected, so an operator confirming
        # the detection needs to see it acted.
        report["skipped_trees"] = skipped
    rows.sort(key=lambda r: (-r["file_count"], r["language"]))
    return rows


# How much of a file to read when looking for an import. An import sits at the top;
# reading whole files across a tree to find one is a scan, not a detection.
IMPORT_HEAD_BYTES = 4096
# Manifests that declare dependencies, per ecosystem. Extending this is a line here.
DEP_FILES = ("package.json", "pom.xml", "build.gradle", "build.gradle.kts")


def frameworks(src: Path, spec: dict, languages: set[str] | None = None) -> list[dict]:
    """Which frameworks are PRESENT in this tree (design §10.2).

    Detection drives REPORTING, never selection. Nothing here filters which
    patterns run: a class's sinks are the union of its language-level and
    framework-level entries, always, because React aims to prevent XSS — which is
    why its escape hatches are the interesting sinks — and people write plain
    unsafe JS beside them. A precedence chain would drop the second.

    What this exists for is the gap a merged manifest cannot report: scan an
    Angular app with React-only patterns and the short result reads as a clean
    one. A language declared with no pattern file is already reported that way;
    this is the same honesty one level down.

    Two signals, either sufficient: a dependency named in a manifest file, or an
    import in the source. Dependencies are the stronger signal and are checked
    first — an import can be a comment or a string, a dependency was installed.
    """
    found: dict[str, dict] = {}

    def note(name: str, how: str, where: str) -> None:
        row = found.setdefault(name, {"kind": "framework", "framework": name,
                                      "language": spec[name].get("language", ""),
                                      "evidence": []})
        if len(row["evidence"]) < 4:
            row["evidence"].append({"how": how, "where": where})

    wanted = {n: s for n, s in spec.items()
              if languages is None or s.get("language") in languages}
    if not wanted:
        return []

    dep_names = {n: set(s.get("deps") or []) for n, s in wanted.items()}
    import_res = {n: [re.compile(p) for p in (s.get("imports") or [])]
                  for n, s in wanted.items()}

    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_TREES)
        rel_dir = os.path.relpath(dirpath, src)
        for name in filenames:
            path = Path(dirpath) / name
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if name in DEP_FILES:
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if name == "package.json":
                    try:
                        doc = json.loads(text)
                    except ValueError:
                        doc = {}
                    declared = set(doc.get("dependencies") or {}) | set(
                        doc.get("devDependencies") or {})
                    for fw, deps in dep_names.items():
                        if deps & declared:
                            note(fw, "dependency", rel)
                else:
                    for fw, deps in dep_names.items():
                        if any(d in text for d in deps):
                            note(fw, "dependency", rel)
                continue
            # Imports, from the head of the file only.
            if not import_res:
                continue
            try:
                with path.open("r", errors="replace") as fh:
                    head = fh.read(IMPORT_HEAD_BYTES)
            except OSError:
                continue
            for fw, pats in import_res.items():
                if fw in found and found[fw]["evidence"]:
                    continue
                if any(p.search(head) for p in pats):
                    note(fw, "import", rel)

    return [found[k] for k in sorted(found)]
