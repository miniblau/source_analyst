"""Manifest loading and validation (design §10.1).

Two orthogonal axes, never conflated: a **class** is the language-agnostic
concept (`manifests/classes/<class>.yaml`); a **pattern file** is its concrete
realization in one frontend (`manifests/patterns/<lang>/<class>.yaml`).

Selection rule: for each class where `applies_to ∩ repo_languages ≠ ∅`, load the
class joined with the pattern files for the intersecting languages *only* — so
a class with no realization in a repo's languages never loads a dead stub.

This module contains no vuln knowledge and no query knowledge. `queries:` in a
pattern file names the blocks each query takes, and the loader merges those
blocks' keys; it never learns what a parameter means.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..cpg.workspace import repo_root

# Same guard as queries.py:29 and rules.py:17. Without it a --class/--lang
# value is interpolated straight into a path, and load_class("../classes/sqli")
# opens and YAML-parses an out-of-tree file before the self-declaration check
# happens to reject it. Validate the name, do not rely on that accident.
NAME_RE = re.compile(r"^[a-z0-9_]+$")

CLASS_REQUIRED = ("class", "title", "applies_to", "narrative")
PATTERN_REQUIRED = ("class", "language", "queries")


class ManifestError(Exception):
    """A manifest is malformed. Always fatal — a bad manifest silently
    producing an empty pattern set is how a scan reports a clean bill of
    health it never earned."""


def manifests_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_MANIFESTS")
    return Path(env).expanduser().resolve() if env else repo_root() / "manifests"


def config_dir() -> Path:
    env = os.environ.get("SOURCE_ANALYST_CONFIG")
    return Path(env).expanduser().resolve() if env else repo_root() / "config"


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise ManifestError(f"{path}: invalid YAML ({e})")
    if not isinstance(doc, dict):
        raise ManifestError(f"{path}: expected a mapping at the top level")
    return doc


def language_map() -> dict[str, list[str]]:
    """Extension → language map (§10.2). Static, explicit, boring."""
    path = config_dir() / "languages.yaml"
    if not path.is_file():
        raise ManifestError(f"missing language map: {path}")
    doc = _read_yaml(path)
    out: dict[str, list[str]] = {}
    for lang, exts in doc.items():
        if not isinstance(exts, list) or not all(isinstance(e, str) for e in exts):
            raise ManifestError(f"{path}: {lang} must map to a list of extensions")
        out[str(lang)] = exts
    return out


# ----------------------------------------------------------------- containers


@dataclass(frozen=True)
class VulnClass:
    name: str
    title: str
    applies_to: list[str]
    narrative: str
    seed_hypotheses: list[str]
    max_static_tier: str
    references: list[str]
    path: Path


@dataclass(frozen=True)
class Patterns:
    vuln_class: str
    language: str
    blocks: dict[str, dict[str, Any]]
    queries: dict[str, list[str]]
    rules: list[str]
    path: Path

    def params_for(self, query: str) -> dict[str, Any]:
        """Merge the blocks this query takes into a params object.

        The loader never inspects a parameter's meaning — block keys ARE query
        parameter names, so a new query is a line in `queries:`, not code.
        """
        if query not in self.queries:
            raise ManifestError(
                f"{self.path}: query {query!r} is not bound; "
                f"bound queries: {', '.join(sorted(self.queries)) or '(none)'}")
        params: dict[str, Any] = {}
        for block in self.queries[query]:
            clash = sorted(set(params) & set(self.blocks[block]))
            # Silent last-wins here would drop a sink or sanitizer list with no
            # diagnostic, and this is the seam the whole "patterns are data"
            # property rests on. The current manifest avoids collisions only by
            # naming convention, so make the next one an error, not a surprise.
            if clash:
                raise ManifestError(
                    f"{self.path}: queries.{query} merges block {block!r} over a key already "
                    f"set by an earlier block: {', '.join(clash)}")
            params.update(self.blocks[block])
        return params


# -------------------------------------------------------------------- loading


def available_classes() -> list[str]:
    d = manifests_dir() / "classes"
    return sorted(p.stem for p in d.glob("*.yaml")) if d.is_dir() else []


def available_patterns() -> list[str]:
    d = manifests_dir() / "patterns"
    if not d.is_dir():
        return []
    return sorted(f"{p.parent.name}/{p.stem}" for p in d.glob("*/*.yaml"))


def load_class(name: str) -> VulnClass:
    if not NAME_RE.match(name):
        raise ManifestError(f"invalid vuln class name {name!r} (expected [a-z0-9_]+)")
    path = manifests_dir() / "classes" / f"{name}.yaml"
    if not path.is_file():
        raise ManifestError(
            f"unknown vuln class {name!r}; available: {', '.join(available_classes()) or '(none)'}")
    doc = _read_yaml(path)
    missing = [k for k in CLASS_REQUIRED if k not in doc]
    if missing:
        raise ManifestError(f"{path}: missing required key(s): {', '.join(missing)}")
    if doc["class"] != name:
        raise ManifestError(f"{path}: declares class {doc['class']!r} but is filed as {name!r}")
    applies_to = doc["applies_to"]
    if not isinstance(applies_to, list) or not applies_to:
        raise ManifestError(f"{path}: applies_to must be a non-empty list of languages")
    return VulnClass(
        name=name,
        title=str(doc["title"]),
        applies_to=[str(x) for x in applies_to],
        narrative=" ".join(str(doc["narrative"]).split()),
        seed_hypotheses=[" ".join(str(h).split()) for h in doc.get("seed_hypotheses", [])],
        max_static_tier=str(doc.get("max_static_tier", "static_reachability")),
        references=[str(r) for r in doc.get("references", [])],
        path=path,
    )


def load_patterns(vuln_class: str, language: str) -> Patterns:
    for label, value in (("vuln class", vuln_class), ("language", language)):
        if not NAME_RE.match(value):
            raise ManifestError(f"invalid {label} name {value!r} (expected [a-z0-9_]+)")
    path = manifests_dir() / "patterns" / language / f"{vuln_class}.yaml"
    if not path.is_file():
        raise ManifestError(
            f"no {vuln_class!r} patterns for language {language!r} at {path}; "
            f"available: {', '.join(available_patterns()) or '(none)'}")
    doc = _read_yaml(path)
    missing = [k for k in PATTERN_REQUIRED if k not in doc]
    if missing:
        raise ManifestError(f"{path}: missing required key(s): {', '.join(missing)}")
    if doc["class"] != vuln_class or doc["language"] != language:
        raise ManifestError(
            f"{path}: declares {doc['class']}/{doc['language']} but is filed as "
            f"{language}/{vuln_class}")

    reserved = set(PATTERN_REQUIRED) | {"rules"}
    blocks = {k: v for k, v in doc.items() if k not in reserved}
    for name, block in blocks.items():
        if not isinstance(block, dict):
            raise ManifestError(f"{path}: block {name!r} must be a mapping of param name to value")

    queries = doc["queries"]
    if not isinstance(queries, dict) or not queries:
        raise ManifestError(f"{path}: `queries` must be a non-empty mapping of query to blocks")
    bound: dict[str, list[str]] = {}
    for query, names in queries.items():
        if not isinstance(names, list) or not names:
            raise ManifestError(f"{path}: queries.{query} must be a non-empty list of block names")
        unknown = [n for n in names if n not in blocks]
        if unknown:
            raise ManifestError(
                f"{path}: queries.{query} references undefined block(s): {', '.join(unknown)}")
        bound[str(query)] = [str(n) for n in names]

    return Patterns(
        vuln_class=vuln_class,
        language=language,
        blocks=blocks,
        queries=bound,
        rules=[str(r) for r in doc.get("rules", [])],
        path=path,
    )


def has_patterns(vuln_class: str, language: str) -> bool:
    return (manifests_dir() / "patterns" / language / f"{vuln_class}.yaml").is_file()


def applicable(languages: list[str]) -> list[tuple[VulnClass, list[str], list[str]]]:
    """Classes with a realization in these languages: (class, realized, unrealized).

    `applies_to` is the class's ambition and deliberately runs ahead of the
    pattern files — §10.1's whole point is that adding a language is one new
    file. So a declared language with no pattern file is not an error; it is a
    *coverage gap*, and it is returned separately rather than dropped. Silently
    skipping it is how a repo gets reported clean in a language nobody wrote
    patterns for yet.
    """
    out = []
    for name in available_classes():
        vc = load_class(name)
        matched = [l for l in languages if l in vc.applies_to]
        realized = [l for l in matched if has_patterns(name, l)]
        unrealized = [l for l in matched if not has_patterns(name, l)]
        if matched:
            out.append((vc, realized, unrealized))
    return out


def validate_all() -> tuple[list[str], list[str]]:
    """Load every manifest. Returns (problems, gaps).

    A *problem* is incoherence — malformed YAML, a class/pattern mismatch, a
    query bound to an undefined block. A *gap* is a declared language with no
    pattern file yet: expected during rollout, reported so it is never mistaken
    for coverage. Only problems are fatal.
    """
    problems: list[str] = []
    gaps: list[str] = []
    try:
        language_map()
    except ManifestError as e:
        problems.append(str(e))

    # An empty manifests tree previously validated as ok:true, exit 0 — so a
    # missing or mis-pointed SOURCE_ANALYST_MANIFESTS read as a healthy install
    # and every later scan would find nothing to run. "No manifests" is a
    # broken install, never a clean bill of health.
    if not available_classes():
        problems.append(
            f"{manifests_dir()}: no vuln classes found — nothing would run "
            f"(is SOURCE_ANALYST_MANIFESTS pointing at the right tree?)")

    for name in available_classes():
        try:
            vc = load_class(name)
        except ManifestError as e:
            problems.append(str(e))
            continue
        realized = 0
        for lang in vc.applies_to:
            if not has_patterns(name, lang):
                gaps.append(f"classes/{name}.yaml: applies_to {lang!r} — no patterns/{lang}/"
                            f"{name}.yaml yet, that language is uncovered")
                continue
            try:
                load_patterns(name, lang)
                realized += 1
            except ManifestError as e:
                problems.append(str(e))
        # A class realized in NO language is the dead stub §10.1 exists to
        # prevent: it would load, match nothing, and report a clean bill of
        # health it never earned.
        if realized == 0:
            problems.append(f"classes/{name}.yaml: no pattern file in any declared language")

    for ref in available_patterns():
        lang, _, cls = ref.partition("/")
        if cls not in available_classes():
            problems.append(f"patterns/{ref}.yaml: no matching classes/{cls}.yaml")
    return problems, gaps
