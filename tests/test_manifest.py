"""Manifest loader, validator and language detection (§10.1, §10.2).

Pure deterministic core: no Joern, no LLM, no network. If any test here needs
one of those, the seam has been broken.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from source_analyst.manifest import detect
from source_analyst.manifest.loader import (
    ManifestError,
    applicable,
    available_classes,
    language_map,
    load_class,
    load_patterns,
    validate_all,
)

ROOT = Path(__file__).resolve().parents[1]


class TestLanguageMap(unittest.TestCase):
    def test_map_is_data(self):
        m = language_map()
        self.assertEqual(m["java"], [".java"])
        self.assertIn(".tsx", m["js"])


class TestDetect(unittest.TestCase):
    def _tree(self, files: list[str]) -> Path:
        d = Path(tempfile.mkdtemp())
        for rel in files:
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x")
        return d

    def test_counts_sorted_desc(self):
        src = self._tree(["a.java", "b/c.java", "d.js", "e.swift"])
        rows = detect.counts(src, language_map())
        self.assertEqual([r["language"] for r in rows], ["java", "js", "swift"])
        self.assertEqual(rows[0]["file_count"], 2)

    def test_vendored_trees_are_not_counted(self):
        """A Java service with a vendored JS bundle must not read as a JS repo —
        it would load the wrong pattern files."""
        src = self._tree(["a.java", "node_modules/x.js", "target/gen.java",
                          "vendor/y.js", "build/z.js"])
        rows = detect.counts(src, language_map())
        self.assertEqual([r["language"] for r in rows], ["java"])
        self.assertEqual(rows[0]["file_count"], 1)

    def test_unknown_extensions_are_ignored(self):
        src = self._tree(["README.md", "Makefile", "x.py"])
        self.assertEqual(detect.counts(src, language_map()), [])


class TestClassLoading(unittest.TestCase):
    def test_sqli_class_loads(self):
        vc = load_class("sqli")
        self.assertEqual(vc.name, "sqli")
        self.assertIn("java", vc.applies_to)
        self.assertTrue(vc.narrative)
        self.assertTrue(vc.seed_hypotheses)
        # Static-only evidence may never claim `confirmed` (§6).
        self.assertNotEqual(vc.max_static_tier, "confirmed")

    def test_unknown_class_rejected(self):
        with self.assertRaises(ManifestError):
            load_class("not_a_class")

    def test_path_traversal_rejected(self):
        with self.assertRaises(ManifestError):
            load_class("../../etc/passwd")


class TestPatternLoading(unittest.TestCase):
    def test_params_merge_declared_blocks(self):
        p = load_patterns("sqli", "java")
        params = p.params_for("reachable")
        self.assertIn("annotations", params)   # from `sources`
        self.assertIn("sinks", params)         # from `sinks`
        self.assertNotIn("sanitizers", params)  # reachable does not take them

        san = p.params_for("sanitizer_on_path")
        self.assertIn("sanitizers", san)
        self.assertIn("annotations", san)

    def test_every_bound_query_exists_in_the_catalog(self):
        """A manifest may not bind a query the substrate does not have."""
        from source_analyst.cpg import queries
        p = load_patterns("sqli", "java")
        for name in p.queries:
            self.assertIn(name, queries.available(), f"{name} is not a named query")

    def test_declared_rule_sets_exist(self):
        from source_analyst.struct_grep import rules
        p = load_patterns("sqli", "java")
        for name in p.rules:
            self.assertIn(name, rules.available(), f"{name} is not a named rule set")

    def test_unbound_query_rejected(self):
        p = load_patterns("sqli", "java")
        with self.assertRaises(ManifestError):
            p.params_for("callers")

    def test_missing_language_rejected(self):
        with self.assertRaises(ManifestError):
            load_patterns("sqli", "cobol")

    def test_query_bound_to_undefined_block_is_fatal(self):
        """A typo'd block name must fail loudly. Silently merging nothing would
        run a query with an empty sink list and report a clean tree."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "classes").mkdir()
            (root / "patterns" / "java").mkdir(parents=True)
            (root / "classes" / "x.yaml").write_text(textwrap.dedent("""
                class: x
                title: X
                applies_to: [java]
                narrative: n
            """))
            (root / "patterns" / "java" / "x.yaml").write_text(textwrap.dedent("""
                class: x
                language: java
                sinks:
                  sinks: [foo]
                queries:
                  sql_sinks: [sinkz]
            """))
            env = dict(os.environ, SOURCE_ANALYST_MANIFESTS=str(root))
            proc = subprocess.run(
                [sys.executable, "-m", "source_analyst.manifest.cli", "validate"],
                cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("undefined block", proc.stdout + proc.stderr)


class TestSelection(unittest.TestCase):
    def test_class_not_applying_is_skipped_not_stubbed(self):
        self.assertEqual(applicable(["cobol"]), [])

    def test_declared_but_unrealized_language_is_a_reported_gap(self):
        """§10.1: applies_to runs ahead of pattern files by design. The gap must
        surface — silently dropping it reports a language as clean that nothing
        ever looked at."""
        [(vc, realized, unrealized)] = applicable(["java", "js"])
        self.assertEqual(vc.name, "sqli")
        self.assertEqual(realized, ["java"])
        self.assertEqual(unrealized, ["js"])

    def test_repo_manifests_are_coherent(self):
        problems, gaps = validate_all()
        self.assertEqual(problems, [])
        self.assertTrue(gaps, "sqli declares js/swift/c with no patterns yet")


class TestNoVulnKnowledgeInCode(unittest.TestCase):
    """Invariant #3, enforced mechanically rather than by review.

    A sink, source or sanitizer appearing in tool code means the manifest has
    been bypassed and adding a vuln class now requires a code change.
    """

    FORBIDDEN = ["executeQuery", "executeUpdate", "prepareStatement", "createNativeQuery",
                 "queryForList", "RequestParam", "PathVariable", "getParameter",
                 "sqlite3_exec", "strcpy"]

    def test_tool_code_names_no_sinks_or_sources(self):
        offenders = []
        for path in sorted((ROOT / "source_analyst").rglob("*.py")):
            text = path.read_text()
            for token in self.FORBIDDEN:
                if token in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {token}")
        self.assertEqual(offenders, [], "vuln knowledge belongs in manifests/, not code")

    def test_queries_name_no_sinks_or_sources(self):
        offenders = []
        for path in sorted((ROOT / "queries").glob("*.sc")):
            body = "\n".join(
                l for l in path.read_text().splitlines() if not l.strip().startswith("//"))
            for token in self.FORBIDDEN:
                if token in body:
                    offenders.append(f"{path.name}: {token}")
        self.assertEqual(offenders, [], "a query must take its patterns as params")


class TestParamsComposition(unittest.TestCase):
    """`manifest params | cpg query --params-from -` is the seam that ends
    hand-typed sink lists; it must survive a pipe."""

    def _params(self, stdin_text, param=None, param_json=None, params_from="-"):
        import argparse
        import io
        from source_analyst.cpg import cli
        ns = argparse.Namespace(params_from=params_from, param=param, param_json=param_json)
        real, sys.stdin = sys.stdin, io.StringIO(stdin_text)
        try:
            return cli._params(ns)
        finally:
            sys.stdin = real

    def test_stdin_params_are_read(self):
        self.assertEqual(self._params('{"sinks": ["a", "b"]}'), {"sinks": ["a", "b"]})

    def test_explicit_flags_override_the_manifest(self):
        out = self._params('{"sinks": ["a"], "arg_index": "1"}', param=["arg_index=2"])
        self.assertEqual(out["arg_index"], "2")
        self.assertEqual(out["sinks"], ["a"])

    def test_non_object_params_rejected(self):
        with self.assertRaises(SystemExit):
            self._params('["not", "an", "object"]')

    def test_malformed_json_rejected(self):
        with self.assertRaises(SystemExit):
            self._params("not json at all")

    def test_manifest_params_are_valid_json_on_stdout(self):
        proc = subprocess.run(
            [sys.executable, "-m", "source_analyst.manifest.cli", "params",
             "--class", "sqli", "--lang", "java", "--query", "reachable"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        params = json.loads(proc.stdout)          # bare object, pipe-ready
        self.assertIn("sinks", params)
        json.loads(proc.stderr.strip().splitlines()[-1])  # provenance on stderr


if __name__ == "__main__":
    unittest.main()
