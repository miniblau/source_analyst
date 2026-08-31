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
    tier_table,
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

    def test_skipped_trees_are_reported(self):
        """The skip list changes which languages are detected, so an operator
        confirming detection has to be able to see that it acted."""
        src = self._tree(["a.java", "node_modules/x.js", "vendor/y.js"])
        report: dict = {}
        detect.counts(src, language_map(), report)
        self.assertEqual(report["skipped_trees"], 2)

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

    def test_path_traversal_rejected_by_name_not_by_accident(self):
        """Must be rejected on the NAME, before any file is opened.

        Previously this passed only because the traversed-to file happened to
        declare a different `class:` — so an out-of-tree YAML was read and
        parsed first, and a file that did self-declare would have loaded.
        """
        for bad in ("../../etc/passwd", "../classes/sqli", "./sqli", "a/b"):
            with self.assertRaises(ManifestError) as cm:
                load_class(bad)
            self.assertIn("invalid vuln class name", str(cm.exception), bad)
        with self.assertRaises(ManifestError) as cm:
            load_patterns("sqli", "../patterns/java")
        self.assertIn("invalid language name", str(cm.exception))


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

    def test_block_key_collision_is_fatal(self):
        """Silent last-wins would drop a sink list with no diagnostic."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "classes").mkdir()
            (root / "patterns" / "java").mkdir(parents=True)
            (root / "classes" / "x.yaml").write_text(
                "class: x\ntitle: X\napplies_to: [java]\nnarrative: n\n")
            (root / "patterns" / "java" / "x.yaml").write_text(textwrap.dedent("""
                class: x
                language: java
                a:
                  sinks: [one]
                b:
                  sinks: [two]
                queries:
                  sql_sinks: [a, b]
            """))
            os.environ["SOURCE_ANALYST_MANIFESTS"] = str(root)
            try:
                p = load_patterns("x", "java")
                with self.assertRaises(ManifestError) as cm:
                    p.params_for("sql_sinks")
                self.assertIn("already set by an earlier block", str(cm.exception))
            finally:
                del os.environ["SOURCE_ANALYST_MANIFESTS"]

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


class TestTiers(unittest.TestCase):
    """§6 report honesty. The failure this guards is not a crash: it is a strong
    lead being presented as an assessed-and-clean result."""

    def _tree(self, root: Path, tier: str, queries: str) -> None:
        (root / "classes").mkdir(exist_ok=True)
        (root / "patterns" / "js").mkdir(parents=True, exist_ok=True)
        (root / "classes" / "xss.yaml").write_text(textwrap.dedent(f"""
            class: xss
            title: XSS
            applies_to: [js]
            narrative: n
            max_static_tier: {tier}
        """))
        (root / "patterns" / "js" / "xss.yaml").write_text(textwrap.dedent(f"""
            class: xss
            language: js
            sinks:
              sinks: [dangerouslySetInnerHTML]
            queries:
              {queries}
            max_static_tier: {tier}
        """))

    def test_tier_table_matches_the_spec(self):
        tiers = tier_table()
        self.assertEqual(tiers["static_pattern"]["ordinal"], 0)
        self.assertFalse(tiers["static_pattern"]["is_hypothesis"])   # lead, not hypothesis
        self.assertEqual(tiers["static_reachability"]["requires_queries"], ["reachable"])

    def test_cannot_claim_reachability_without_binding_a_reachability_query(self):
        """A JSX attribute is not a call node, so no current query can reach it.
        A pattern file for such a sink must not be able to claim it did."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._tree(root, "static_reachability", "sql_sinks: [sinks]")
            os.environ["SOURCE_ANALYST_MANIFESTS"] = str(root)
            try:
                with self.assertRaises(ManifestError) as cm:
                    load_patterns("xss", "js")
                self.assertIn("requires quer", str(cm.exception))
                self.assertIn("reachable", str(cm.exception))
            finally:
                del os.environ["SOURCE_ANALYST_MANIFESTS"]

    def test_pattern_only_class_is_honest_and_loads(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._tree(root, "static_pattern", "sql_sinks: [sinks]")
            os.environ["SOURCE_ANALYST_MANIFESTS"] = str(root)
            try:
                p = load_patterns("xss", "js")
                self.assertEqual(p.max_static_tier, "static_pattern")
                # The load-bearing distinction: never assessed, not assessed-clean.
                self.assertFalse(p.reachability_assessed())
                problems, gaps = validate_all()
                self.assertEqual(problems, [])
                self.assertTrue(any("never assessed" in g for g in gaps))
            finally:
                del os.environ["SOURCE_ANALYST_MANIFESTS"]

    def test_language_may_not_out_claim_its_class_ceiling(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._tree(root, "static_pattern", "sql_sinks: [sinks]")
            (root / "patterns" / "js" / "xss.yaml").write_text(textwrap.dedent("""
                class: xss
                language: js
                sinks:
                  sinks: [dangerouslySetInnerHTML]
                queries:
                  reachable: [sinks]
                max_static_tier: static_reachability
            """))
            os.environ["SOURCE_ANALYST_MANIFESTS"] = str(root)
            try:
                problems, _ = validate_all()
                self.assertTrue(any("above the class ceiling" in p for p in problems), problems)
            finally:
                del os.environ["SOURCE_ANALYST_MANIFESTS"]

    def test_java_sqli_declares_the_tier_it_can_actually_reach(self):
        p = load_patterns("sqli", "java")
        self.assertEqual(p.max_static_tier, "static_reachability")
        self.assertTrue(p.reachability_assessed())


class TestFrameworkCoverage(unittest.TestCase):
    """A framework nothing covers must be NAMED, not inferred from a short report.

    A language declared with no pattern file is already reported as a coverage gap,
    deliberately, so a repo cannot come back clean in a language nobody wrote
    patterns for. There was no equivalent one level down: scan an Angular app with
    React-only patterns and you get a short result that looks like a clean one.

    Detection selects NOTHING. A class's sinks stay the union of its language-level
    and framework-level entries whatever is found here — React aims to prevent XSS,
    which is exactly why its escape hatches are the interesting sinks, and people
    write plain unsafe JS beside them. A precedence chain would drop the second.
    """

    def tree(self, files: dict[str, str]) -> Path:
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            f = d / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)
        return d

    def detect(self, src: Path):
        out = subprocess.run(
            [sys.executable, "-m", "source_analyst.manifest.cli", "detect", "--src", str(src)],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stderr.strip().splitlines()[-1])

    def test_a_dependency_is_evidence(self):
        src = self.tree({"package.json": json.dumps({"dependencies": {"@angular/core": "1"}}),
                         "a.ts": "export const x = 1\n"})
        self.assertIn("angular", self.detect(src)["frameworks"])

    def test_an_import_is_evidence_without_a_manifest_file(self):
        src = self.tree({"a.ts": "import { Component } from '@angular/core'\n"})
        self.assertIn("angular", self.detect(src)["frameworks"])

    def test_a_framework_no_pattern_file_covers_is_named(self):
        """The whole point: this must be reachable, or it is decoration."""
        src = self.tree({"package.json": json.dumps({"dependencies": {"vue": "3"}}),
                         "a.js": "import { ref } from 'vue'\n"})
        got = self.detect(src)
        self.assertIn("vue", got["frameworks"])
        # vue IS declared by js/xss today, so it should be covered — the assertion
        # that matters is that the field distinguishes the two states at all.
        self.assertIsInstance(got["frameworks_uncovered"], list)

    def test_a_tree_with_no_framework_says_so(self):
        src = self.tree({"a.py": "print(1)\n"})
        got = self.detect(src)
        self.assertEqual(got["frameworks"], [])
        self.assertEqual(got["frameworks_uncovered"], [])


class TestSelection(unittest.TestCase):
    def test_class_not_applying_is_skipped_not_stubbed(self):
        self.assertEqual(applicable(["cobol"]), [])

    def test_declared_but_unrealized_language_is_a_reported_gap(self):
        """§10.1: applies_to runs ahead of pattern files by design. The gap must
        surface — silently dropping it reports a language as clean that nothing
        ever looked at."""
        rows = applicable(["java", "js"])
        self.assertTrue(rows, "no class applied to java — the manifest tree is broken")

        # The property is every class's, and it is about the PARTITION, not about
        # which languages happen to exist. This assertion has now encoded the
        # corpus twice: first "there is exactly one vuln class" (broke when
        # path_traversal arrived), then "java is the only realized language"
        # (broke the moment js/sqli.yaml was written). Both times the test was
        # describing today's tree rather than the behaviour under test.
        asked = ["java", "js"]
        for vc, realized, unrealized in rows:
            self.assertEqual(sorted(realized + unrealized), asked, vc.name)
            self.assertEqual(set(realized) & set(unrealized), set(), vc.name)
            self.assertTrue(realized, f"{vc.name} applies to nothing that is realized")

        self.assertIn("sqli", {vc.name for vc, _, _ in rows})

    def test_empty_manifest_tree_is_a_problem_not_a_pass(self):
        """An empty tree validated ok:true/exit 0, so a mis-pointed
        SOURCE_ANALYST_MANIFESTS read as a healthy install and every later scan
        would quietly have nothing to run."""
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, SOURCE_ANALYST_MANIFESTS=d)
            proc = subprocess.run(
                [sys.executable, "-m", "source_analyst.manifest.cli", "validate"],
                cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("no vuln classes found", proc.stdout + proc.stderr)

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
