"""Corpus as test oracle for `struct_grep` rule sets.

Same discipline as tests/test_corpus.py, opengrep side: golden fact JSONL with
`ts` stripped, two-sided fixtures (the planted sink lights up, the sanitized
control stays dark), and an explicit check that "no findings" is never
ambiguous.

    UPDATE_GOLDEN=1 python -m unittest tests.test_corpus_rules

Gated on opengrep, not Joern — this suite runs with no JVM and no LLM calls.
"""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "corpus" / "fixtures.json").read_text())
GOLDEN = ROOT / "corpus" / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
OPENGREP = os.environ.get("OPENGREP_BIN", "opengrep")


def run_scan(src: Path, rules: list[str], expect_rc: int = 0) -> tuple[list[dict], dict]:
    cmd = [sys.executable, "-m", "source_analyst.struct_grep.cli", "scan", "--src", str(src)]
    for r in rules:
        cmd += ["--rules", r]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    # rc 2 = the scan ran but is not trustworthy (nothing scanned, rules
    # skipped, parse errors). Callers that want that state ask for it.
    if proc.returncode != expect_rc:
        raise AssertionError(
            f"struct_grep scan rc={proc.returncode} (wanted {expect_rc}):\n{proc.stderr}")
    facts = [json.loads(line) for line in proc.stdout.splitlines()]
    meta = json.loads(proc.stderr.strip().splitlines()[-1])
    return facts, meta


def strip_ts(facts: list[dict]) -> list[dict]:
    return [{k: v for k, v in f.items() if k != "ts"} for f in facts]


def golden_name(ruleset: str) -> str:
    return ruleset.replace("/", "_")


@unittest.skipUnless(shutil.which(OPENGREP), "opengrep not installed")
class TestGoldenRules(unittest.TestCase):
    def _check(self, fixture: str):
        fx = FIXTURES[fixture]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest(f"fixture {fixture} not present at {fx['path']}")
        rules = fx["rules"]
        facts, meta = run_scan(src, rules)
        golden = GOLDEN / f"{golden_name(rules[0])}.{fixture}.jsonl"
        got = strip_ts(facts)
        if UPDATE:
            GOLDEN.mkdir(parents=True, exist_ok=True)
            golden.write_text("".join(json.dumps(f, separators=(",", ":")) + "\n" for f in got))
            self.skipTest(f"golden updated: {golden.name}")
        want = [json.loads(line) for line in golden.read_text().splitlines()]
        self.assertEqual(got, want, f"{rules} on {fixture} drifted from golden")
        return facts, meta

    def test_java_sqli_min_fixture(self):
        """Two-sided: the concatenation lights up, both controls stay dark."""
        facts, meta = self._check("java_sqli_min")
        dyn = [f for f in facts if f["rule"] == "java_sql_sink_dynamic"]
        inv = [f for f in facts if f["rule"] == "java_sql_sink"]

        # positive: exactly the planted concatenation
        self.assertEqual(len(dyn), 1, "exactly one runtime-built SQL sink is planted")
        self.assertEqual(dyn[0]["line"], 13)
        self.assertIn("+ name", dyn[0]["code"])

        # negative: the parameterized control is inventoried but never "dynamic"
        self.assertEqual({f["line"] for f in inv}, {13, 18, 20})
        self.assertNotIn(18, {f["line"] for f in dyn}, "literal SQL must not read as runtime-built")
        self.assertNotIn(20, {f["line"] for f in dyn}, "no-arg executeQuery has no SQL text")

        # provenance: every fact traces to the rule that produced it
        for f in facts:
            self.assertEqual(f["src"], f"opengrep:{f['rule']}")
            self.assertEqual(f["vuln_class"], "sqli")

    def test_webgoat(self):
        facts, meta = self._check("webgoat")
        files = {f["file"] for f in facts}
        for known in [
            "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java",
            "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
            "src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java",
        ]:
            self.assertIn(known, files, "known WebGoat SQLi site missing from sink candidates")
        self.assertGreater(meta["scan_meta"]["files_scanned"], 100)
        self.assertEqual(meta["scan_meta"]["parse_errors"], 0)

        # The 3-arg overload: an arity-1 pattern silently loses this real SQLi.
        dyn = {(f["file"], f["line"]) for f in facts if f["rule"] == "java_sql_sink_dynamic"}
        self.assertIn(
            ("src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/"
             "SqlInjectionLesson5b.java", 48), dyn,
            "prepareStatement(sql, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY) must be matched")

    def test_agrees_with_cpg_sink_inventory(self):
        """The two substrates must see the same sinks; only the verdict differs.

        Pattern search and the CPG disagree about which sinks carry runtime-built
        SQL (opengrep constant-folds, Joern does not), but a sink either exists
        or it does not. A divergence in the *inventory* means one of them is
        blind, and that is worth failing over.
        """
        joern_golden = GOLDEN / "sql_sinks.webgoat.jsonl"
        og_golden = GOLDEN / "java_sqli.webgoat.jsonl"
        if not (joern_golden.is_file() and og_golden.is_file()):
            self.skipTest("both goldens required")
        joern = {(f["file"], f["line"])
                 for f in map(json.loads, joern_golden.read_text().splitlines())}
        og = {(f["file"], f["line"])
              for f in map(json.loads, og_golden.read_text().splitlines())
              if f["rule"] == "java_sql_sink"}
        self.assertEqual(og, joern, "sink inventories diverged between opengrep and the CPG")

    def test_determinism(self):
        """Same input → byte-identical facts, and content-hash ids are stable."""
        src = ROOT / FIXTURES["java_sqli_min"]["path"]
        a, _ = run_scan(src, ["java/sqli"])
        b, _ = run_scan(src, ["java/sqli"])
        self.assertEqual(strip_ts(a), strip_ts(b))
        self.assertEqual([f["id"] for f in a], [f["id"] for f in b])
        self.assertEqual(len({f["id"] for f in a}), len(a), "ids must not collide")

    def test_empty_result_is_disambiguated(self):
        """No findings must be distinguishable from nothing having been parsed.

        Scanning a tree with no Java in it yields zero facts *and* zero files
        scanned — the tell that the run proves nothing. A real clean scan reports
        many files and zero parse errors. Reporting "no vuln" without reading
        these two numbers is the mistake this test exists to prevent.
        """
        # ...and the exit status says so too, so a caller that reads nothing
        # but the return code still cannot mistake this for a clean tree.
        facts, meta = run_scan(ROOT / "rules", ["java/sqli"], expect_rc=2)
        self.assertEqual(facts, [])
        self.assertEqual(meta["scan_meta"]["files_scanned"], 0,
                         "no Java in rules/ — nothing was analysed")
        self.assertFalse(meta["scan_meta"]["trustworthy"])

        src = ROOT / FIXTURES["java_sqli_min"]["path"]
        _, real = run_scan(src, ["java/sqli"])
        self.assertGreater(real["scan_meta"]["files_scanned"], 0)
        self.assertEqual(real["scan_meta"]["parse_errors"], 0)
        self.assertTrue(real["scan_meta"]["trustworthy"])

    def test_line_refs_point_at_real_source(self):
        """A file:line a reviewer cannot open is worse than no reference."""
        fx = FIXTURES["webgoat"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("webgoat fixture not present")
        facts, _ = run_scan(src, fx["rules"])
        for f in facts:
            path = src / f["file"]
            self.assertTrue(path.is_file(), f"{f['file']} does not exist")
            self.assertLessEqual(f["line"], len(path.read_text().splitlines()),
                                 f"{f['file']}:{f['line']} is past end of file")


@unittest.skipUnless(shutil.which(OPENGREP), "opengrep not installed")
class TestUntrustworthyScan(unittest.TestCase):
    """A scan that could not do its job must not exit 0.

    Verified failure this guards: one bad rule in a file aborts the whole
    opengrep run — files_scanned 0, parse_errors 1, zero facts — and the tool
    previously returned 0, so a caller checking exit status read it as a clean
    tree. Zero facts is only evidence of absence when the scan was sound.
    """

    @unittest.skipUnless(shutil.which(OPENGREP), "opengrep not installed")
    def test_broken_rule_file_does_not_exit_clean(self):
        broken = ROOT / "rules" / "java" / "zz_test_broken.yaml"
        broken.write_text(textwrap.dedent("""
            rules:
              - id: java_zz_ok
                languages: [java]
                severity: INFO
                message: ok
                metadata: {vuln_class: sqli, kind: sink_candidate}
                patterns:
                  - pattern: $R.executeQuery(...)
              - id: java_zz_bad
                languages: [notalanguage]
                severity: INFO
                message: bad
                metadata: {vuln_class: sqli, kind: sink_candidate}
                patterns:
                  - pattern: $R.foo(...)
        """).lstrip())
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "source_analyst.struct_grep.cli", "scan",
                 "--src", str(ROOT / "corpus" / "fixtures" / "java_sqli_min"),
                 "--rules", "java/zz_test_broken"],
                cwd=ROOT, capture_output=True, text=True, timeout=600)
        finally:
            broken.unlink(missing_ok=True)

        self.assertEqual(proc.stdout.strip(), "", "a failed scan must emit no facts")
        self.assertNotEqual(proc.returncode, 0,
                            "a scan that parsed nothing must not report success")
        meta = json.loads(
            [l for l in proc.stderr.splitlines() if l.startswith("{")][-1])
        self.assertFalse(meta["scan_meta"]["trustworthy"])
        self.assertIn("not trustworthy", proc.stderr)

    @unittest.skipUnless(shutil.which(OPENGREP), "opengrep not installed")
    def test_scanning_no_files_is_not_a_clean_result(self):
        """A Java rule set over a tree with no Java is zero facts for a reason
        that has nothing to do with the code being safe."""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "notes.md").write_text("no source here\n")
            proc = subprocess.run(
                [sys.executable, "-m", "source_analyst.struct_grep.cli", "scan",
                 "--src", d, "--rules", "java/sqli"],
                cwd=ROOT, capture_output=True, text=True, timeout=600)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no files were scanned", proc.stderr)


class TestPipelineRunsBothSubstrates(unittest.TestCase):
    """A rule set nothing invokes is a rule set that does not exist.

    Four of five pattern files declared `rules:` and `night.sh`'s facts stage ran
    only the four CPG queries, so across BOTH directories of the first full run
    there were zero opengrep facts in any class. Every report was CPG-only while
    the manifests claimed two substrates, and the leads section — sinks no query
    can reach — never had a fact to render. Its absence read as "there were none".
    """

    def test_night_facts_stage_invokes_declared_rule_sets(self):
        night = (ROOT / "tools" / "night.sh").read_text()
        self.assertIn("struct_grep scan", night,
                      "the facts stage does not run the pattern substrate at all, so "
                      "every `rules:` declaration in every manifest is inert")
        # And it must be driven by what the manifest declares, not a fixed list —
        # a hardcoded rule set would go stale the moment a class added one.
        self.assertIn("manifest show", night)

    def test_every_declared_rule_set_exists(self):
        """A `rules:` entry naming a file that is not there fails only at run time."""
        from source_analyst.manifest.loader import available_classes, load_patterns
        from source_analyst.struct_grep import rules as rulemod
        have = set(rulemod.available())
        for vc in available_classes():
            for lang in ("java", "js"):
                try:
                    pats = load_patterns(vc, lang)
                except Exception:
                    continue
                for rs in pats.rules:
                    self.assertIn(rs, have,
                                  f"{lang}/{vc} declares rule set {rs!r}, which does not exist")


class TestVocabulary(unittest.TestCase):
    def test_rule_sets_are_listed(self):
        from source_analyst.struct_grep import rules
        self.assertIn("java/sqli", rules.available())

    def test_unknown_rule_set_rejected(self):
        from source_analyst.struct_grep import rules
        with self.assertRaises(SystemExit):
            rules.resolve("java/nope")

    def test_path_traversal_rejected(self):
        from source_analyst.struct_grep import rules
        for bad in ["../etc/passwd", "java/../../x", "/abs/path", "java", "java/sqli/extra"]:
            with self.assertRaises(SystemExit, msg=f"{bad!r} should be rejected"):
                rules.resolve(bad)


if __name__ == "__main__":
    unittest.main()
