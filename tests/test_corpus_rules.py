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
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "corpus" / "fixtures.json").read_text())
GOLDEN = ROOT / "corpus" / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
OPENGREP = os.environ.get("OPENGREP_BIN", "opengrep")


def run_scan(src: Path, rules: list[str]) -> tuple[list[dict], dict]:
    cmd = [sys.executable, "-m", "source_analyst.struct_grep.cli", "scan", "--src", str(src)]
    for r in rules:
        cmd += ["--rules", r]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        raise AssertionError(f"struct_grep scan failed:\n{proc.stderr}")
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
        facts, meta = run_scan(ROOT / "rules", ["java/sqli"])
        self.assertEqual(facts, [])
        self.assertEqual(meta["scan_meta"]["files_scanned"], 0,
                         "no Java in rules/ — nothing was analysed")

        src = ROOT / FIXTURES["java_sqli_min"]["path"]
        _, real = run_scan(src, ["java/sqli"])
        self.assertGreater(real["scan_meta"]["files_scanned"], 0)
        self.assertEqual(real["scan_meta"]["parse_errors"], 0)

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
