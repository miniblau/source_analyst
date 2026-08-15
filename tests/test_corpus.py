"""Corpus as test oracle: every query is proven against ground truth.

Golden files hold fact records with `ts` stripped (ids are content hashes and
do not depend on time), so a re-run must reproduce them byte-for-byte. A query
change that moves golden output is reviewed, not rubber-stamped:

    UPDATE_GOLDEN=1 python -m unittest tests.test_corpus

Fixtures whose source tree is absent (WebGoat is cloned, not vendored) skip.
Requires Joern; there are no LLM calls anywhere in here.
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


def run_query(src: Path, query: str, params: dict, lang: str) -> tuple[list[dict], dict]:
    cmd = [sys.executable, "-m", "source_analyst.cpg.cli", "query",
           "--src", str(src), "--query", query, "--lang", lang]
    for k, v in params.items():
        cmd += ["--param-json", f"{k}={json.dumps(v)}"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        raise AssertionError(f"cpg query failed:\n{proc.stderr}")
    facts = [json.loads(line) for line in proc.stdout.splitlines()]
    meta = json.loads(proc.stderr.strip().splitlines()[-1])
    return facts, meta


def strip_ts(facts: list[dict]) -> list[dict]:
    return [{k: v for k, v in f.items() if k != "ts"} for f in facts]


@unittest.skipUnless(shutil.which(os.environ.get("JOERN_BIN", "joern")), "joern not installed")
class TestGolden(unittest.TestCase):
    def _check(self, name: str, query: str):
        fx = FIXTURES[name]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest(f"fixture {name} not present at {fx['path']}")
        facts, meta = run_query(src, query, fx["queries"][query]["params"], fx["lang"])
        golden = GOLDEN / f"{query}.{name}.jsonl"
        got = strip_ts(facts)
        if UPDATE:
            GOLDEN.mkdir(parents=True, exist_ok=True)
            golden.write_text("".join(json.dumps(f, separators=(",", ":")) + "\n" for f in got))
            self.skipTest(f"golden updated: {golden.name}")
        want = [json.loads(line) for line in golden.read_text().splitlines()]
        self.assertEqual(got, want, f"{query} on {name} drifted from golden")
        return facts, meta

    def test_sql_sinks_min_fixture(self):
        facts, meta = self._check("java_sqli_min", "sql_sinks")
        by_method = {f["subject"].split(":")[0].split(".")[-1]: f for f in facts}

        # positive: the planted concatenation is a sink with a non-literal argument
        pos = by_method["concatenated"]
        self.assertEqual(pos["name"], "executeQuery")
        self.assertTrue(pos["arg_present"])
        self.assertFalse(pos["arg_is_literal"])
        self.assertTrue(pos["resolved"])

        # negative: the parameterized control carries no runtime-built SQL
        params = [f for f in facts if "parameterized" in f["subject"]]
        self.assertTrue(params, "parameterized sink calls should still be reported as candidates")
        for f in params:
            self.assertFalse(f["arg_present"] and not f["arg_is_literal"],
                             f"{f['code']} must not look like runtime-built SQL")

        # negative: a method with no SQL contributes nothing
        self.assertNotIn("greet", by_method)

    def test_sql_sinks_webgoat(self):
        facts, meta = self._check("webgoat", "sql_sinks")
        files = {f["file"] for f in facts}
        for known in [
            "src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java",
            "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
            "src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java",
        ]:
            self.assertIn(known, files, "known WebGoat SQLi site missing from sink candidates")
        self.assertGreater(meta["query_meta"]["cpg_calls"], 1000)

    def test_line_refs_point_at_real_source(self):
        """A file:line a reviewer cannot open is worse than no reference."""
        fx = FIXTURES["webgoat"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("webgoat fixture not present")
        facts, _ = run_query(src, "sql_sinks", fx["queries"]["sql_sinks"]["params"], fx["lang"])
        for f in facts:
            path = src / f["file"]
            self.assertTrue(path.is_file(), f"{f['file']} does not exist")
            self.assertLessEqual(f["line"], len(path.read_text().splitlines()),
                                 f"{f['file']}:{f['line']} is past end of file")

    def test_empty_result_is_disambiguated(self):
        """No match must be distinguishable from a CPG that built nothing."""
        fx = FIXTURES["java_sqli_min"]
        src = ROOT / fx["path"]
        facts, meta = run_query(src, "sql_sinks", {"sinks": ["sqlite3_exec"]}, fx["lang"])
        self.assertEqual(facts, [])
        self.assertEqual(meta["query_meta"]["matched"], 0)
        self.assertGreater(meta["query_meta"]["cpg_calls"], 0)
        self.assertGreater(meta["query_meta"]["cpg_methods"], 0)


if __name__ == "__main__":
    unittest.main()
