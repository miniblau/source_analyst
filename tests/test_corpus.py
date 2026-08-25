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

    # ------------------------------------------------------------ request_sources

    def test_request_sources_webgoat(self):
        facts, meta = self._check("webgoat", "request_sources")
        qm = meta["query_meta"]
        self.assertGreater(qm["matched_annotation"], 100)
        self.assertIn("RequestParam", qm["annotation_names_in_cpg"])
        # An annotated controller parameter is an entry point: the framework
        # calls it, so zero CPG callers is expected and must not be read as dead.
        annotated = [f for f in facts if f["origin"] == "annotation"]
        self.assertTrue(any(f["callers"] == 0 for f in annotated))

    def test_request_sources_absent_is_not_a_frontend_gap(self):
        """No annotated sources must be distinguishable from annotations unparsed."""
        facts, meta = self._check("java_sqli_min", "request_sources")
        qm = meta["query_meta"]
        self.assertEqual(facts, [])
        self.assertEqual(qm["matched_annotation"], 0)
        # The claim "this tree has no request sources" is only honest because the
        # CPG parsed parameters at all and simply found none annotated.
        self.assertGreater(qm["cpg_parameters"], 0)
        self.assertEqual(qm["cpg_annotated_params"], 0)
        # The field must be CPG-wide, so it still answers "did the frontend
        # resolve ANY annotation" when nothing matched. Derived from the
        # matched set it was always [] here and disambiguated nothing.
        self.assertEqual(qm["annotation_names_in_cpg"], [])

    # ------------------------------------------------------------------ reachable

    def test_reachable_two_sided_fixture(self):
        """The discriminating test: identical sink names on both sides."""
        facts, meta = self._check("java_sqli_flow", "reachable")
        qm = meta["query_meta"]
        self.assertTrue(qm["dataflow_overlay"], "no dataflow overlay — emptiness would be a lie")

        # positives: the raw concatenation and the escaped one. The escaped path
        # is a flow too — passing through a candidate sanitizer does not remove
        # it, it only adds a sanitizer_on_path fact about it.
        self.assertEqual({f["source_name"] for f in facts}, {"name", "term"},
                         [f["sink_code"] for f in facts])
        for flow in facts:
            self.assertEqual(flow["kind"], "flow")
            self.assertEqual(flow["source_marker"], "RequestParam")
            self.assertEqual(flow["sink_name"], "executeQuery")
            self.assertGreater(flow["crosses_methods"], 1, "should cross a method boundary")
            self.assertTrue(flow["steps"])

        # negatives: both sides really were in scope — the sinks and sources of
        # the bound/constant/sink-less cases exist, they simply do not connect.
        self.assertGreater(qm["source_nodes"], 2)
        self.assertGreater(qm["sink_arg_nodes"], 1)
        self.assertEqual(qm["pairs"], 2)

        # the bound-parameter, constant-only and sink-less controls stay dark
        subjects = " ".join(f["subject"] for f in facts)
        for control in ("bound", "constantOnly", "echo"):
            self.assertNotIn(control, subjects)

    def test_reachable_webgoat_known_lessons(self):
        facts, meta = self._check("webgoat", "reachable")
        by_file = {f["sink_file"].split("/")[-1] for f in facts}
        for known in ["SqlInjectionLesson5a.java", "SqlInjectionLesson8.java",
                      "SqlInjectionChallenge.java", "Servers.java"]:
            self.assertIn(known, by_file, f"known WebGoat SQLi flow missing: {known}")
        # inter-procedural reach is the whole point; a single-hop-only result
        # means the call graph is not being traversed.
        self.assertTrue(any(f["crosses_methods"] >= 3 for f in facts))
        self.assertTrue(meta["query_meta"]["dataflow_overlay"])

    def test_reachable_is_narrower_than_sink_inventory(self):
        """Reachability must actually prune, or it is adding no evidence."""
        fx = FIXTURES["webgoat"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("webgoat fixture not present")
        sinks, _ = run_query(src, "sql_sinks", fx["queries"]["sql_sinks"]["params"], fx["lang"])
        flows, _ = run_query(src, "reachable", fx["queries"]["reachable"]["params"], fx["lang"])
        reached = {(f["sink_file"], f["sink_line"]) for f in flows}
        inventory = {(f["file"], f["line"]) for f in sinks}
        self.assertLess(len(reached), len(inventory))
        self.assertTrue(reached <= inventory,
                        f"reachable reported sites absent from the inventory: {reached - inventory}")

    # ---------------------------------------------------------- sanitizer_on_path

    def test_sanitizer_on_path_two_sided_fixture(self):
        facts, meta = self._check("java_sqli_flow", "sanitizer_on_path")
        by_source = {f["source_name"]: f for f in facts}

        # the raw tainted path has no candidate sanitizer on it
        self.assertEqual(by_source["name"]["candidate_count"], 0)
        self.assertEqual(by_source["name"]["reported_paths_without_sanitizer"],
                         by_source["name"]["reported_paths"])

        # the escaped path is still reported as a flow, with the escape call named
        esc = by_source["term"]
        self.assertGreater(esc["candidate_count"], 0)
        names = {c["name"] for c in esc["candidate_sanitizers"]}
        self.assertTrue({"escape", "replace"} & names, names)
        for c in esc["candidate_sanitizers"]:
            self.assertGreaterEqual(c["line"], 1)

        # no field in the payload may express a safety verdict
        self.assertNotIn("sanitized", esc)
        self.assertNotIn("safe", esc)

    def test_sanitizer_facts_join_with_reachable(self):
        """Both queries must agree on the (source, sink) pairs they describe."""
        fx = FIXTURES["webgoat"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("webgoat fixture not present")
        flows, _ = run_query(src, "reachable", fx["queries"]["reachable"]["params"], fx["lang"])
        checks, _ = run_query(src, "sanitizer_on_path",
                              fx["queries"]["sanitizer_on_path"]["params"], fx["lang"])
        key = lambda f: (f["sink_file"], f["sink_line"], f["source_file"],
                         f["source_line"], f["source_name"])
        self.assertEqual({key(f) for f in flows}, {key(f) for f in checks})

    def test_sanitizer_counts_never_claim_route_coverage(self):
        """Guards the known unsoundness: the engine enumerates representative
        paths, so 'no clean path reported' is not 'every route is sanitized'.

        WebGoat SqlInjectionLesson8:62 is the standing case — a clean route
        (61->62) exists in the source but is never enumerated. If a field ever
        starts asserting route coverage, this test is where it gets caught.
        """
        facts, meta = self._check("webgoat", "sanitizer_on_path")
        self.assertTrue(meta["query_meta"]["paths_are_representative"])
        for f in facts:
            for field in f:
                self.assertFalse(
                    field.startswith("unsanitized") or field in ("sanitized", "safe", "exploitable"),
                    f"{field} asserts route coverage the engine cannot support")
            # counts are scoped to reported paths, and stay internally consistent
            self.assertEqual(
                f["reported_paths_with_sanitizer"] + f["reported_paths_without_sanitizer"],
                f["reported_paths"])

        l8 = [f for f in facts
              if f["sink_file"].endswith("SqlInjectionLesson8.java") and f["sink_line"] == 62]
        self.assertTrue(l8, "expected the Lesson8 detour pair in the corpus")
        for f in l8:
            self.assertGreater(f["candidate_count"], 0, "the replace() detour should be reported")

    # ------------------------------------------------------------- callee_body

    def test_callee_body_two_sided_fixture(self):
        """Two-sided on the SAME code path: every name below is looked up the same
        way, so only what the CPG actually holds separates the answers. A query that
        replied from the name string would pass the in-tree case and fail the rest."""
        facts, meta = self._check("java_sqli_flow", "callee_body")
        by_name = {f["full_name"]: f for f in facts}
        qm = meta["query_meta"]

        # One row per request, in the order asked — a name that matched nothing is
        # stated, never omitted.
        self.assertEqual(len(facts), qm["requested"])
        self.assertEqual([f["full_name"] for f in facts],
                         FIXTURES["java_sqli_flow"]["queries"]["callee_body"]["params"]["methods"])

        # POSITIVE: in-tree, and the body is the real text off disk, not the signature.
        esc = by_name["demo.FlowController.escape:java.lang.String(java.lang.String)"]
        self.assertEqual(esc["status"], "resolved")
        self.assertIn("s.replace(", esc["body"])
        self.assertIn("replace", [c["name"] for c in esc["calls"]])
        self.assertFalse(esc["is_external"])

        # POSITIVE: a callee that contains the sink — proves the body is the callee's
        # own code and not the caller's.
        rq = by_name["demo.FlowController.runQuery:java.sql.ResultSet(java.lang.String)"]
        self.assertEqual(rq["status"], "resolved")
        self.assertIn("executeQuery", rq["body"])
        self.assertIn("executeQuery", [c["name"] for c in rq["calls"]])

        # NEGATIVE: a library method. The node EXISTS, so "not found" would be wrong;
        # the body is absent, so "resolved" would be a lie. Neither may collapse into
        # the other — a caller that reads this as "nothing there" has re-created the
        # naming bug this query was written to fix.
        ext = by_name[
            "java.sql.Connection.prepareStatement:java.sql.PreparedStatement(java.lang.String)"]
        self.assertEqual(ext["status"], "external_stub")
        self.assertEqual(ext["body"], "")
        self.assertTrue(ext["is_external"])

        # NEGATIVE: no such method anywhere.
        self.assertEqual(by_name["demo.FlowController.noSuchMethod:void()"]["status"],
                         "not_in_cpg")

        self.assertEqual((qm["resolved"], qm["external_stub"], qm["not_in_cpg"]), (2, 1, 1))
        self.assertEqual(qm["source_unavailable"], 0)
        self.assertTrue(qm["source_root_readable"])

    def test_callee_body_line_range_matches_the_file_on_disk(self):
        """The body is read off disk by line range, so an off-by-one would hand the
        agent a neighbouring method and read as fact. Check it against the source."""
        fx = FIXTURES["java_sqli_flow"]
        src = ROOT / fx["path"]
        facts, _ = run_query(src, "callee_body", fx["queries"]["callee_body"]["params"],
                             fx["lang"])
        for f in facts:
            if f["status"] != "resolved":
                continue
            on_disk = (src / f["file"]).read_text().splitlines()
            want = on_disk[f["line_start"] - 1:f["line_end"]]
            self.assertEqual(f["body"].splitlines(), want,
                             f"{f['name']}: emitted body is not the file's own lines")
            self.assertIn(f["name"], want[0])

    def test_callee_body_webgoat_reads_the_method_a_report_refuted_by_name(self):
        """The case that motivated the query: three exclusions in the first WebGoat
        report rested on the callee's package looking unrelated to databases. The
        body settles it from code — file IO, no database call anywhere."""
        fx = FIXTURES["webgoat"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("webgoat fixture not present")
        facts, meta = run_query(src, "callee_body", fx["queries"]["callee_body"]["params"],
                                fx["lang"])
        upload = facts[0]
        self.assertEqual(upload["status"], "resolved")
        self.assertTrue(upload["file"].endswith("ProfileUploadBase.java"))
        names = {c["name"] for c in upload["calls"]}
        self.assertIn("createNewFile", names)
        self.assertFalse(names & {"executeQuery", "executeUpdate", "prepareStatement",
                                  "createQuery", "createNativeQuery"},
                         "no database call is reachable in this body — that is the refutation")
        # The tainted parameter's type, argued from the signature rather than the name.
        types = {p["type"] for p in upload["parameters"]}
        self.assertIn("org.springframework.web.multipart.MultipartFile", types)
        self.assertTrue(all(p["type_resolved"] for p in upload["parameters"]))
        self.assertEqual(meta["query_meta"]["external_stub"], 1)

    def test_callee_body_requires_its_param(self):
        """A callee_body with no methods asked for scanned nothing, and a tool that
        scanned nothing must not exit 0 (CLAUDE.md)."""
        fx = FIXTURES["java_sqli_min"]
        with self.assertRaises(AssertionError):
            run_query(ROOT / fx["path"], "callee_body", {}, fx["lang"])

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
