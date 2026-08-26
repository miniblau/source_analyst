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

from source_analyst import records

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
def manifest_params(vuln_class: str, lang: str, query: str) -> dict:
    """Params from the LIVE manifest, not the snapshot in fixtures.json.

    fixtures.json stores a copy taken when a fixture was registered, so a manifest
    change is invisible to the golden tests until someone resyncs it — which is how
    a widening of path_traversal went entirely untested. Coverage assertions must
    read what the manifest says today.
    """
    out = subprocess.run(
        [sys.executable, "-m", "source_analyst.manifest.cli", "params",
         "--class", vuln_class, "--lang", lang, "--query", query],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


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

    def test_reachable_path_traversal_two_sided_fixture(self):
        """Class #2, and the test that it needed no new query.

        The whole point of path_traversal as a second class is that the same
        generic queries serve a sink shape nothing like SQLi's: the tainted value
        is the RECEIVER (`f.createNewFile()`), not an argument. If this passes,
        invariant #3's "new class = new data, zero code change" is a measured
        fact rather than a claim, which one class alone could never establish.
        """
        facts, meta = self._check("java_path_traversal_flow", "reachable")
        qm = meta["query_meta"]
        self.assertTrue(qm["dataflow_overlay"], "no dataflow overlay — emptiness would be a lie")

        # Both positives take their filename from the same request parameter and
        # land on the same sink line; only the sanitizer on one of them differs.
        self.assertEqual({f["source_name"] for f in facts}, {"name"},
                         [f["sink_code"] for f in facts])
        self.assertEqual({f["source_line"] for f in facts}, {28, 44})
        for flow in facts:
            self.assertEqual(flow["kind"], "flow")
            self.assertEqual(flow["source_marker"], "RequestParam")
            self.assertTrue(flow["steps"])

        # THE shape assertion, and it is about BREADTH. This test used to require
        # every flow to be `createNewFile` at argument 0, which was the assertion
        # encoding the same corpus-shaped assumption the class had: one sink shape,
        # the receiver, because that is what WebGoat's lesson uses. A class pinned
        # that way cannot see `new File(dir, name)` or any static path API, and
        # nothing failed to say so. Both shapes must now appear.
        shapes = {(f["sink_name"], f["sink_arg_index"]) for f in facts}
        self.assertIn(("createNewFile", 0), shapes,
                      "receiver-tainted file operation went missing")
        self.assertIn(("<init>", 2), shapes,
                      "taint into the second constructor argument went missing — "
                      "this is the `new File(dir, name)` shape")

        # negatives were in scope and simply did not connect
        self.assertGreater(qm["source_nodes"], 2)
        self.assertGreaterEqual(qm["sink_arg_nodes"], 1)
        self.assertGreaterEqual(qm["pairs"], 2)

        # the literal-filename and sink-less controls stay dark
        subjects = " ".join(f["subject"] for f in facts)
        for control in ("uploadFixed", "echo"):
            self.assertNotIn(control, subjects)

    def test_sanitizer_on_path_path_traversal_fixture(self):
        """Same sink, same line, same parameter name — only the strip() differs."""
        facts, _ = self._check("java_path_traversal_flow", "sanitizer_on_path")
        by_line = {f["source_line"]: f for f in facts}

        # the raw upload has no candidate sanitizer on it
        self.assertEqual(by_line[28]["candidate_count"], 0)
        self.assertEqual(by_line[28]["reported_paths_without_sanitizer"],
                         by_line[28]["reported_paths"])

        # the stripped upload is still a flow, with the strip call named. It is
        # also still exploitable — replace("../", "") leaves "....//" — which is
        # exactly why this query reports the candidate and decides nothing.
        stripped = by_line[44]
        self.assertGreater(stripped["candidate_count"], 0)
        self.assertIn("replace", {c["name"] for c in stripped["candidate_sanitizers"]})

        # no field in the payload may express a safety verdict
        self.assertNotIn("sanitized", stripped)
        self.assertNotIn("safe", stripped)

    def test_reachable_open_redirect_two_sided_fixture(self):
        """The two-sided case where BOTH sides are a flow.

        sqli and path_traversal both separate their sides by whether a flow exists
        at all. Here both sides flow to the same sink from the same annotation, and
        the query is right to report both — the difference is what the value became
        on the way. That makes this the fixture that proves `reachable` is not
        deciding anything: a query that tried to be clever and suppress the safe one
        would fail here, and so would a scorer that assumed every flow is a bug.
        """
        facts, meta = self._check("java_open_redirect_flow", "reachable")
        self.assertTrue(meta["query_meta"]["dataflow_overlay"])
        by_source = {f["source_name"]: f for f in facts}
        self.assertEqual(set(by_source), {"url", "destId"})

        # Both really are flows into the same sink construction.
        for f in facts:
            self.assertEqual(f["kind"], "flow")
            self.assertEqual(f["source_marker"], "RequestParam")
            self.assertIn("redirect:", f["sink_arg_code"])

        # The discriminator is the SOURCE, not the sink argument: sink_arg_type is
        # the concatenation result and is String on both sides, so a reasoner that
        # stops there learns nothing. Assert that explicitly — if a future change
        # made the sink argument discriminating, the ground-truth `why` for
        # OpenRedirectSecureController would be describing evidence that no longer
        # exists, and this test is where that gets noticed.
        self.assertEqual(by_source["url"]["sink_arg_type"],
                         by_source["destId"]["sink_arg_type"])
        self.assertIn("Integer", by_source["destId"]["source_code"])
        self.assertIn("String", by_source["url"]["source_code"])

        # The safe path is longer because the lookup stands in it.
        self.assertGreater(by_source["destId"]["path_length"],
                           by_source["url"]["path_length"])
        steps = " ".join(str(s.get("code", "")) for s in by_source["destId"]["steps"])
        self.assertIn("getOrDefault", steps)

        # the literal view name is not a flow at all
        self.assertNotIn("home", " ".join(f["subject"] for f in facts))

    def test_ordinary_idioms_no_corpus_exercises(self):
        """The guard against a class being shaped by the one app we validate on.

        WebGoat is small, deliberately vulnerable and idiosyncratic. A class fitted
        to it can score 1.0 on precision and recall and still be blind to the forms
        most client code actually uses — measured, not feared: with path_traversal
        pinned to the receiver (WebGoat's shape) this fixture's
        `Files.readAllBytes` produced ZERO flows while every WebGoat metric read
        1.0. Worse, the same narrowness hid ProfileZipSlip, a path-traversal lesson
        in WebGoat ITSELF, and ground truth could not show it because ground truth
        is scoped to what the substrate already found.

        So each class must find its idiom here. Adding a sink name is cheap;
        proving the name matches something is what this test is for.
        """
        fx = FIXTURES["java_typical_idioms"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("typical-idioms fixture not present")

        # Keyed on (sink, ARGUMENT POSITION), not the sink name alone. Name-only was
        # not a guard: `Files.readAllBytes` also yields a flow at argument 0, whose
        # `sink_arg_code` is the bare class reference `Files`, so re-pinning the class
        # to the receiver still "reached readAllBytes" and the test passed while the
        # real coverage was gone. The position is the thing that was blind.
        wanted = {
            "sqli": {("queryForList", 1), ("createQuery", 1)},   # JdbcTemplate, JPA
            "path_traversal": {("readAllBytes", 1)},             # static NIO path arg
            "open_redirect": {("sendRedirect", 1)},              # the servlet form
        }
        for vuln_class, expect in wanted.items():
            params = manifest_params(vuln_class, "java", "reachable")
            facts, meta = run_query(src, "reachable", params, fx["lang"])
            self.assertTrue(meta["query_meta"]["dataflow_overlay"])
            got = {(f["sink_name"], f["sink_arg_index"]) for f in facts}
            self.assertTrue(
                expect <= got,
                f"{vuln_class} lost coverage of {sorted(expect - got)} — a shape no "
                f"WebGoat run exercises. Reached: {sorted(got)}")

    def test_false_positive_rate_on_safe_code(self):
        """The number WebGoat cannot give us.

        WebGoat is ~all-vulnerable, so precision there is measured against almost
        nothing to reject, and the rate at which these classes fire on ordinary safe
        code was simply never measured. This fixture is safe BY CONSTRUCTION — bound
        parameters, an allowlist lookup, fixed paths — never safe by sanitizer, since
        a sanitizer on the path is still a flow and `reachable` is right to report it.

        The expectations below are a MEASUREMENT, pinned so it cannot quietly get
        worse. They are deliberately not all zero: `execute` is an unfiltered short
        name in the sqli list and it fires on a task runner here, which is the cost
        of portable-first matching stated as a number instead of a caveat.
        """
        fx = FIXTURES["java_clean_controls"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("clean-controls fixture not present")

        expected = {
            # class            (n flows, why)
            "sqli": (1, "TaskRunner.execute — an unfiltered short name colliding on "
                        "ordinary code, the same shape as WebGoat's ProfileUpload"),
            "path_traversal": (0, "the java.nio.file filter rejects Buffers.copy"),
            "open_redirect": (1, "the allowlist redirect: a real flow that is not a "
                                 "bug, which is a labelled negative and not a "
                                 "substrate false positive"),
        }
        for vuln_class, (want, why) in expected.items():
            params = manifest_params(vuln_class, "java", "reachable")
            facts, _ = run_query(src, "reachable", params, fx["lang"])
            got = [(f["sink_name"], f["sink_arg_code"]) for f in facts]
            self.assertEqual(
                len(facts), want,
                f"{vuln_class} fires {len(facts)} time(s) on safe-by-construction "
                f"code, expected {want} ({why}). Reported: {got}")

        # And the three that must never fire, by name, so a regression is legible.
        for vuln_class in expected:
            params = manifest_params(vuln_class, "java", "reachable")
            facts, _ = run_query(src, "reachable", params, fx["lang"])
            subjects = " ".join(f["subject"] for f in facts)
            for safe in ("boundParameter", "fixedPath"):
                self.assertNotIn(safe, subjects,
                                 f"{vuln_class} fired on {safe}, which is safe by "
                                 "construction — the value never becomes the "
                                 "dangerous part")

    def test_a_second_language_reaches_its_sink(self):
        """Everything before this ran on Java, and only Java.

        Five fixtures, one real app, one `manifests/patterns/` directory — so every
        claim about the design being language-agnostic was a claim about code nobody
        had run twice. This is the second language, and it found the one place the
        design was genuinely Java-shaped: both source origins (`annotations`, and
        named `calls`) describe how JAVA delivers request input. Express delivers it
        as a property read off the request object, which is neither, so no manifest
        could ask for it until `member_reads` existed. Sinks needed nothing.
        """
        fx = FIXTURES["js_sqli_flow"]
        src = ROOT / fx["path"]
        if not src.is_dir():
            self.skipTest("js fixture not present")
        facts, meta = run_query(src, "reachable",
                                manifest_params("sqli", "js", "reachable"), fx["lang"])
        self.assertTrue(meta["query_meta"]["dataflow_overlay"],
                        "no dataflow overlay on the JS CPG — emptiness would be a lie")

        # positives: the direct concatenation and the one through a helper
        self.assertEqual(len(facts), 2, [f["sink_arg_code"] for f in facts])
        self.assertEqual({f["source_code"] for f in facts}, {"req.query.name"})
        self.assertTrue(any(f["crosses_methods"] > 1 for f in facts),
                        "the helper route should cross a method boundary")

        # negatives from the SAME sink name: bound placeholder, and constant-only.
        subjects = " ".join(f["subject"] for f in facts)
        for control in ("/safe", "/all"):
            self.assertNotIn(control, subjects)

    def test_a_lead_is_not_a_clean_result(self):
        """`render` must distinguish "nothing looked" from "we looked, found nothing".

        tiers.yaml names this as the distinction that matters most, and Juice Shop
        makes it concrete: the CPG holds 147 files, exactly the .ts count, so all 80
        Angular templates are absent and every `[innerHTML]` binding is unreachable
        by every query. Reporting only what the queries reached would describe code
        no query ever read.

        A lead is DECLARED by the rule (`cpg_visible: false`), never inferred from
        "no flow at this line" — inferring it would turn a sink a query examined and
        cleared into a lead, which is the same conflation upside down.
        """
        from source_analyst.lifecycle.render import leads

        visible = records.fact(
            {"kind": "sink_candidate", "vuln_class": "xss", "file": "a.ts", "line": 5,
             "code": "el.innerHTML = x", "rule": "js_xss_dom_sink",
             "rule_meta": {"cpg_visible": True}}, "opengrep:js_xss_dom_sink")
        blind = records.fact(
            {"kind": "sink_candidate", "vuln_class": "xss", "file": "a.html", "line": 9,
             "code": '<div [innerHTML]="v">', "rule": "js_xss_template_binding",
             "rule_meta": {"cpg_visible": False}}, "opengrep:js_xss_template_binding")
        other = records.fact(
            {"kind": "sink_candidate", "vuln_class": "sqli", "file": "b.html", "line": 1,
             "code": "x", "rule": "r", "rule_meta": {"cpg_visible": False}}, "opengrep:r")

        got = leads([visible, blind, other], "xss")
        self.assertEqual([f["file"] for f in got], ["a.html"],
                         "only a sink the CPG cannot see is a lead, and only for "
                         "the class being rendered")

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
