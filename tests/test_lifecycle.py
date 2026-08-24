"""Phase 1 deterministic halves: brief (context in) and admit (judgement out).

The agent sits between them and is not exercised here — that is the seam. These
tests run with zero model calls, as the contract requires.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

import yaml
from pathlib import Path

from source_analyst import records
from source_analyst.belief import store
from source_analyst.lifecycle import admit as admit_mod

ROOT = Path(__file__).resolve().parents[1]


def flow_fact(**kw):
    payload = {"kind": "flow", "subject": "p.C.h:R(java.lang.String)", "object": "p.C.q:R(S)",
               "source_name": "q", "source_marker": "RequestParam", "source_origin": "annotation",
               "source_code": "@RequestParam String q", "source_file": "A.java", "source_line": 10,
               "sink_name": "executeQuery", "sink_full_name": "java.sql.Statement.executeQuery:R(S)",
               "sink_code": "st.executeQuery(sql)", "sink_arg_code": "sql",
               "sink_file": "A.java", "sink_line": 20, "path_length": 3, "crosses_methods": 2,
               "path_count": 1, "steps": [{"line": 10, "code": "q"}]}
    payload.update(kw)
    return records.fact(payload, "cpg:reachable")


class TestAdmitGate(unittest.TestCase):
    """Invariant #1 enforced at the door: an agent may not assert ground truth."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        self.fact = flow_fact()
        store.append([self.fact], self.log)
        self.addCleanup(self.tmp.cleanup)

    def run_admit(self, obj, kind="hypothesis", extra=()):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.admit", "--type", kind,
             "--class", "sqli", "--lang", "java", "--src", "agent:test", *extra],
            cwd=ROOT, env=self.env, input=json.dumps(obj), capture_output=True, text=True)

    def hyp(self, **kw):
        base = {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
                "confidence": 0.7, "evidence": [self.fact["id"]]}
        base.update(kw)
        return base

    def test_good_hypothesis_admitted(self):
        r = self.run_admit(self.hyp())
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(r.stdout)
        self.assertTrue(rec["id"].startswith("h_"))
        self.assertEqual(rec["src"], "agent:test")

    def test_hallucinated_evidence_rejected(self):
        """The failure the architecture exists to prevent: prose citing a fact
        that was never established."""
        r = self.run_admit(self.hyp(evidence=["f_" + "0" * 24]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not in the log", r.stderr)

    def test_evidence_must_be_a_fact_not_another_judgement(self):
        ok = self.run_admit(self.hyp())
        hid = json.loads(ok.stdout)["id"]
        r = self.run_admit(self.hyp(evidence=[hid]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is a hypothesis, not a fact", r.stderr)

    def test_no_evidence_rejected(self):
        self.assertNotEqual(self.run_admit(self.hyp(evidence=[])).returncode, 0)

    def test_confirmed_refused_in_a_static_run(self):
        r = self.run_admit(self.hyp(status="confirmed"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("requires a dynamic verification tier", r.stderr)

    def test_confirmed_allowed_only_with_an_explicit_dynamic_run(self):
        r = self.run_admit(self.hyp(status="confirmed"), extra=("--dynamic",))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_confidence_bounds(self):
        for bad in (1.5, -0.1, "high"):
            self.assertNotEqual(self.run_admit(self.hyp(confidence=bad)).returncode, 0, bad)

    def test_finding_may_not_exceed_the_class_ceiling(self):
        hid = json.loads(self.run_admit(self.hyp()).stdout)["id"]
        f = {"hypothesis": hid, "tier": "dynamic_poc", "severity": "high",
             "recreation": "r", "refs": ["A.java:20"], "title": "t", "caveats": "c"}
        r = self.run_admit(f, kind="finding")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("above the class ceiling", r.stderr)

    def test_finding_without_caveats_rejected(self):
        """A static-only finding that does not say where it stops is the
        overclaiming this system exists to prevent. Asking in the prompt was not
        enough — the first real run produced 23 findings with none, because the
        output schema forbade the field the prompt demanded."""
        hid = json.loads(self.run_admit(self.hyp()).stdout)["id"]
        bad = {"hypothesis": hid, "tier": "static_pattern", "severity": "low",
               "recreation": "r", "refs": ["A.java:20"], "title": "t"}
        r = self.run_admit(bad, kind="finding")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("caveats", r.stderr)

    def test_finding_must_point_at_a_real_hypothesis(self):
        f = {"hypothesis": "h_nope", "tier": "static_reachability", "severity": "high",
             "recreation": "r", "refs": ["A.java:20"], "title": "t", "caveats": "c"}
        self.assertNotEqual(self.run_admit(f, kind="finding").returncode, 0)

    def test_class_title_is_accepted_as_an_alias(self):
        """Observed on the first local-model run and again on a 0.5B: the model wrote
        the class's human title where its identifier belongs. Both spellings come from
        the same manifest, so this is a formatting slip, not a judgement error — and
        constrained decoding exists to keep formatting out of the measurement."""
        r = self.run_admit(self.hyp(vuln_class="SQL injection"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_an_accepted_alias_is_normalised_to_the_identifier(self):
        """The alias is accepted at the door and never survives it: everything
        downstream keys on the identifier, so a title in the log would be the silent
        partial result all over again."""
        rec = json.loads(self.run_admit(self.hyp(vuln_class="SQL injection")).stdout)
        self.assertEqual(rec["vuln_class"], "sqli")

    def test_a_different_class_is_still_rejected(self):
        """Naming another class is comprehension, not formatting. The class is not
        the agent's to invent."""
        r = self.run_admit(self.hyp(vuln_class="xss"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("vuln_class", r.stderr)

    def test_batch_is_all_or_nothing(self):
        good, bad = self.hyp(), self.hyp(evidence=["f_" + "1" * 24])
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.admit", "--type", "hypothesis",
             "--class", "sqli", "--lang", "java", "--src", "agent:test"],
            cwd=ROOT, env=self.env,
            input=json.dumps(good) + "\n" + json.dumps(bad) + "\n",
            capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual([x for x in store.read(self.log) if x["type"] == "hypothesis"], [],
                         "a rejected batch must not partially land")


class TestBrief(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        self.addCleanup(self.tmp.cleanup)

    def brief(self, *argv):
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--class", "sqli",
             "--lang", "java", *argv],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [json.loads(l) for l in r.stdout.splitlines()]

    def test_header_carries_the_class_narrative_and_ceiling(self):
        rows = self.brief("--agent", "hypothesize")
        h = rows[0]
        self.assertEqual(h["kind"], "briefing")
        self.assertTrue(h["narrative"])
        self.assertTrue(h["seed_hypotheses"])
        self.assertEqual(h["max_static_tier"], "static_reachability")
        # The narrative is the agent's ONLY description of the class.
        self.assertTrue(h["instructions"])

    def test_cases_join_flow_and_sanitizer_facts(self):
        flow = flow_fact()
        check = records.fact(
            {"kind": "sanitizer_check", "source_name": "q", "source_file": "A.java",
             "source_line": 10, "sink_file": "A.java", "sink_line": 20, "sink_name": "executeQuery",
             "reported_paths": 1, "reported_paths_without_sanitizer": 0, "candidate_count": 1,
             "candidate_sanitizers": [{"name": "replace", "file": "A.java", "line": 15,
                                       "code": "s.replace(1,2)", "step_index": 1,
                                       "full_name": "x", "resolved": True}]},
            "cpg:sanitizer_on_path")
        store.append([flow, check], self.log)
        rows = self.brief("--agent", "hypothesize")
        case = [r for r in rows if r.get("kind") == "case"][0]
        self.assertEqual(set(case["evidence"]), {flow["id"], check["id"]})
        self.assertEqual(case["sanitizers"]["candidates"][0]["name"], "replace")
        # The representative-paths caveat travels with the case, not just the docs.
        self.assertIn("representative", case["sanitizers"]["caveat"])

    def test_case_carries_the_tainted_arguments_type(self):
        """Sinks match on a short name, so the argument's type is what settles
        'is this even the right kind of call' without appealing to naming."""
        store.append([flow_fact(sink_arg_type="java.lang.String",
                                sink_arg_type_resolved=True)], self.log)
        case = [r for r in self.brief("--agent", "hypothesize") if r.get("kind") == "case"][0]
        self.assertEqual(case["sink"]["arg_type"], "java.lang.String")
        self.assertTrue(case["sink"]["arg_type_resolved"])

    def test_opengrep_sink_fact_does_not_displace_the_cpg_one(self):
        """Both substrates emit `sink_candidate` at the same file:line and the
        design encourages both to accrete into one log. Last-wins would let the
        opengrep record — which has no `arg_is_literal` — silently drop that field
        from every case."""
        flow = flow_fact()
        cpg_sink = records.fact(
            {"kind": "sink_candidate", "file": "A.java", "line": 20, "name": "executeQuery",
             "arg_is_literal": False, "arg_code": "sql", "resolved": True,
             "subject": "s", "object": "o"}, "cpg:sql_sinks")
        og_sink = records.fact(
            {"kind": "sink_candidate", "file": "A.java", "line": 20, "rule": "java_sql_sink",
             "code": "st.executeQuery(sql)", "vuln_class": "sqli"}, "opengrep:java_sql_sink")
        # appended AFTER the CPG fact, which is what breaks a last-wins lookup
        store.append([flow, cpg_sink, og_sink], self.log)
        case = [r for r in self.brief("--agent", "hypothesize") if r.get("kind") == "case"][0]
        self.assertIs(case["sink"]["arg_is_literal"], False,
                      "the CPG record carries the field and must win")

    def test_empty_log_still_briefs_without_inventing_cases(self):
        rows = self.brief("--agent", "hypothesize")
        self.assertEqual(rows[0]["cases"], 0)
        self.assertEqual([r for r in rows if r.get("kind") == "case"], [])


class TestStepSlimming(unittest.TestCase):
    """Path steps are 67% of the briefing and most of that is repetition."""

    def test_carried_fields_are_dropped_only_when_unchanged(self):
        from source_analyst.lifecycle.brief import _slim_steps
        steps = [
            {"label": "PARAM", "file": "A.java", "method": "m1", "line": 1, "code": "a"},
            {"label": "CALL", "file": "A.java", "method": "m1", "line": 2, "code": "b"},
            {"label": "CALL", "file": "B.java", "method": "m2", "line": 3, "code": "c"},
            {"label": "CALL", "file": "B.java", "method": "m3", "line": 4, "code": "d"},
        ]
        got = _slim_steps(steps)
        self.assertEqual(got[0], steps[0], "the first step states everything")
        self.assertEqual(got[1], {"label": "CALL", "line": 2, "code": "b"})
        self.assertEqual(got[2], steps[2], "a change must be restated")
        self.assertEqual(got[3], {"label": "CALL", "method": "m3", "line": 4, "code": "d"},
                         "file unchanged, method changed")

    def test_slimming_is_lossless(self):
        """Carrying the last stated value forward must rebuild the original exactly
        — a briefing that quietly lost a hop would be worse than a slow one."""
        from source_analyst.lifecycle.brief import _slim_steps, CARRIED_STEP_FIELDS
        steps = [
            {"file": "A.java", "method": "m1", "line": 1},
            {"file": "A.java", "method": "m1", "line": 2},
            {"file": "B.java", "method": "m1", "line": 3},
            {"file": "B.java", "method": "m2", "line": 4},
            {"file": "B.java", "method": "m2", "line": 5},
        ]
        carried, rebuilt = {}, []
        for slim in _slim_steps(steps):
            for k in CARRIED_STEP_FIELDS:
                if k in slim:
                    carried[k] = slim[k]
            rebuilt.append({**slim, **{k: v for k, v in carried.items()}})
        self.assertEqual(rebuilt, steps)

    def test_header_announces_the_convention(self):
        """The reader is told once, not on every step — which is the whole saving."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log = Path(tmp.name) / "log.jsonl"
        store.append([flow_fact()], log)
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--class", "sqli",
             "--lang", "java", "--agent", "hypothesize"],
            cwd=ROOT, env=dict(os.environ, SOURCE_ANALYST_LOG=str(log)),
            capture_output=True, text=True)
        header = json.loads(r.stdout.splitlines()[0])
        self.assertEqual(header["step_fields_carry_forward"], ["file", "method"])


class TestChunking(unittest.TestCase):
    """Batching, because a 38k-token briefing is a worse prompt than seven small
    ones — and because most models cannot hold it at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        self.addCleanup(self.tmp.cleanup)
        # Five cases at distinct sinks.
        store.append([flow_fact(sink_line=20 + i, source_name=f"q{i}") for i in range(5)],
                     self.log)

    def run_brief(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--class", "sqli",
             "--lang", "java", "--agent", "hypothesize", *argv],
            cwd=ROOT, env=self.env, capture_output=True, text=True)

    def rows(self, *argv):
        r = self.run_brief(*argv)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [json.loads(l) for l in r.stdout.splitlines()]

    def test_chunks_count_is_plain_on_stdout(self):
        """A shell driver must be able to loop without parsing JSON."""
        r = self.run_brief("--chunk-size", "2", "--chunks")
        self.assertEqual(r.stdout.strip(), "3")

    def test_every_case_appears_exactly_once_across_chunks(self):
        seen = []
        for i in range(3):
            seen += [c["sink"]["line"] for c in self.rows("--chunk-size", "2", "--chunk", str(i))
                     if c.get("kind") == "case"]
        self.assertEqual(sorted(seen), [20, 21, 22, 23, 24])
        self.assertEqual(len(seen), len(set(seen)), "a case must not be briefed twice")

    def test_chunk_header_says_it_is_a_chunk(self):
        """An agent given two cases must not read that as the whole set — it changes
        what 'the only one of its kind' would mean."""
        h = self.rows("--chunk-size", "2", "--chunk", "1")[0]
        self.assertEqual(h["chunk"], {"index": 1, "of": 3, "rows": 2, "rows_total": 5})
        self.assertEqual(h["cases"], 2)

    def test_last_chunk_is_short_not_padded(self):
        cases = [c for c in self.rows("--chunk-size", "2", "--chunk", "2")
                 if c.get("kind") == "case"]
        self.assertEqual(len(cases), 1)

    def test_chunk_past_the_end_is_an_error_not_an_empty_success(self):
        """Silently briefing nothing would look to the pipeline like a model that
        had nothing to say."""
        r = self.run_brief("--chunk-size", "2", "--chunk", "3")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("past the last batch", r.stderr)

    def test_chunk_without_size_is_rejected(self):
        self.assertNotEqual(self.run_brief("--chunk", "1").returncode, 0)

    def test_unchunked_briefing_is_unchanged(self):
        rows = self.rows()
        self.assertEqual(rows[0]["chunk"], {"index": 0, "of": 1, "rows": 5, "rows_total": 5})
        self.assertEqual(len([r for r in rows if r.get("kind") == "case"]), 5)


class TestRenderSummary(unittest.TestCase):
    """The opening triage table and the refuted list, both counted off the log."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))

    def build(self, specs):
        """specs: (confidence, severity, status) -> log of facts/hypotheses/findings"""
        recs = []
        for i, (conf, sev, status) in enumerate(specs):
            f = flow_fact(sink_line=20 + i, source_name=f"q{i}")
            h = records.record("hypothesis", {
                "statement": "s", "vuln_class": "sqli", "status": status,
                "confidence": conf, "evidence": [f["id"]],
                "case": "LIAR.java:999", "reasoning": f"reason {i}"}, src="agent:test")
            recs += [f, h]
            if status != "refuted":
                recs.append(records.record("finding", {
                    "hypothesis": h["id"], "title": f"t{i}", "tier": "static_reachability",
                    "severity": sev, "recreation": "r", "refs": ["A.java:20"],
                    "caveats": "c"}, src="agent:test"))
        store.append(recs, self.log)

    def render(self):
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render", "--class", "sqli"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_every_finding_lands_in_exactly_one_band(self):
        """The summary's totals must equal the findings. A finding that falls
        through the bands is a finding the reader never learns exists."""
        self.build([(0.95, "high", "needs_proof"), (0.85, "high", "needs_proof"),
                    (0.7, "medium", "needs_proof"), (0.1, "low", "needs_proof")])
        out = self.render()
        rows = [l for l in out.splitlines() if l.startswith("| ")]
        totals = [int(l.rsplit("|", 2)[1].strip().strip("*"))
                  for l in rows if "**total**" not in l and "confidence |" not in l
                  and not l.startswith("|---")]
        self.assertEqual(sum(totals), 4)
        self.assertIn("| **total**", out)

    def test_band_boundary_is_inclusive(self):
        from source_analyst.lifecycle.render import band_of, bands
        table = bands()
        self.assertEqual(band_of(0.85, table), "strong")
        self.assertEqual(band_of(0.8499, table), "moderate")
        self.assertEqual(band_of(0.0, table), "weak")

    def test_missing_confidence_is_unscored_not_weak(self):
        """Filing a missing number under the lowest band would invent a judgement."""
        from source_analyst.lifecycle.render import band_of, bands
        self.assertEqual(band_of(None, bands()), "unscored")
        self.assertEqual(band_of("high", bands()), "unscored")

    def test_last_band_must_reach_zero(self):
        from source_analyst.lifecycle import render
        d = Path(self.tmp.name)
        (d / "triage.yaml").write_text(
            yaml.safe_dump({"bands": [{"name": "a", "min": 0.5}]}))
        os.environ["SOURCE_ANALYST_CONFIG"] = str(d)
        self.addCleanup(lambda: os.environ.pop("SOURCE_ANALYST_CONFIG", None))
        with self.assertRaises(render.RenderError):
            render.bands()

    def test_refuted_are_listed_weakest_first(self):
        """Least-confident refutation on top: that is where the model was least sure
        it was right to drop a proven path, so it is where to look first."""
        self.build([(0.99, "high", "refuted"), (0.5, "high", "refuted"),
                    (0.75, "high", "refuted")])
        out = self.render()
        section = out.split("## Refuted during triage")[1]
        confs = [float(l.split("**confidence ")[1].split("**")[0])
                 for l in section.splitlines() if "**confidence " in l]
        self.assertEqual(confs, sorted(confs), "weakest refutation must come first")

    def test_refuted_site_comes_from_evidence_not_the_agents_prose(self):
        """Same discipline as `score`: the agent wrote 'LIAR.java:999' in `case`."""
        self.build([(0.9, "high", "refuted")])
        section = self.render().split("## Refuted during triage")[1]
        self.assertIn("A.java:20", section)
        self.assertNotIn("LIAR.java", section)

    def test_refuted_carry_evidence_ids_for_tracing(self):
        self.build([(0.9, "high", "refuted")])
        section = self.render().split("## Refuted during triage")[1]
        self.assertIn("Evidence: f_", section)

    def test_no_refuted_section_when_nothing_was_refuted(self):
        self.build([(0.9, "high", "needs_proof")])
        self.assertNotIn("Refuted during triage", self.render())


class TestRenderHonesty(unittest.TestCase):
    """Limits that are properties of the engine are stated by the renderer, not
    requested of an agent. Asking produced 0 mentions across 23 real findings."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))

    def seed(self, candidates):
        flow = flow_fact()
        evidence = [flow["id"]]
        recs = [flow]
        if candidates:
            check = records.fact(
                {"kind": "sanitizer_check", "source_name": "q", "source_file": "A.java",
                 "source_line": 10, "sink_file": "A.java", "sink_line": 20,
                 "sink_name": "executeQuery", "reported_paths": 1,
                 "reported_paths_without_sanitizer": 0,
                 "candidate_count": len(candidates),
                 "candidate_sanitizers": [{"name": n, "file": "A.java", "line": 15,
                                           "code": f"s.{n}()", "step_index": 1,
                                           "full_name": "x", "resolved": True}
                                          for n in candidates]},
                "cpg:sanitizer_on_path")
            recs.append(check)
            evidence.append(check["id"])
        h = records.record("hypothesis", {
            "statement": "s", "vuln_class": "sqli", "status": "needs_proof",
            "confidence": 0.8, "evidence": evidence}, src="agent:test")
        recs.append(h)
        recs.append(records.record("finding", {
            "hypothesis": h["id"], "title": "t", "tier": "static_reachability",
            "severity": "high", "recreation": "r", "refs": ["A.java:20"],
            "caveats": "the agent's own caveat"}, src="agent:test"))
        store.append(recs, self.log)

    def render(self):
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render", "--class", "sqli"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_representative_paths_limit_is_always_stated(self):
        self.seed([])
        self.assertIn("representative", self.render())

    def test_sanitizer_note_names_the_candidates_and_their_status(self):
        self.seed(["replace", "matches"])
        out = self.render()
        self.assertIn("Sanitizer note", out)
        self.assertIn("`matches`, `replace`", out)
        self.assertIn("not* been audited", out)

    def test_sanitizer_note_warns_a_clean_route_may_be_unreported(self):
        """The error that makes a live vulnerability look safer: reading 'a
        sanitizer was on the reported path' as 'every route is sanitized'."""
        self.seed(["replace"])
        note = self.render().split("**Sanitizer note.**")[1].split("\n")[0]
        self.assertIn("no sanitizer at all may exist", note)

    def test_no_sanitizer_note_when_no_candidate_was_seen(self):
        """Boilerplate on every finding would train the reader to skip it."""
        self.seed([])
        self.assertNotIn("Sanitizer note", self.render())


class TestRefutationBasis(unittest.TestCase):
    """A refutation resting on a resolved argument type and one resting on what
    things are named read identically in prose. They are not the same claim, and
    the weaker one is where a real bug hides, so the renderer separates them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))

    def seed(self, **fact_kw):
        f = flow_fact(**fact_kw)
        h = records.record("hypothesis", {
            "statement": "s", "vuln_class": "sqli", "status": "refuted",
            "confidence": 0.9, "evidence": [f["id"]],
            "reasoning": "the package is about something else"}, src="agent:test")
        store.append([f, h], self.log)

    def render(self):
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render", "--class", "sqli"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_resolved_type_is_reported_as_a_sound_basis(self):
        self.seed(sink_arg_type="org.springframework.web.multipart.MultipartFile",
                  sink_arg_type_resolved=True)
        out = self.render()
        self.assertIn("MultipartFile", out)
        self.assertIn("does not rest on naming", out)

    def test_missing_type_is_flagged_as_unverified(self):
        """The state every refutation was in before the type fact existed."""
        self.seed()
        out = self.render()
        self.assertIn("call site only", out)
        self.assertIn("argument type is unknown", out)
        self.assertIn("unverified", out)

    def test_unresolved_type_is_not_treated_as_evidence(self):
        """A frontend that could not resolve a type has said nothing. Reading ANY
        as 'not a string' would refute a live case on a tooling gap."""
        self.seed(sink_arg_type="ANY", sink_arg_type_resolved=False)
        out = self.render()
        self.assertIn("unresolved", out)
        self.assertIn("unverified", out)


class TestEmptyReportIsNotACleanBill(unittest.TestCase):
    """Invariant #8 at the last mile. Every tool refuses to let zero results read
    as "nothing here"; the document a human actually reads is the one place that
    mistake is expensive, and it was the one place not doing it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        self.log.touch()

    def render(self):
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render", "--class", "sqli"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_empty_log_says_nothing_was_analysed(self):
        out = self.render()
        self.assertIn("not the same as a clean result", out)
        self.assertIn("Nothing was analysed", out)
        self.assertNotIn("means: .", out, "the tier sentence must not render malformed")

    def test_facts_without_hypotheses_says_nothing_was_judged(self):
        store.append([flow_fact()], self.log)
        self.assertIn("Nothing was judged", self.render())

    def test_all_refuted_is_called_out_as_the_false_negative_shape(self):
        f = flow_fact()
        h = records.record("hypothesis", {
            "statement": "s", "vuln_class": "sqli", "status": "refuted",
            "confidence": 0.9, "evidence": [f["id"]], "reasoning": "no"}, src="agent:t")
        store.append([f, h], self.log)
        out = self.render()
        self.assertIn("Every candidate was refuted", out)
        self.assertIn("false-negative", out)

    def test_hypotheses_without_findings_says_not_written_up(self):
        f = flow_fact()
        h = records.record("hypothesis", {
            "statement": "s", "vuln_class": "sqli", "status": "needs_proof",
            "confidence": 0.9, "evidence": [f["id"]]}, src="agent:t")
        store.append([f, h], self.log)
        self.assertIn("Judged but not written up", self.render())

    def test_silence_is_never_offered_as_safety(self):
        self.assertIn("None of these is evidence that the code is safe", self.render())


class TestPromptHygiene(unittest.TestCase):
    """Over-fitting guard (§8): agents learn the class from the manifest, never
    from their own prompt. A prompt naming a class would not survive class #2."""

    FORBIDDEN = ("sql", "sqli", "injection", "xss", "ssrf")

    def test_agent_prompts_do_not_name_a_vuln_class(self):
        offenders = []
        for path in sorted((ROOT / "agents").glob("*.md")):
            for n, line in enumerate(path.read_text().lower().splitlines(), 1):
                for tok in self.FORBIDDEN:
                    if tok in line.split("#")[0]:
                        offenders.append(f"{path.name}:{n}: {tok}")
        self.assertEqual(offenders, [], "class knowledge belongs in the manifest narrative")

    def test_brief_instructions_do_not_name_a_vuln_class(self):
        from source_analyst.lifecycle.brief import INSTRUCTIONS
        blob = " ".join(x for v in INSTRUCTIONS.values() for x in v).lower()
        for tok in self.FORBIDDEN:
            self.assertNotIn(tok, blob, f"brief instructions name {tok!r}")


if __name__ == "__main__":
    unittest.main()
