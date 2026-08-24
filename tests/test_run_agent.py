"""The seam: `run_agent` transports a briefing to a model and JSONL back.

Every test here runs with zero model calls — the runner under test is the stub,
which is the whole point of having a runner seam that is configuration rather
than code. What is being tested is transport discipline: selection, isolation,
slop handling, and the two failure modes that must never look like success.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from source_analyst import records
from source_analyst.belief import store
from source_analyst.lifecycle import run_agent as ra

ROOT = Path(__file__).resolve().parents[1]

BRIEFING = json.dumps({
    "kind": "briefing", "agent": "hypothesize", "class": "sqli", "title": "t",
    "language": "java", "narrative": "n", "seed_hypotheses": [],
    "max_static_tier": "static_reachability", "instructions": [],
}, separators=(",", ":"))


def case_line(evidence: list[str]) -> str:
    return json.dumps({
        "kind": "case", "evidence": evidence,
        "source": {"name": "q", "file": "A.java", "line": 10},
        "sink": {"name": "executeQuery", "file": "A.java", "line": 20},
        "path": {}, "sanitizers": None}, separators=(",", ":"))


def run(argv: list[str], stdin: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "source_analyst.lifecycle.run_agent", *argv],
                          cwd=ROOT, input=stdin, capture_output=True, text=True,
                          env=env or dict(os.environ), timeout=120)


class TestSelection(unittest.TestCase):
    """Which model answers is a configuration decision, resolved in one place."""

    DOC = {"default": "stub",
           "runners": {"stub": {"cmd": ["true"]}, "other": {"cmd": ["true"]}},
           "agents": {"report": "other"}}

    def test_precedence_flag_beats_everything(self):
        env = dict(os.environ, SOURCE_ANALYST_RUNNER="stub")
        try:
            os.environ["SOURCE_ANALYST_RUNNER"] = "stub"
            name, _ = ra.select(self.DOC, "report", "other")
        finally:
            os.environ.pop("SOURCE_ANALYST_RUNNER", None)
        self.assertEqual(name, "other")
        self.assertTrue(env)

    def test_per_agent_override_then_default(self):
        os.environ.pop("SOURCE_ANALYST_RUNNER", None)
        self.assertEqual(ra.select(self.DOC, "report", None)[0], "other")
        self.assertEqual(ra.select(self.DOC, "hypothesize", None)[0], "stub")

    def test_env_beats_config(self):
        os.environ["SOURCE_ANALYST_RUNNER"] = "stub"
        try:
            self.assertEqual(ra.select(self.DOC, "report", None)[0], "stub")
        finally:
            os.environ.pop("SOURCE_ANALYST_RUNNER", None)

    def test_unknown_runner_is_fatal(self):
        with self.assertRaises(ra.RunnerError):
            ra.select(self.DOC, "hypothesize", "nope")

    def test_runner_without_cmd_is_fatal(self):
        with self.assertRaises(ra.RunnerError):
            ra.select({"default": "x", "runners": {"x": {}}}, "hypothesize", None)

    def test_shipped_config_is_loadable_and_names_a_default(self):
        doc = ra.load_runners()
        self.assertIn(doc["default"], doc["runners"])
        for name, spec in doc["runners"].items():
            self.assertIsInstance(spec.get("cmd"), list, f"runner {name} has no cmd list")


class TestPromptResolution(unittest.TestCase):
    def test_agent_name_is_vocabulary_not_a_path(self):
        for bad in ["../etc/passwd", "a/b", "/abs", "a.b"]:
            with self.assertRaises(ra.RunnerError, msg=f"{bad!r} should be rejected"):
                ra.prompt_path(bad)

    def test_missing_prompt_is_fatal(self):
        with self.assertRaises(ra.RunnerError):
            ra.prompt_path("no_such_agent")

    def test_shipped_agents_resolve(self):
        for agent in ("hypothesize", "report"):
            self.assertTrue(ra.prompt_path(agent).is_file())

    def test_model_placeholder_without_model_is_fatal(self):
        with self.assertRaises(ra.RunnerError):
            ra.build_cmd({"cmd": ["run", "{model}"]}, "hypothesize")

    def test_placeholders_expand(self):
        cmd = ra.build_cmd({"cmd": ["x", "{agent}", "{model}", "{prompt}"], "model": "m"},
                           "hypothesize")
        self.assertEqual(cmd[1:3], ["hypothesize", "m"])
        self.assertTrue(cmd[3].endswith("agents/hypothesize.md"))

    def test_composed_input_carries_prompt_then_briefing(self):
        payload = ra.compose("hypothesize", BRIEFING)
        self.assertIn("# hypothesize", payload)
        self.assertIn('"kind":"briefing"', payload)
        self.assertLess(payload.index("# hypothesize"), payload.index('"kind":"briefing"'))


class TestExtraction(unittest.TestCase):
    """Models narrate. That is not an error, and it is not data either."""

    def test_fences_and_prose_are_discarded_and_counted(self):
        objs, junk = ra.extract(
            'Sure! Here you go:\n```json\n{"a":1}\n{"b":2}\n```\nHope that helps.\n')
        self.assertEqual(objs, [{"a": 1}, {"b": 2}])
        self.assertEqual(len(junk), 2)

    def test_json_arrays_are_not_records(self):
        """The contract is one object per line; an array is the model ignoring it."""
        objs, junk = ra.extract('[{"a":1}]\n')
        self.assertEqual(objs, [])
        self.assertEqual(len(junk), 1)


class TestFailureModes(unittest.TestCase):
    """The ways a run can come back incomplete, none of which is success."""

    def _cfg(self, tmp: Path, runners: dict) -> dict:
        (tmp / "runners.yaml").write_text(json.dumps({"default": "t", "runners": runners}))
        for name in ("hypothesis.yaml", "tiers.yaml", "verdicts.yaml", "languages.yaml"):
            src = ROOT / "config" / name
            if src.is_file():
                (tmp / name).write_text(src.read_text())
        return dict(os.environ, SOURCE_ANALYST_CONFIG=str(tmp))

    def test_no_records_exits_nonzero(self):
        """A model that emitted only prose established nothing. Exiting 0 would
        let the next `admit` read as 'the model had nothing to say'."""
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["echo", "I could not find anything."]}})
            r = run(["--agent", "hypothesize"], BRIEFING, env)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(r.stdout.strip(), "")
        self.assertIn("established nothing", r.stderr)

    def test_runner_failure_exits_nonzero_and_emits_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["false"]}})
            r = run(["--agent", "hypothesize"], BRIEFING, env)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout.strip(), "")
        self.assertIn("exited 1", r.stderr)

    def test_missing_runner_binary_is_reported_plainly(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["definitely_not_installed_xyz"]}})
            r = run(["--agent", "hypothesize"], BRIEFING, env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not installed", r.stderr)

    def test_timeout_is_reported_not_hung(self):
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["sleep", "30"], "timeout": 1}})
            r = run(["--agent", "hypothesize"], BRIEFING, env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exceeded", r.stderr)

    def test_empty_stdin_rejected(self):
        r = run(["--agent", "hypothesize", "--runner", "stub"], "")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nothing on stdin", r.stderr)

    def test_fewer_records_than_cases_exits_nonzero(self):
        """Observed on a 0.5B: four cases in, one record out, exit 0. The three
        missing cases were never judged, and nothing downstream could tell them from
        cases the model had considered and dismissed — the log is simply short, and
        short reads as complete."""
        one = json.dumps({"statement": "s", "vuln_class": "sqli", "status": "proposed",
                          "confidence": 0.5, "evidence": ["f_" + "a" * 24]},
                         separators=(",", ":"))
        briefing = BRIEFING + "\n" + "\n".join(case_line(["f_" + "a" * 24]) for _ in range(4))
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["echo", one]}})
            r = run(["--agent", "hypothesize"], briefing, env)
        self.assertEqual(r.returncode, 4)
        self.assertIn("4 case(s) briefed but only 1", r.stderr)
        self.assertIn("unjudged", r.stderr)
        # The first cut of this gate printed the records and *then* exited 4, so
        # `run_agent | admit` had already handed the short batch over and it landed
        # in the log. A non-zero exit stops the next command, not the current pipe.
        self.assertEqual(r.stdout.strip(), "")

    def test_one_record_per_case_is_success(self):
        rec = json.dumps({"statement": "s", "vuln_class": "sqli", "status": "proposed",
                          "confidence": 0.5, "evidence": ["f_" + "a" * 24]},
                         separators=(",", ":"))
        briefing = BRIEFING + "\n" + "\n".join(case_line(["f_" + "a" * 24]) for _ in range(2))
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["printf", "%s\\n%s\\n", rec, rec]}})
            r = run(["--agent", "hypothesize"], briefing, env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stderr.strip().splitlines()[-1])["cases"], 2)

    def test_a_briefing_with_no_cases_is_not_short(self):
        """`cases: 0` must not turn every run into a short count — the check is
        about cases that went unjudged, not about briefings that carry none."""
        rec = json.dumps({"statement": "s", "vuln_class": "sqli", "status": "proposed",
                          "confidence": 0.5, "evidence": ["f_" + "a" * 24]},
                         separators=(",", ":"))
        with tempfile.TemporaryDirectory() as d:
            env = self._cfg(Path(d), {"t": {"cmd": ["echo", rec]}})
            r = run(["--agent", "hypothesize"], BRIEFING, env)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestStubRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.var = Path(self.tmp.name)
        self.env = dict(os.environ, SOURCE_ANALYST_VAR=str(self.var))

    def test_round_trip_through_the_seam(self):
        stdin = BRIEFING + "\n" + case_line(["f_a", "f_b"]) + "\n"
        r = run(["--agent", "hypothesize", "--runner", "stub"], stdin, self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        objs = [json.loads(l) for l in r.stdout.splitlines()]
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]["evidence"], ["f_a", "f_b"],
                         "evidence must survive the seam byte-for-byte")
        self.assertEqual(objs[0]["vuln_class"], "sqli")

    def test_meta_reports_the_slop(self):
        stdin = BRIEFING + "\n" + case_line(["f_a"]) + "\n"
        r = run(["--agent", "hypothesize", "--runner", "stub"], stdin, self.env)
        meta = json.loads([l for l in r.stderr.splitlines() if l.startswith("{")][-1])
        self.assertEqual(meta["records"], 1)
        self.assertGreaterEqual(meta["discarded_lines"], 1, "the stub emits prose on purpose")
        self.assertEqual(meta["runner"], "stub")

    def test_transcript_records_both_sides(self):
        """A nondeterministic step needs provenance: what the model saw, verbatim."""
        stdin = BRIEFING + "\n" + case_line(["f_a"]) + "\n"
        r = run(["--agent", "hypothesize", "--runner", "stub"], stdin, self.env)
        meta = json.loads([l for l in r.stderr.splitlines() if l.startswith("{")][-1])
        text = Path(meta["transcript"]).read_text()
        self.assertIn("===== STDIN =====", text)
        self.assertIn("# hypothesize", text, "the prompt the model was given")
        self.assertIn('"kind":"case"', text)
        self.assertIn("===== STDOUT =====", text)

    def test_determinism(self):
        stdin = BRIEFING + "\n" + case_line(["f_a"]) + "\n" + case_line(["f_b"]) + "\n"
        a = run(["--agent", "hypothesize", "--runner", "stub"], stdin, self.env)
        b = run(["--agent", "hypothesize", "--runner", "stub"], stdin, self.env)
        self.assertEqual(a.stdout, b.stdout)

    def test_dry_run_spawns_nothing(self):
        stdin = BRIEFING + "\n" + case_line(["f_a"]) + "\n"
        r = run(["--agent", "hypothesize", "--runner", "stub", "--dry-run"], stdin, self.env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("# hypothesize", r.stdout)
        self.assertFalse((self.var / "agent_runs").exists(), "dry run must not write a transcript")


class TestChainWithZeroModelCalls(unittest.TestCase):
    """brief -> run_agent -> admit, end to end, on a synthetic log.

    This is the test that says the Phase 1 loop is real: the only nondeterministic
    component is replaced by a script, and everything else is the shipped code.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.log = d / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log),
                        SOURCE_ANALYST_VAR=str(d), SOURCE_ANALYST_RUNNER="stub")
        flow = records.fact(
            {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.C.q:R(S)",
             "source_name": "q", "source_marker": "RequestParam", "source_origin": "annotation",
             "source_code": "@RequestParam String q", "source_file": "A.java", "source_line": 10,
             "sink_name": "executeQuery", "sink_full_name": "java.sql.Statement.executeQuery:R(S)",
             "sink_code": "st.executeQuery(sql)", "sink_arg_code": "sql",
             "sink_file": "A.java", "sink_line": 20, "path_length": 3, "crosses_methods": 2,
             "path_count": 1, "steps": []}, "cpg:reachable")
        store.append([flow], self.log)
        self.flow = flow

    def stage(self, argv, stdin=None):
        return subprocess.run([sys.executable, "-m", *argv], cwd=ROOT, env=self.env,
                              input=stdin, capture_output=True, text=True, timeout=120)

    def test_hypothesis_leg(self):
        b = self.stage(["source_analyst.lifecycle.brief", "--agent", "hypothesize",
                        "--class", "sqli", "--lang", "java"])
        self.assertEqual(b.returncode, 0, b.stderr)
        a = self.stage(["source_analyst.lifecycle.run_agent", "--agent", "hypothesize"], b.stdout)
        self.assertEqual(a.returncode, 0, a.stderr)
        m = self.stage(["source_analyst.lifecycle.admit", "--type", "hypothesis",
                        "--class", "sqli", "--lang", "java", "--src", "agent:stub"], a.stdout)
        self.assertEqual(m.returncode, 0, m.stderr)
        rec = json.loads(m.stdout.strip())
        self.assertEqual(rec["type"], "hypothesis")
        self.assertEqual(rec["evidence"], [self.flow["id"]],
                         "the fact id must be the same one the substrate minted")

    def test_full_chain_reaches_a_rendered_report(self):
        for agent, kind, status in (("hypothesize", "hypothesis", None),
                                    ("report", "finding", "needs_proof")):
            argv = ["source_analyst.lifecycle.brief", "--agent", agent,
                    "--class", "sqli", "--lang", "java"]
            if status:
                argv += ["--status", status]
            b = self.stage(argv)
            a = self.stage(["source_analyst.lifecycle.run_agent", "--agent", agent], b.stdout)
            self.assertEqual(a.returncode, 0, a.stderr)
            m = self.stage(["source_analyst.lifecycle.admit", "--type", kind, "--class", "sqli",
                            "--lang", "java", "--src", f"agent:{agent}"], a.stdout)
            self.assertEqual(m.returncode, 0, m.stderr)

        r = self.stage(["source_analyst.lifecycle.render", "--class", "sqli"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("A.java:20", r.stdout)


class TestNoModelKnowledgeInCode(unittest.TestCase):
    """The §7 model-agnostic claim, enforced mechanically rather than by review.

    Sibling of test_manifest's invariant #3 check: if a provider or model name
    ever appears in code, the claim that swapping models is a config edit has
    quietly stopped being true, and this is where that gets caught.
    """

    VENDORS = ("openai", "anthropic", "gpt-", "llama", "mistral", "qwen", "gemini",
               "api_key", "api-key", "bearer ", "chat/completions", "ollama", "opencode")

    def test_no_vendor_token_in_python(self):
        offenders = []
        for py in sorted((ROOT / "source_analyst").rglob("*.py")):
            text = py.read_text().lower()
            for token in self.VENDORS:
                if token in text:
                    offenders.append(f"{py.relative_to(ROOT)}: {token!r}")
        self.assertEqual(offenders, [], "vendor knowledge belongs in config/runners.yaml")

    def test_config_is_where_vendors_live(self):
        """...and the counterpart: the seam is real because config does name them."""
        text = (ROOT / "config" / "runners.yaml").read_text().lower()
        self.assertTrue(any(v in text for v in ("ollama", "opencode")),
                        "runners.yaml should carry at least one real runner to copy")


if __name__ == "__main__":
    unittest.main()
