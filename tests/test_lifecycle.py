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
             "recreation": "r", "refs": ["A.java:20"], "title": "t"}
        r = self.run_admit(f, kind="finding")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("above the class ceiling", r.stderr)

    def test_finding_must_point_at_a_real_hypothesis(self):
        f = {"hypothesis": "h_nope", "tier": "static_reachability", "severity": "high",
             "recreation": "r", "refs": ["A.java:20"], "title": "t"}
        self.assertNotEqual(self.run_admit(f, kind="finding").returncode, 0)

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

    def test_empty_log_still_briefs_without_inventing_cases(self):
        rows = self.brief("--agent", "hypothesize")
        self.assertEqual(rows[0]["cases"], 0)
        self.assertEqual([r for r in rows if r.get("kind") == "case"], [])


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
