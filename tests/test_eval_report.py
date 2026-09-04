"""Per-case stability must be keyed on evidence, not on the agent's prose.

No Joern, no LLM. The bug these guard was found in the report's own output on
2026-09-04: the agent named one WebGoat site `JWTToken.java:98` in run 1 and
`JWTController.java:...` in runs 2 and 3, so keying on `case` split one flipping
case into two stable ones and hid the flip that moved open_redirect precision
from 1.0 to 0.5. A harness whose whole purpose is measuring noise was
under-reporting it.
"""

import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_report


def fact(fid, file, line):
    return {"v": 1, "type": "fact", "id": fid, "sink_file": file, "sink_line": line}


def hyp(hid, status, conf, evidence, case):
    return {"v": 1, "type": "hypothesis", "id": hid, "src": "agent:hypothesize",
            "status": status, "confidence": conf, "evidence": evidence, "case": case}


class TestSiteOf(unittest.TestCase):
    def test_resolves_from_evidence_not_the_case_string(self):
        facts = {"f_1": fact("f_1", "a/B.java", 98)}
        h = hyp("h1", "refuted", 0.9, ["f_1"], "totally/different/Name.java:1")
        self.assertEqual(eval_report.site_of(h, facts), "a/B.java:98")

    def test_falls_back_to_plain_file_line(self):
        facts = {"f_1": {"id": "f_1", "file": "a/c.ts", "line": 5}}
        self.assertEqual(
            eval_report.site_of(hyp("h", "x", 1, ["f_1"], "c"), facts), "a/c.ts:5")

    def test_unresolvable_evidence_does_not_collapse_into_one_key(self):
        a = eval_report.site_of(hyp("h1", "x", 1, [], "same prose"), {})
        b = eval_report.site_of(hyp("h2", "x", 1, [], "same prose"), {})
        self.assertNotEqual(a, b, "distinct hypotheses must not merge into a fake key")


class TestStability(unittest.TestCase):
    def _report(self, runs):
        """runs: list of list-of-hypotheses; shared facts. Returns the printed text."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name)
        shared = [fact("f_1", "a/B.java", 98), fact("f_2", "a/C.java", 12)]
        for i, hyps in enumerate(runs, 1):
            (out / f"run{i}.sqli.java.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in shared + hyps))
            (out / f"run{i}.sqli.java.score.json").write_text(json.dumps(
                {"scored": 1, "precision": 1.0, "recall": 1.0, "site_recall": 1.0,
                 "cases": {"true_positive": 1, "false_positive": 0,
                           "false_negative": 0}}))
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            eval_report.report(out)
        return buf.getvalue()

    def test_a_flip_hidden_behind_renamed_prose_is_reported(self):
        text = self._report([
            [hyp("h1", "refuted", 0.9, ["f_1"], "JWTToken.java:98")],
            [hyp("h2", "inconclusive", 0.5, ["f_1"], "JWTController.java:40")],
            [hyp("h3", "inconclusive", 0.5, ["f_1"], "JWTController.java:40")],
        ])
        self.assertIn("FLIPPED", text)
        self.assertIn("B.java:98", text)  # printed short, as the report does
        self.assertIn("1 flipped", text)

    def test_a_case_absent_from_a_run_is_not_stable(self):
        text = self._report([
            [hyp("h1", "refuted", 0.9, ["f_2"], "c")],
            [hyp("h2", "refuted", 0.9, ["f_2"], "c")],
            [],  # never judged in run 3
        ])
        self.assertIn("ABSENT", text)
        self.assertIn("1 flipped", text)

    def test_a_genuinely_stable_case_stays_stable(self):
        text = self._report([[hyp(f"h{i}", "refuted", 0.9, ["f_1"], "c")] for i in range(3)])
        self.assertNotIn("FLIPPED", text)
        self.assertIn("1 stable, 0 flipped", text)
