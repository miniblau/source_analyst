"""Scoring an agent against corpus ground truth.

The scorer is the only place a number gets attached to a model, so its failure
mode is specific: a metric that is wrong in the flattering direction. These tests
are mostly about the three conflations `score` refuses to make.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from source_analyst import records
from source_analyst.belief import store
from source_analyst.lifecycle import score as sc

ROOT = Path(__file__).resolve().parents[1]

TRUTH = {
    "target": "t", "commit": "c", "class": "sqli", "language": "java",
    "labels": ["vulnerable", "not_this_class"],
    "sites": [
        {"sink": "A.java:20", "label": "vulnerable", "why": "concatenated"},
        {"sink": "B.java:30", "label": "not_this_class", "why": "not a db call"},
        {"sink": "C.java:40", "label": "vulnerable", "why": "never reached"},
    ],
}


def truth() -> dict:
    doc = dict(TRUTH)
    doc["by_sink"] = {s["sink"]: s for s in TRUTH["sites"]}
    return doc


def flow(file: str, line: int, source: str = "q") -> dict:
    return records.fact(
        {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.C.q:R(S)",
         "source_name": source, "source_marker": "m", "source_origin": "annotation",
         "source_code": "x", "source_file": file, "source_line": 1,
         "sink_name": "s", "sink_full_name": "f", "sink_code": "c", "sink_arg_code": "a",
         "sink_file": file, "sink_line": line, "path_length": 2, "crosses_methods": 1,
         "path_count": 1, "steps": []}, "cpg:reachable")


def hyp(fact_id: str, status: str, conf: float = 0.5, **kw) -> dict:
    base = {"statement": "s", "vuln_class": "sqli", "status": status, "confidence": conf,
            "evidence": [fact_id]}
    base.update(kw)
    return records.record("hypothesis", base, src="agent:test")


class TestConflationsRefused(unittest.TestCase):
    def score(self, log):
        return sc.score(log, truth(), "sqli", None)

    def test_dropped_vulnerable_is_a_false_negative(self):
        f = flow("A.java", 20)
        card, _, _ = self.score([f, hyp(f["id"], "refuted")])
        self.assertEqual(card["cases"]["false_negative"], 1)
        self.assertEqual(card["cases"]["true_positive"], 0)
        self.assertEqual(card["recall"], 0.0)

    def test_kept_noise_is_a_false_positive(self):
        f = flow("B.java", 30)
        card, _, _ = self.score([f, hyp(f["id"], "needs_proof")])
        self.assertEqual(card["cases"]["false_positive"], 1)
        self.assertEqual(card["precision"], 0.0)

    def test_site_the_substrate_never_offered_is_not_a_miss(self):
        """C.java:40 is labelled vulnerable and has no fact. Counting it as a
        false negative would blame the model for a substrate gap."""
        a, b = flow("A.java", 20), flow("B.java", 30)
        card, _, _ = self.score([a, b, hyp(a["id"], "needs_proof"),
                                 hyp(b["id"], "refuted")])
        self.assertEqual(card["cases"]["false_negative"], 0)
        self.assertEqual(card["recall"], 1.0)
        self.assertEqual(card["site_recall"], 1.0,
                         "an unreached site must not be folded into the model's recall")
        self.assertEqual(card["sites_never_reached_by_substrate"], ["C.java:40"])

    def test_unlabelled_site_is_unscored_not_correct(self):
        f = flow("Z.java", 99)
        card, rows, unl = self.score([f, hyp(f["id"], "needs_proof")])
        self.assertEqual(card["scored"], 0)
        self.assertEqual(card["unlabelled"], 1)
        self.assertEqual(rows, [])
        self.assertEqual(unl[0]["sink"], "Z.java:99")

    def test_site_comes_from_evidence_not_from_the_agents_prose(self):
        """An agent that writes the wrong `case` string must not be scored on it."""
        f = flow("B.java", 30)
        card, rows, _ = self.score([f, hyp(f["id"], "needs_proof", case="A.java:20")])
        self.assertEqual(rows[0]["sink"], "B.java:30")
        self.assertEqual(card["cases"]["false_positive"], 1,
                         "the lie must not turn kept noise into a true positive")

    def test_site_recall_is_per_site_not_per_case(self):
        """Two sources into one site: keeping one is still full coverage of the site,
        but case recall alone would say 50%."""
        a, b = flow("A.java", 20, "q1"), flow("A.java", 20, "q2")
        card, _, _ = self.score([a, b, hyp(a["id"], "needs_proof"), hyp(b["id"], "refuted")])
        self.assertEqual(card["recall"], 0.5)
        self.assertEqual(card["site_recall"], 1.0)


class TestMislabelledJudgementsAreVisible(unittest.TestCase):
    """The regression that made a 26-case run score 22 and look flawless."""

    def test_other_class_is_counted_and_named(self):
        f = flow("A.java", 20)
        wrong = hyp(f["id"], "needs_proof")
        wrong["vuln_class"] = "SQL injection"
        card, _, _ = sc.score([f, wrong], truth(), "sqli", None)
        self.assertEqual(card["scored"], 0)
        self.assertEqual(card["skipped_other_class"], ["SQL injection"],
                         "a filtered-out judgement must never be invisible")

    def test_a_reached_site_is_not_blamed_on_the_substrate(self):
        """The site has a fact, so the substrate found it. Deriving reached-ness
        from scored rows made a data defect read as a substrate gap."""
        f = flow("A.java", 20)
        wrong = hyp(f["id"], "needs_proof")
        wrong["vuln_class"] = "SQL injection"
        card, _, _ = sc.score([f, wrong], truth(), "sqli", None)
        self.assertNotIn("A.java:20", card["sites_never_reached_by_substrate"])
        self.assertIn("C.java:40", card["sites_never_reached_by_substrate"],
                      "a site with no fact at all is still a substrate gap")


class TestConfidenceSeparation(unittest.TestCase):
    """The metric that distinguishes a model from a rubber stamp."""

    def test_flat_confidence_separates_by_zero(self):
        a, b = flow("A.java", 20), flow("B.java", 30)
        card, _, _ = sc.score([a, b, hyp(a["id"], "needs_proof", 0.5),
                               hyp(b["id"], "needs_proof", 0.5)], truth(), "sqli", None)
        self.assertEqual(card["confidence"]["separation"], 0.0)

    def test_discriminating_confidence_separates_positively(self):
        a, b = flow("A.java", 20), flow("B.java", 30)
        card, _, _ = sc.score([a, b, hyp(a["id"], "needs_proof", 0.9),
                               hyp(b["id"], "needs_proof", 0.2)], truth(), "sqli", None)
        self.assertEqual(card["confidence"]["separation"], 0.7)

    def test_separation_is_null_when_no_noise_was_kept(self):
        """Undefined, not zero — there is nothing to compare against."""
        a = flow("A.java", 20)
        card, _, _ = sc.score([a, hyp(a["id"], "needs_proof", 0.9)], truth(), "sqli", None)
        self.assertIsNone(card["confidence"]["separation"])


class TestOracleValidation(unittest.TestCase):
    def _write(self, doc) -> Path:
        d = Path(self.tmp.name)
        (d / "t.sqli.yaml").write_text(yaml.safe_dump(doc))
        os.environ["SOURCE_ANALYST_GROUND_TRUTH"] = str(d)
        return d / "t.sqli.yaml"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.environ.pop("SOURCE_ANALYST_GROUND_TRUTH", None))

    def test_missing_oracle_is_fatal(self):
        self._write(TRUTH)
        with self.assertRaises(sc.ScoreError):
            sc.load_labels("nosuch", "sqli")

    def test_empty_oracle_is_fatal(self):
        self._write({"target": "t", "sites": []})
        with self.assertRaises(sc.ScoreError):
            sc.load_labels("t", "sqli")

    def test_label_outside_the_declared_vocabulary_is_fatal(self):
        doc = dict(TRUTH, sites=[{"sink": "A.java:20", "label": "probably_fine"}])
        self._write(doc)
        with self.assertRaises(sc.ScoreError):
            sc.load_labels("t", "sqli")

    def test_name_is_vocabulary_not_a_path(self):
        for bad in ["../../etc/passwd", "a/b", "A.java"]:
            with self.assertRaises(sc.ScoreError):
                sc.load_labels(bad, "sqli")


class TestShippedOracle(unittest.TestCase):
    """The WebGoat labels are ground truth; a label pointing at nothing is worse
    than no label at all."""

    def setUp(self):
        self.truth = sc.load_labels("webgoat", "sqli")

    def test_labels_are_declared_and_used(self):
        used = {s["label"] for s in self.truth["sites"]}
        self.assertEqual(used, set(self.truth["labels"]),
                         "a one-sided oracle cannot distinguish a model from a rubber stamp")

    def test_every_site_points_at_real_source(self):
        root = ROOT / "corpus" / "webgoat"
        if not root.is_dir():
            self.skipTest("webgoat fixture not present")
        for sink in self.truth["by_sink"]:
            path, _, line = sink.rpartition(":")
            f = root / path
            self.assertTrue(f.is_file(), f"{path} does not exist")
            self.assertLessEqual(int(line), len(f.read_text().splitlines()),
                                 f"{sink} is past end of file")

    def test_every_site_carries_its_reasoning(self):
        for sink, spec in self.truth["by_sink"].items():
            self.assertTrue(str(spec.get("why", "")).strip(),
                            f"{sink} has no `why` — an unarguable label is not ground truth")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.log = d / "log.jsonl"
        (d / "webgoat.sqli.yaml").write_text(yaml.safe_dump(TRUTH))
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log),
                        SOURCE_ANALYST_GROUND_TRUTH=str(d))

    def run_score(self, extra=()):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.score", "--class", "sqli",
             "--target", "webgoat", *extra],
            cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=120)

    def test_nothing_scored_exits_nonzero(self):
        """An empty scorecard prints plausible nulls; it must not read as a result."""
        store.append([flow("A.java", 20)], self.log)
        r = self.run_score()
        self.assertEqual(r.returncode, 3)
        self.assertIn("nothing was scored", r.stderr)

    def test_src_filter_scores_one_producer(self):
        f = flow("A.java", 20)
        mine = records.record("hypothesis", {"statement": "s", "vuln_class": "sqli",
                                             "status": "needs_proof", "confidence": 0.9,
                                             "evidence": [f["id"]]}, src="agent:a")
        theirs = records.record("hypothesis", {"statement": "s", "vuln_class": "sqli",
                                              "status": "refuted", "confidence": 0.1,
                                              "evidence": [f["id"]]}, src="agent:b")
        store.append([f, mine, theirs], self.log)
        a = json.loads(self.run_score(["--src", "agent:a"]).stdout.splitlines()[0])
        b = json.loads(self.run_score(["--src", "agent:b"]).stdout.splitlines()[0])
        self.assertEqual(a["cases"]["true_positive"], 1)
        self.assertEqual(b["cases"]["false_negative"], 1)

    def test_detail_emits_one_row_per_case(self):
        f = flow("A.java", 20)
        store.append([f, hyp(f["id"], "needs_proof")], self.log)
        out = [json.loads(l) for l in self.run_score(["--detail"]).stdout.splitlines()]
        self.assertEqual(out[0]["kind"], "scorecard")
        self.assertEqual(out[1]["kind"], "scored_case")
        self.assertEqual(out[1]["sink"], "A.java:20")

    def test_scoring_writes_nothing_to_the_log(self):
        """A scorecard is a measurement of a model, not a fact about the code."""
        f = flow("A.java", 20)
        store.append([f, hyp(f["id"], "needs_proof")], self.log)
        before = self.log.read_bytes()
        self.run_score()
        self.assertEqual(self.log.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
