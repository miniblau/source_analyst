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


class TestArgumentQuality(unittest.TestCase):
    """Precision cannot tell a sound refutation from a lucky one.

    Both score 1.0, and on the first full three-class run that difference was
    real: all three sqli noise sites carried identical, fully resolved
    `sink_arg_type` evidence, and the agent argued from it once and from the
    sink's NAME twice. Separately an open_redirect case came back `refuted` while
    its own prose said the tainted value "directly influences the redirect
    destination". This block is what makes that visible; it must never move a
    number, because a phrase list is an approximation.
    """

    def refuted(self, reasoning):
        h = hyp("f_x", "refuted", 0.9)
        h["reasoning"] = reasoning
        return h

    def signals(self, reasoning):
        log = [flow("A.java", 20)]
        h = self.refuted(reasoning)
        h["evidence"] = [log[0]["id"]]
        return sc.score(log + [h], truth(), "sqli", None)[0]["argument_quality"]

    def test_prose_that_argues_the_bug_under_a_refuted_verdict_is_flagged(self):
        a = self.signals("The source is an Integer used as a map key. However the "
                         "tainted value directly influences the redirect destination.")
        self.assertEqual(a["signals"]["contradicts_verdict"], 1)

    def test_refuting_from_a_name_is_flagged(self):
        a = self.signals("The sink name 'execute' does not align with this class.")
        self.assertEqual(a["signals"]["argued_from_name"], 1)
        self.assertEqual(a["signals"]["argued_from_evidence"], 0)

    def test_naming_the_sink_while_citing_the_type_is_not_held_against_it(self):
        """The prompt asks for exactly this shape, so it must not be penalised."""
        a = self.signals("The sink is named 'execute', but the argument type is "
                         "MultipartFile, which cannot hold SQL statement text.")
        self.assertEqual(a["signals"]["argued_from_name"], 0)
        self.assertEqual(a["signals"]["argued_from_evidence"], 1)

    def test_no_refutation_is_null_not_zero(self):
        """Nothing to characterise and nothing wrong are different answers."""
        log = [flow("A.java", 20)]
        h = hyp(log[0]["id"], "needs_proof", 0.9)
        a = sc.score(log + [h], truth(), "sqli", None)[0]["argument_quality"]
        self.assertEqual(a["n"], 0)
        self.assertIsNone(a["signals"])
        self.assertIn("nothing to characterise", a["note"])

    def test_it_never_moves_precision(self):
        """A phrase list must not launder a guess into a metric."""
        log = [flow("A.java", 20)]
        good = self.refuted("the argument type is MultipartFile")
        good["evidence"] = [log[0]["id"]]
        bad = self.refuted("the sink name does not match")
        bad["evidence"] = [log[0]["id"]]
        a = sc.score(log + [good], truth(), "sqli", None)[0]
        b = sc.score(log + [bad], truth(), "sqli", None)[0]
        self.assertEqual(a["precision"], b["precision"])
        self.assertEqual(a["recall"], b["recall"])


class TestGroundTruthLoading(unittest.TestCase):
    """The oracle must not shrink quietly.

    `by_sink` is keyed by sink, so a repeated sink silently overwrote its
    predecessor: the file said five sites, the scorer counted three, and nothing
    anywhere said so. A shorter oracle is an easier target, which is the flattering
    direction — the one failure mode this module exists to refuse.
    """

    def _load(self, sites: list[dict]) -> dict:
        d = Path(tempfile.mkdtemp())
        (d / "t.sqli.yaml").write_text(yaml.safe_dump(dict(TRUTH, sites=sites)))
        old = os.environ.get("SOURCE_ANALYST_GROUND_TRUTH")
        os.environ["SOURCE_ANALYST_GROUND_TRUTH"] = str(d)
        try:
            return sc.load_labels("t", "sqli")
        finally:
            if old is None:
                del os.environ["SOURCE_ANALYST_GROUND_TRUTH"]
            else:
                os.environ["SOURCE_ANALYST_GROUND_TRUTH"] = old

    def test_duplicate_sink_is_rejected_not_collapsed(self):
        with self.assertRaises(sc.ScoreError) as cm:
            self._load([
                {"sink": "A.java:20", "label": "vulnerable", "why": "reached from one entry"},
                {"sink": "A.java:20", "label": "vulnerable", "why": "reached from another"},
            ])
        self.assertIn("duplicate site", str(cm.exception))

    def test_distinct_sinks_still_load(self):
        doc = self._load([
            {"sink": "A.java:20", "label": "vulnerable", "why": "one"},
            {"sink": "A.java:21", "label": "vulnerable", "why": "another line, another site"},
        ])
        self.assertEqual(len(doc["by_sink"]), 2)


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


def check(file: str, line: int, source: str = "q", candidates: int = 0) -> dict:
    """A sanitizer_check fact — carries the signal calibration correlates against."""
    return records.fact(
        {"kind": "sanitizer_check", "source_name": source, "source_file": file,
         "source_line": 1, "sink_file": file, "sink_line": line, "sink_name": "s",
         "reported_paths": 1, "reported_paths_without_sanitizer": 0,
         "candidate_count": candidates, "candidate_sanitizers": []},
        "cpg:sanitizer_on_path")


class TestSpearman(unittest.TestCase):
    def test_perfect_inverse_is_minus_one(self):
        self.assertEqual(sc.spearman([1, 2, 3, 4], [4, 3, 2, 1]), -1.0)

    def test_perfect_agreement_is_plus_one(self):
        self.assertEqual(sc.spearman([1, 2, 3, 4], [10, 20, 30, 40]), 1.0)

    def test_ties_do_not_invent_an_ordering(self):
        self.assertEqual(sc.spearman([1, 1, 1, 1], [1, 2, 3, 4]), None)

    def test_too_few_points_is_none(self):
        self.assertIsNone(sc.spearman([1, 2], [2, 1]))

    def test_monotone_but_not_linear_still_scores_one(self):
        """Rank correlation, not Pearson: the agent is being asked to order cases,
        not to place them on a line."""
        self.assertEqual(sc.spearman([1, 2, 3, 4], [1, 10, 1000, 100000]), 1.0)


class TestCalibration(unittest.TestCase):
    """Does confidence carry information? Stays defined when no noise was kept,
    which is precisely where `separation` gives up."""

    def kept(self, pairs):
        """pairs: (confidence, sanitizer candidate count)"""
        rows, facts = [], {}
        for i, (conf, cands) in enumerate(pairs):
            f, c = flow("A.java", 20 + i), check("A.java", 20 + i, candidates=cands)
            facts[f["id"]] = f
            facts[c["id"]] = c
            rows.append({"confidence": conf, "evidence": [f["id"], c["id"]]})
        return rows, facts

    def test_flat_confidence_is_named_not_left_blank(self):
        """The null baseline. 'The model said the same thing every time' is a result
        about the model, not a gap in the measurement."""
        rows, facts = self.kept([(0.5, 0), (0.5, 1), (0.5, 2), (0.5, 3)])
        out = sc.calibrate(rows, facts)
        self.assertEqual(out["spread"], 0.0)
        self.assertEqual(out["stdev"], 0.0)
        self.assertEqual(out["signals"], {})
        self.assertIn("constant", out["note"])

    def test_confidence_falling_with_sanitizers_agrees(self):
        rows, facts = self.kept([(0.9, 0), (0.8, 1), (0.7, 2), (0.6, 3)])
        sig = sc.calibrate(rows, facts)["signals"]["sanitizer_candidates"]
        self.assertEqual(sig["rho"], -1.0)
        self.assertTrue(sig["agrees"])

    def test_confidence_rising_with_sanitizers_disagrees(self):
        """The metric has to be able to fail, or it is decoration."""
        rows, facts = self.kept([(0.6, 0), (0.7, 1), (0.8, 2), (0.9, 3)])
        sig = sc.calibrate(rows, facts)["signals"]["sanitizer_candidates"]
        self.assertEqual(sig["rho"], 1.0)
        self.assertFalse(sig["agrees"])

    def test_constant_signal_is_distinguished_from_absent_signal(self):
        """Conflating them would hide a substrate gap behind a model result."""
        rows, facts = self.kept([(0.9, 2), (0.8, 2), (0.7, 2), (0.6, 2)])
        sigs = sc.calibrate(rows, facts)["signals"]
        self.assertIsNone(sigs["sanitizer_candidates"]["rho"])
        self.assertIn("constant", sigs["sanitizer_candidates"]["reason"])
        self.assertIn("absent", sigs["arg_is_literal"]["reason"])

    def test_calibration_reads_the_kept_set_only(self):
        f = flow("A.java", 20)
        card, _, _ = sc.score([f, hyp(f["id"], "refuted", 0.9)], truth(), "sqli", None)
        self.assertEqual(card["calibration"]["n"], 0)
        self.assertIn("no kept hypotheses", card["calibration"]["note"])

    def test_it_survives_a_model_that_kept_no_noise(self):
        """The whole point: `separation` is null on a perfect run, this is not."""
        rows, facts = self.kept([(0.9, 0), (0.8, 1), (0.7, 2)])
        out = sc.calibrate(rows, facts)
        self.assertIsNotNone(out["signals"]["sanitizer_candidates"]["rho"])


class TestCalibrationConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.environ.pop("SOURCE_ANALYST_CONFIG", None))

    def write(self, doc):
        d = Path(self.tmp.name)
        (d / "calibration.yaml").write_text(yaml.safe_dump(doc))
        os.environ["SOURCE_ANALYST_CONFIG"] = str(d)

    def test_shipped_config_loads(self):
        signals = sc.calibration_signals()
        self.assertTrue(signals)
        for name, spec in signals.items():
            self.assertIn(spec["direction"], ("up", "down"))
            self.assertTrue(str(spec.get("why", "")).strip(),
                            f"{name} has no `why` — an unarguable direction is a guess")

    def test_unknown_direction_rejected(self):
        self.write({"signals": {"x": {"field": "f", "direction": "sideways"}}})
        with self.assertRaises(sc.ScoreError):
            sc.calibration_signals()

    def test_signal_without_a_field_rejected(self):
        self.write({"signals": {"x": {"direction": "up"}}})
        with self.assertRaises(sc.ScoreError):
            sc.calibration_signals()

    def test_empty_signals_rejected(self):
        self.write({"signals": {}})
        with self.assertRaises(sc.ScoreError):
            sc.calibration_signals()


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

    def test_a_revised_case_is_scored_once_not_once_per_level(self):
        """A traced log holds one hypothesis per level per site, all at the same
        status. Grading a hypothesis alongside its own revision counts the site twice
        and feeds calibration duplicate points that inflate n. Measured on a traced
        WebGoat log: 49 scored over 26 sites."""
        f = flow("A.java", 20)
        root = hyp(f["id"], "needs_proof", 0.5)
        child = records.record("hypothesis",
                               {"statement": "s", "vuln_class": "sqli",
                                "status": "needs_proof", "confidence": 0.9,
                                "evidence": [f["id"]], "parent": root["id"], "depth": 1},
                               src="agent:trace")
        store.append([f, root, child], self.log)
        card = json.loads(self.run_score().stdout.splitlines()[0])
        self.assertEqual(card["scored"], 1)
        self.assertEqual(card["superseded_excluded"], 1)

    def test_scoring_a_producer_keeps_what_that_producer_said(self):
        """The other question. Dropping superseded rows under --src would score the
        hypothesize leg at zero on any log that has been traced."""
        f = flow("A.java", 20)
        root = hyp(f["id"], "needs_proof", 0.5)
        child = records.record("hypothesis",
                               {"statement": "s", "vuln_class": "sqli",
                                "status": "needs_proof", "confidence": 0.9,
                                "evidence": [f["id"]], "parent": root["id"], "depth": 1},
                               src="agent:trace")
        store.append([f, root, child], self.log)
        card = json.loads(self.run_score(["--src", "agent:test"]).stdout.splitlines()[0])
        self.assertEqual(card["scored"], 1)
        self.assertEqual(card["superseded_excluded"], 0)

    def test_scoring_writes_nothing_to_the_log(self):
        """A scorecard is a measurement of a model, not a fact about the code."""
        f = flow("A.java", 20)
        store.append([f, hyp(f["id"], "needs_proof")], self.log)
        before = self.log.read_bytes()
        self.run_score()
        self.assertEqual(self.log.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
