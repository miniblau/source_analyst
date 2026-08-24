"""The trace loop: the only iterating agent (design §4.1, §4.2).

Two halves, both deterministic and both tested with zero model calls: which
hypotheses a level may descend into, and what a revision is allowed to assert.

The gates are the whole value here, so each one is tested from both sides — a
gate that cannot refuse is decoration.
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
from source_analyst.lifecycle.brief import callees_of, traceable

ROOT = Path(__file__).resolve().parents[1]
CFG = {"max": 3, "spend_gate": "rising_confidence", "checkpoint_every": 2}


def hyp(hid, status="needs_proof", confidence=0.5, depth=0, parent=None, evidence=()):
    return {"type": "hypothesis", "id": hid, "status": status, "statement": "s",
            "confidence": confidence, "depth": depth, "parent": parent,
            "evidence": list(evidence), "vuln_class": "sqli"}


class TestTraceable(unittest.TestCase):
    """Three gates, three different reasons to stop. None substitutes for another."""

    def test_a_leaf_is_traceable(self):
        self.assertEqual([h["id"] for h in traceable([hyp("h_a")], "needs_proof", CFG)],
                         ["h_a"])

    def test_a_hypothesis_with_a_child_is_not_retraced(self):
        """Re-tracing a node that already has a child forks the tree sideways
        instead of deepening it, and doubles the spend for no new depth."""
        log = [hyp("h_a"), hyp("h_b", parent="h_a", depth=1, confidence=0.9)]
        self.assertEqual([h["id"] for h in traceable(log, "needs_proof", CFG)], ["h_b"])

    def test_the_wrong_status_is_not_traced(self):
        self.assertEqual(traceable([hyp("h_a", status="refuted")], "needs_proof", CFG), [])

    def test_refuted_can_be_traced_deliberately(self):
        """Re-examining exclusions is the point of having the body: a refutation is
        exactly the judgement a reviewer most wants a second look at."""
        self.assertEqual([h["id"] for h in
                          traceable([hyp("h_a", status="refuted")], "refuted", CFG)], ["h_a"])

    def test_max_depth_is_a_hard_stop(self):
        self.assertEqual(traceable([hyp("h_a", depth=3)], "needs_proof", CFG), [])
        self.assertEqual([h["id"] for h in traceable([hyp("h_a", depth=2)], "needs_proof", CFG)],
                         ["h_a"])

    def test_spend_gate_starves_a_level_that_did_not_help(self):
        """`rising_confidence`: a level costs budget, so paying for another one after
        the last made the case no stronger is how a rabbit hole eats an afternoon."""
        log = [hyp("h_a", confidence=0.7),
               hyp("h_b", parent="h_a", depth=1, confidence=0.7)]
        self.assertEqual(traceable(log, "needs_proof", CFG), [])

    def test_spend_gate_funds_a_level_that_helped(self):
        log = [hyp("h_a", confidence=0.7),
               hyp("h_b", parent="h_a", depth=1, confidence=0.8)]
        self.assertEqual([h["id"] for h in traceable(log, "needs_proof", CFG)], ["h_b"])

    def test_spend_gate_can_be_disabled(self):
        log = [hyp("h_a", confidence=0.7),
               hyp("h_b", parent="h_a", depth=1, confidence=0.4)]
        cfg = dict(CFG, spend_gate="always")
        self.assertEqual([h["id"] for h in traceable(log, "needs_proof", cfg)], ["h_b"])


class TestCalleeSelection(unittest.TestCase):
    """What gets read is decided by the substrate, from the hypothesis's own facts."""

    def _fact(self, **kw):
        payload = {"kind": "flow", "subject": "p.C.handler:R(S)", "object": "p.C.run:R(S)",
                   "sink_full_name": "java.sql.Statement.executeQuery:R(S)",
                   "steps": [{"method": "p.C.handler:R(S)"}, {"method": "p.Helper.clean:S(S)"}]}
        payload.update(kw)
        return records.fact(payload, "cpg:reachable")

    def test_reading_list_covers_the_methods_the_flow_passes_through(self):
        """Measured on WebGoat SQLi: every sink and every sanitizer candidate resolves
        into java.sql or java.lang and has no body in the tree. A reading list of
        those alone came back eight stubs and taught the agent nothing — the readable
        code is in the methods the flow crosses."""
        f = self._fact()
        got = callees_of(hyp("h_a", evidence=[f["id"]]), {f["id"]: f})
        self.assertIn("p.Helper.clean:S(S)", got)
        self.assertIn("p.C.handler:R(S)", got)
        self.assertIn("p.C.run:R(S)", got)
        self.assertIn("java.sql.Statement.executeQuery:R(S)", got)

    def test_sanitizer_candidates_are_read(self):
        f = self._fact(kind="sanitizer_check",
                       candidate_sanitizers=[{"full_name": "p.Helper.escape:S(S)"}])
        self.assertIn("p.Helper.escape:S(S)",
                      callees_of(hyp("h_a", evidence=[f["id"]]), {f["id"]: f}))

    def test_evidence_that_is_not_in_the_log_is_skipped_not_invented(self):
        self.assertEqual(callees_of(hyp("h_a", evidence=["f_nope"]), {}), [])


class TestPriorBeliefsReachTrace(unittest.TestCase):
    """`trace` is the agent that produces beliefs, which makes it the one that most
    needs to see them — the store exists so a later run prunes instead of re-auditing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        flow = records.fact(
            {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.Helper.escape:S(S)",
             "sink_file": "A.java", "sink_line": 20, "steps": []}, "cpg:reachable")
        root = records.record("hypothesis",
                              {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
                               "confidence": 0.6, "evidence": [flow["id"]]}, "agent:hypothesize")
        body = records.fact({"kind": "callee_body", "full_name": "p.Helper.escape:S(S)",
                             "status": "resolved", "name": "escape", "body": "..."},
                            "cpg:callee_body")
        audited = records.belief("p.Helper.escape:S(S)", "sanitizes", "sqli", "unsound",
                                 "it only strips one quote form", "human")
        unrelated = records.belief("p.Other.thing:S(S)", "sanitizes", "sqli", "partial",
                                   "not on this path at all", "human")
        store.append([flow, root, body, audited, unrelated], self.log)

    def brief(self):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--agent", "trace",
             "--class", "sqli", "--lang", "java"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)

    def test_a_belief_about_a_method_in_this_batch_is_shown(self):
        r = self.brief()
        self.assertEqual(r.returncode, 0, r.stderr)
        priors = [json.loads(x) for x in r.stdout.splitlines()
                  if json.loads(x).get("kind") == "prior_belief"]
        self.assertEqual([p["subject"] for p in priors], ["p.Helper.escape:S(S)"])
        self.assertEqual(priors[0]["verdict"], "unsound")

    def test_a_belief_about_a_method_not_in_this_batch_is_not_shown(self):
        """Everything in a briefing is context the model pays for and may reason from.
        An audit of a method this case never touches is noise that can only mislead."""
        out = self.brief().stdout
        self.assertNotIn("p.Other.thing", out)

    def test_the_header_counts_what_was_shown(self):
        header = json.loads(self.brief().stdout.splitlines()[0])
        self.assertEqual(header["prior_beliefs"], 1)


class TestAdmitTrace(unittest.TestCase):
    """What a revision may assert. `admit` is still the only door."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))

        self.flow = records.fact(
            {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.C.q:R(S)",
             "sink_file": "A.java", "sink_line": 20,
             "sink_full_name": "java.sql.Statement.executeQuery:R(S)"}, "cpg:reachable")
        self.body = records.fact(
            {"kind": "callee_body", "full_name": "p.Helper.escape:S(S)", "status": "resolved",
             "name": "escape", "body": "return s.replace(\"x\", \"y\");"}, "cpg:callee_body")
        self.stub = records.fact(
            {"kind": "callee_body", "full_name": "java.sql.Statement.executeQuery:R(S)",
             "status": "external_stub", "name": "executeQuery", "body": ""}, "cpg:callee_body")
        self.parent = records.record(
            "hypothesis", {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
                           "confidence": 0.6, "evidence": [self.flow["id"]]}, "agent:hypothesize")
        store.append([self.flow, self.body, self.stub, self.parent], self.log)

    def run_admit(self, obj, extra=()):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.admit", "--type", "trace",
             "--class", "sqli", "--lang", "java", "--src", "agent:trace", *extra],
            cwd=ROOT, env=self.env, input=json.dumps(obj), capture_output=True, text=True)

    def rev(self, **kw):
        base = {"parent": self.parent["id"], "statement": "revised", "vuln_class": "sqli",
                "status": "needs_proof", "confidence": 0.8,
                "evidence": [self.flow["id"], self.body["id"]],
                "basis": "the body escapes nothing relevant", "read": ["p.Helper.escape:S(S)"]}
        base.update(kw)
        return base

    def records_of(self, kind):
        return [r for r in store.read(self.log) if r.get("type") == kind]

    def test_a_revision_becomes_a_child_at_the_next_depth(self):
        r = self.run_admit(self.rev())
        self.assertEqual(r.returncode, 0, r.stderr)
        kids = [h for h in self.records_of("hypothesis") if h.get("parent")]
        self.assertEqual(len(kids), 1)
        self.assertEqual(kids[0]["depth"], 1)
        self.assertEqual(kids[0]["parent"], self.parent["id"])
        self.assertEqual(kids[0]["src"], "agent:trace")

    def test_depth_counts_from_the_parent_not_from_zero(self):
        deep = records.record("hypothesis",
                              {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
                               "confidence": 0.6, "evidence": [self.flow["id"]], "depth": 2},
                              "agent:trace")
        store.append([deep], self.log)
        r = self.run_admit(self.rev(parent=deep["id"]))
        self.assertEqual(r.returncode, 0, r.stderr)
        kid = [h for h in self.records_of("hypothesis") if h.get("parent") == deep["id"]][0]
        self.assertEqual(kid["depth"], 3)

    def test_an_unknown_parent_is_rejected(self):
        r = self.run_admit(self.rev(parent="h_nope"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("parent", r.stderr)

    def test_a_parent_that_is_not_a_hypothesis_is_rejected(self):
        r = self.run_admit(self.rev(parent=self.flow["id"]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a hypothesis", r.stderr)

    def test_a_verdict_becomes_a_belief(self):
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape:S(S)", "verdict": "unsound",
             "rationale": "it replaces x with y, which the narrative's attack does not use"}]))
        self.assertEqual(r.returncode, 0, r.stderr)
        beliefs = self.records_of("belief")
        self.assertEqual(len(beliefs), 1)
        self.assertEqual(beliefs[0]["subject"], "p.Helper.escape:S(S)")
        self.assertEqual(beliefs[0]["predicate"], "sanitizes")
        self.assertEqual(beliefs[0]["object"], "sqli")
        self.assertEqual(beliefs[0]["verdict"], "unsound")
        self.assertEqual(beliefs[0]["audited_by"], "agent:trace")

    def test_a_verdict_may_name_the_method_without_its_signature(self):
        """Observed live: a verdict on `...SqlInjectionLesson6a.unionQueryChecker`
        against a fact whose full_name ends `:boolean(java.lang.String)`. The model
        read the right method and named it the short way — formatting, not
        comprehension, and the same answer as the class title."""
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape", "verdict": "unsound",
             "rationale": "it only replaces x with y"}]))
        self.assertEqual(r.returncode, 0, r.stderr)
        beliefs = self.records_of("belief")
        # Normalised: the store keys on the subject, so a short form surviving into
        # the log would never match the fact it was argued from.
        self.assertEqual(beliefs[0]["subject"], "p.Helper.escape:S(S)")

    def test_an_ambiguous_short_name_is_refused(self):
        """Two overloads read: the signature is the only thing separating them, so
        the short form genuinely does not pick one."""
        other = records.fact(
            {"kind": "callee_body", "full_name": "p.Helper.escape:S(S,int)",
             "status": "resolved", "name": "escape", "body": "..."}, "cpg:callee_body")
        store.append([other], self.log)
        r = self.run_admit(self.rev(
            evidence=[self.flow["id"], self.body["id"], other["id"]],
            verdicts=[{"subject": "p.Helper.escape", "verdict": "unsound",
                       "rationale": "r"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("2 overloads", r.stderr)

    def test_a_verdict_about_a_method_that_was_not_read_is_rejected(self):
        """The failure this whole leg was built to end: a trust decision about code
        nobody looked at. It would be believed by every later run."""
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Other.unseen:S(S)", "verdict": "unsound", "rationale": "looks bad"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nobody read", r.stderr)

    def test_a_verdict_on_an_unread_body_is_rejected_even_though_the_stub_exists(self):
        """`external_stub` means the signature was known and the body was not. Reading
        that as grounds for a verdict is the gap-as-acquittal the prompt warns about,
        and it is the subtler half of the same bug."""
        r = self.run_admit(self.rev(
            evidence=[self.flow["id"], self.stub["id"]],
            verdicts=[{"subject": "java.sql.Statement.executeQuery:R(S)", "verdict": "unsound",
                       "rationale": "the JDBC driver handles it"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a trust decision", r.stderr)

    def test_the_pruning_verdict_needs_a_dynamic_tier(self):
        """`sound` is the mirror of `confirmed` and the only verdict that PRUNES, so a
        wrong one removes a live vulnerability from every future run. Observed live:
        a trace filed `sound` on a method whose own rationale said it "does not
        contain any logic that would prevent SQL injection"."""
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape:S(S)", "verdict": "sound",
             "rationale": "it escapes quotes"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("requires a dynamic verification tier", r.stderr)
        self.assertEqual(self.records_of("belief"), [])

    def test_the_pruning_verdict_is_allowed_in_a_dynamic_run(self):
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape:S(S)", "verdict": "sound",
             "rationale": "a payload was driven through it and did not reach"}]),
            extra=("--dynamic",))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.records_of("belief")[0]["verdict"], "sound")

    def test_an_unknown_verdict_is_rejected(self):
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape:S(S)", "verdict": "probably_fine", "rationale": "r"}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown verdict", r.stderr)

    def test_a_verdict_without_a_rationale_is_rejected(self):
        """A verdict with no stated reason cannot be audited later, and this record is
        precisely what stops the system re-litigating a sanitizer on every run."""
        r = self.run_admit(self.rev(verdicts=[
            {"subject": "p.Helper.escape:S(S)", "verdict": "unsound", "rationale": ""}]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("rationale", r.stderr)

    def test_two_verdicts_on_one_subject_are_rejected(self):
        v = {"subject": "p.Helper.escape:S(S)", "verdict": "unsound", "rationale": "r"}
        r = self.run_admit(self.rev(verdicts=[v, dict(v, verdict="partial")]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("two verdicts", r.stderr)

    def test_a_second_revision_of_one_parent_is_refused(self):
        """v1 revises one case into one child, so `revised_hypotheses` can treat
        "is a parent" as "is history". A fork makes that projection wrong in a way
        nothing reports: the site appears twice in every report and scorecard and
        neither copy is marked as the other's sibling."""
        self.assertEqual(self.run_admit(self.rev()).returncode, 0)
        r = self.run_admit(self.rev(statement="a different revision"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already has a revision", r.stderr)

    def test_two_revisions_of_one_parent_in_one_batch_are_refused(self):
        """The log snapshot predates the batch, so both would pass a check made
        against it alone."""
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.admit", "--type", "trace",
             "--class", "sqli", "--lang", "java", "--src", "agent:trace"],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
            input=json.dumps(self.rev()) + "\n" + json.dumps(self.rev(statement="b")))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already has a revision", r.stderr)
        self.assertEqual([h for h in self.records_of("hypothesis") if h.get("parent")], [])

    def test_a_revision_that_drops_the_site_anchor_is_refused(self):
        """`score` and `render` locate a hypothesis from its evidence facts, and a
        callee_body carries `file` but no `line`. A revision citing only bodies
        resolves to no site: dropped as unlabelled by the scorecard, headed `?` in
        the report, and perfectly well-formed on the way in."""
        r = self.run_admit(self.rev(evidence=[self.body["id"]]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("locates a sink site", r.stderr)

    def test_a_revision_may_not_move_to_another_case(self):
        other = records.fact(
            {"kind": "flow", "subject": "p.D.h:R(S)", "object": "p.D.q:R(S)",
             "sink_file": "B.java", "sink_line": 99}, "cpg:reachable")
        store.append([other], self.log)
        r = self.run_admit(self.rev(evidence=[other["id"], self.body["id"]]))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not move to another", r.stderr)

    def test_hallucinated_evidence_is_still_rejected(self):
        r = self.run_admit(self.rev(evidence=["f_" + "0" * 24]))
        self.assertNotEqual(r.returncode, 0)

    def test_confirmed_is_still_impossible(self):
        r = self.run_admit(self.rev(status="confirmed"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("dynamic", r.stderr)

    def test_a_rejected_revision_writes_nothing_at_all(self):
        """Whole or nothing: a revision that half-landed would leave a child with no
        belief, or a belief with no child, and the tree would lie about its own depth."""
        before = len(list(store.read(self.log)))
        self.run_admit(self.rev(verdicts=[
            {"subject": "p.Other.unseen:S(S)", "verdict": "unsound", "rationale": "r"}]))
        self.assertEqual(len(list(store.read(self.log))), before)


class TestATracedLogIsReadCorrectlyDownstream(unittest.TestCase):
    """A second level does not just add records — it changes what "the hypotheses"
    means. Everything that reads them has to mean the leaf, or one site is counted
    once per level it was traced through."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.env = dict(os.environ, SOURCE_ANALYST_LOG=str(self.log))
        flow = records.fact(
            {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.C.q:R(S)",
             "source_name": "q", "source_file": "A.java", "source_line": 10,
             "sink_name": "executeQuery", "sink_file": "A.java", "sink_line": 20,
             "sink_full_name": "java.sql.Statement.executeQuery:R(S)",
             "steps": []}, "cpg:reachable")
        root = records.record("hypothesis",
                              {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
                               "confidence": 0.6, "evidence": [flow["id"]]}, "agent:hypothesize")
        child = records.record("hypothesis",
                               {"statement": "s2", "vuln_class": "sqli", "status": "needs_proof",
                                "confidence": 0.8, "evidence": [flow["id"]],
                                "parent": root["id"], "depth": 1}, "agent:trace")
        store.append([flow, root, child], self.log)
        self.root, self.child = root, child

    def test_report_is_briefed_on_the_leaf_not_the_whole_chain(self):
        """Measured on WebGoat: 23 sites, 46 rows. Every site written up once per
        level, and the report reads as though the substrate found twice what it did."""
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--agent", "report",
             "--class", "sqli", "--lang", "java", "--status", "needs_proof"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [json.loads(x) for x in r.stdout.splitlines()
                if json.loads(x).get("kind") == "hypothesis"]
        self.assertEqual([row["hypothesis"]["id"] for row in rows], [self.child["id"]])


    def _render(self):
        return subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render",
             "--class", "sqli", "--target", "t"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)

    def test_a_traced_finding_says_what_was_read(self):
        """If the loop read a method and the report does not say so, a reader cannot
        tell a judgement made from the code from one made from the call site alone —
        which is the only distinction this leg exists to create."""
        body = records.fact({"kind": "callee_body", "full_name": "p.Helper.escape:S(S)",
                             "status": "resolved", "name": "escape", "body": "..."},
                            "cpg:callee_body")
        traced = records.record("hypothesis",
                                {"statement": "s3", "vuln_class": "sqli",
                                 "status": "needs_proof", "confidence": 0.9,
                                 "evidence": [body["id"]], "parent": self.child["id"],
                                 "depth": 2, "basis": "the escape only handles quotes",
                                 "read": ["p.Helper.escape:S(S)"]}, "agent:trace")
        finding = records.record("finding",
                                 {"hypothesis": traced["id"], "title": "t", "severity": "high",
                                  "tier": "static_reachability", "recreation": "r",
                                  "refs": ["A.java:20"], "caveats": "c"}, "agent:report")
        store.append([body, traced, finding], self.log)
        out = self._render().stdout
        self.assertIn("Traced to depth 2", out)
        self.assertIn("p.Helper.escape", out)
        self.assertIn("the escape only handles quotes", out)

    def test_a_trace_level_that_read_nothing_says_so(self):
        """A level whose callees were all outside the tree must not read like one that
        examined everything and found nothing wrong. That is the gap-as-acquittal
        failure, arriving through the report instead of through a verdict."""
        stub = records.fact({"kind": "callee_body", "full_name": "java.sql.Statement.x:R()",
                             "status": "external_stub", "name": "x", "body": ""},
                            "cpg:callee_body")
        traced = records.record("hypothesis",
                                {"statement": "s3", "vuln_class": "sqli",
                                 "status": "needs_proof", "confidence": 0.9,
                                 "evidence": [stub["id"]], "parent": self.child["id"],
                                 "depth": 2, "basis": "nothing could be established",
                                 "read": []}, "agent:trace")
        finding = records.record("finding",
                                 {"hypothesis": traced["id"], "title": "t", "severity": "high",
                                  "tier": "static_reachability", "recreation": "r",
                                  "refs": ["A.java:20"], "caveats": "c"}, "agent:report")
        store.append([stub, traced, finding], self.log)
        out = self._render().stdout
        self.assertIn("No callee body on this path could be read", out)
        self.assertIn("outside the analysed tree", out)

    def test_an_untraced_finding_claims_no_depth(self):
        finding = records.record("finding",
                                 {"hypothesis": self.root["id"], "title": "t",
                                  "severity": "high", "tier": "static_reachability",
                                  "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                                 "agent:report")
        store.append([finding], self.log)
        self.assertNotIn("Traced to depth", self._render().stdout)

    def test_the_report_leg_does_not_rewrite_what_it_already_wrote(self):
        """Unlike `trace`, this leg is not self-consuming — a finding does not remove
        its hypothesis from the selection. A pass that died halfway used to re-brief
        everything and write a SECOND finding for every case it had already done, and
        findings are ULID events so nothing dedupes them."""
        done = records.record("finding",
                              {"hypothesis": self.child["id"], "title": "already written",
                               "severity": "high", "tier": "static_reachability",
                               "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                              "agent:report")
        store.append([done], self.log)
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.brief", "--agent", "report",
             "--class", "sqli", "--lang", "java", "--status", "needs_proof"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [json.loads(x) for x in r.stdout.splitlines()
                if json.loads(x).get("kind") == "hypothesis"]
        self.assertEqual(rows, [], "the only hypothesis has a finding already")

    def test_a_finding_about_a_revised_hypothesis_is_not_rendered_twice(self):
        """A finding is a write-up OF a hypothesis. Re-running the report leg after a
        trace level writes a second one for the same site; rendering both puts it in
        the report twice, once with the superseded confidence."""
        old_f = records.record("finding",
                               {"hypothesis": self.root["id"], "title": "stale write-up",
                                "severity": "high", "tier": "static_reachability",
                                "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                               "agent:report")
        new_f = records.record("finding",
                               {"hypothesis": self.child["id"], "title": "current write-up",
                                "severity": "high", "tier": "static_reachability",
                                "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                               "agent:report")
        store.append([old_f, new_f], self.log)
        out = self._render().stdout
        self.assertIn("current write-up", out)
        self.assertNotIn("stale write-up", out)
        self.assertIn("1 finding(s)", out)

    def test_what_was_superseded_is_stated_not_silently_dropped(self):
        """A report quietly shorter than the log is its own kind of lie."""
        stale_f = records.record("finding",
                                 {"hypothesis": self.root["id"], "title": "t",
                                  "severity": "high", "tier": "static_reachability",
                                  "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                                 "agent:report")
        store.append([stale_f], self.log)
        out = self._render().stdout
        self.assertIn("superseded by a later `trace` level", out)
        self.assertIn("**1** hypothesis/es", out)
        self.assertIn("**1** finding(s)", out)

    def test_supersession_is_stated_on_a_report_that_has_findings_too(self):
        """The zero-findings branch is precisely the reader who does not need this.
        Someone holding 21 findings off a log containing 23 is the one entitled to
        know why two are missing."""
        stale_f = records.record("finding",
                                 {"hypothesis": self.root["id"], "title": "stale",
                                  "severity": "high", "tier": "static_reachability",
                                  "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                                 "agent:report")
        live_f = records.record("finding",
                                {"hypothesis": self.child["id"], "title": "current",
                                 "severity": "high", "tier": "static_reachability",
                                 "recreation": "r", "refs": ["A.java:20"], "caveats": "c"},
                                "agent:report")
        store.append([stale_f, live_f], self.log)
        out = self._render().stdout
        self.assertIn("current", out)
        self.assertIn("superseded by a later `trace` level", out)
        self.assertIn("as it now stands", out)

    def test_render_counts_a_revised_case_once(self):
        """Counting the whole chain inflates every status tally in the summary, and
        would make "every candidate was refuted" fire on a set that is mostly its own
        history."""
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.render",
             "--class", "sqli", "--target", "t"],
            cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("hypotheses: **1**", r.stdout)
        self.assertIn("1 needs_proof", r.stdout)
        self.assertNotIn("hypotheses: **2**", r.stdout)


if __name__ == "__main__":
    unittest.main()
