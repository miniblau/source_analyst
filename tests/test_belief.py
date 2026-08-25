"""Append-only log and belief projection (§5, §10.4).

Pure deterministic core: no Joern, no opengrep, no LLM.
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

ROOT = Path(__file__).resolve().parents[1]


def mk(subject="s", predicate="sanitizes", object_="sqli", verdict="sound",
       rationale="because", audited_by="trace"):
    return records.belief(subject, predicate, object_, verdict, rationale, audited_by)


class TestUlid(unittest.TestCase):
    def test_shape(self):
        u = records.ulid()
        self.assertEqual(len(u), 26)
        self.assertTrue(set(u) <= set(records.CROCKFORD), u)

    def test_time_sortable_in_mint_order(self):
        """§10.4 calls these time-sortable; a burst inside one millisecond must
        not shuffle."""
        got = [records.ulid() for _ in range(500)]
        self.assertEqual(got, sorted(got))
        self.assertEqual(len(set(got)), len(got))


class TestRecords(unittest.TestCase):
    def test_belief_envelope(self):
        b = mk()
        for k in ("v", "type", "id", "ts", "src"):
            self.assertIn(k, b)
        self.assertEqual(b["type"], "belief")
        self.assertTrue(b["id"].startswith("b_"))
        self.assertEqual(b["src"], "belief:trace")

    def test_belief_ids_are_not_content_hashes(self):
        """Asserting the same belief twice is two decisions, not one fact.
        Collapsing them would erase the audit trail."""
        self.assertNotEqual(mk()["id"], mk()["id"])

    def test_rationale_is_mandatory(self):
        for bad in ("", "   "):
            with self.assertRaises(ValueError):
                mk(rationale=bad)

    def test_payload_cannot_forge_envelope(self):
        with self.assertRaises(ValueError):
            records.record("belief", {"id": "b_forged"}, src="belief:x")


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "log.jsonl"
        self.addCleanup(self.tmp.cleanup)

    def test_latest_wins_on_subject_predicate_object(self):
        store.append([mk(verdict="sound"), mk(verdict="unsound")], self.log)
        live = store.project(self.log)
        self.assertEqual(len(live), 1)
        self.assertEqual(next(iter(live.values()))["verdict"], "unsound")
        self.assertEqual(store.superseded(self.log)[("s", "sanitizes", "sqli")], 1)

    def test_different_keys_do_not_collide(self):
        store.append([mk(object_="sqli"), mk(object_="xss"), mk(subject="other")], self.log)
        self.assertEqual(len(store.project(self.log)), 3)

    def test_latest_wins_is_log_order_not_timestamp(self):
        """A clock that jumps backwards, or two verdicts in the same
        millisecond, must not resurrect a superseded belief."""
        first, second = mk(verdict="sound"), mk(verdict="unsound")
        second["ts"] = "2000-01-01T00:00:00Z"      # older than the record it supersedes
        second["id"] = "b_" + "0" * 26            # and sorts earlier too
        store.append([first, second], self.log)
        self.assertEqual(next(iter(store.project(self.log).values()))["verdict"], "unsound")

    def test_projection_is_rebuildable_from_the_log(self):
        store.append([mk(verdict="sound"), mk(verdict="partial"), mk(subject="t")], self.log)
        copy = Path(self.tmp.name) / "copy.jsonl"
        copy.write_text(self.log.read_text())
        self.assertEqual(store.project(self.log), store.project(copy))

    def test_facts_are_idempotent_beliefs_are_not(self):
        fact = records.fact({"kind": "sink_candidate", "file": "A.java"}, "cpg:sql_sinks")
        self.assertEqual(store.append([fact], self.log), (1, 0))
        self.assertEqual(store.append([fact], self.log), (0, 1))
        self.assertEqual(store.append([mk(), mk()], self.log), (2, 0))

    def test_unknown_verdict_rejected(self):
        bad = mk()
        bad["verdict"] = "probably_fine"
        with self.assertRaises(store.LogError):
            store.append([bad], self.log)
        self.assertFalse(self.log.exists(), "a rejected batch must not be partially written")

    def test_missing_envelope_rejected(self):
        rec = mk()
        del rec["src"]
        with self.assertRaises(store.LogError):
            store.append([rec], self.log)

    def test_malformed_log_line_is_fatal_not_skipped(self):
        """A log that silently drops junk is not one anything can be rebuilt
        from, and a dropped belief is a resurrected verdict."""
        self.log.write_text('{"v":1,"type":"belief"}\nnot json\n')
        with self.assertRaises(store.LogError):
            list(store.read(self.log))

    def test_absent_log_projects_empty(self):
        self.assertEqual(store.project(self.log), {})


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = dict(os.environ,
                        SOURCE_ANALYST_LOG=str(Path(self.tmp.name) / "log.jsonl"))
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *argv):
        return subprocess.run([sys.executable, "-m", "source_analyst.belief.cli", *argv],
                              cwd=ROOT, env=self.env, capture_output=True, text=True)

    def assert_one(self, verdict="sound", by="trace"):
        return self.run_cli("assert", "--subject", "isAllowedUrl", "--predicate", "sanitizes",
                            "--object", "ssrf", "--verdict", verdict,
                            "--rationale", "host allowlist, no redirect follow",
                            "--audited-by", by)

    def test_assert_then_get(self):
        self.assertEqual(self.assert_one().returncode, 0)
        got = self.run_cli("get", "--subject", "isAllowedUrl",
                           "--predicate", "sanitizes", "--object", "ssrf")
        self.assertEqual(got.returncode, 0)
        self.assertEqual(json.loads(got.stdout)["verdict"], "sound")

    def test_get_missing_exits_nonzero(self):
        """`no belief recorded` and `belief says no` are different answers."""
        got = self.run_cli("get", "--subject", "nope", "--predicate", "p", "--object", "o")
        self.assertEqual(got.returncode, 1)
        self.assertEqual(got.stdout.strip(), "")
        self.assertFalse(json.loads(got.stderr.strip().splitlines()[-1])["found"])

    def test_supersede_is_reported_not_silent(self):
        self.assert_one(verdict="sound")
        second = self.assert_one(verdict="unsound", by="human")
        meta = json.loads(second.stderr.strip().splitlines()[-1])
        self.assertEqual(meta["superseded"]["verdict"], "sound")
        proj = self.run_cli("project")
        rec = json.loads(proj.stdout.strip())
        self.assertEqual(rec["verdict"], "unsound")
        self.assertEqual(rec["superseded_count"], 1)
        # both decisions survive in the log
        self.assertEqual(len(self.run_cli("log", "--type", "belief").stdout.splitlines()), 2)

    def test_unknown_verdict_rejected_at_the_cli(self):
        r = self.run_cli("assert", "--subject", "s", "--predicate", "p", "--object", "o",
                         "--verdict", "looks_ok", "--rationale", "r", "--audited-by", "me")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unknown verdict", r.stderr)

    def test_append_accepts_facts_and_dedupes(self):
        fact = records.fact({"kind": "flow", "sink_file": "A.java"}, "cpg:reachable")
        line = json.dumps(fact) + "\n"
        first = subprocess.run(
            [sys.executable, "-m", "source_analyst.belief.cli", "append"],
            cwd=ROOT, env=self.env, input=line, capture_output=True, text=True)
        self.assertEqual(json.loads(first.stderr.strip().splitlines()[-1])["written"], 1)
        again = subprocess.run(
            [sys.executable, "-m", "source_analyst.belief.cli", "append"],
            cwd=ROOT, env=self.env, input=line, capture_output=True, text=True)
        meta = json.loads(again.stderr.strip().splitlines()[-1])
        self.assertEqual((meta["written"], meta["duplicate_facts"]), (0, 1))

    def test_append_rejects_a_bad_record_without_writing_the_batch(self):
        good = json.dumps(records.fact({"kind": "flow"}, "cpg:reachable"))
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.belief.cli", "append"],
            cwd=ROOT, env=self.env, input=good + '\n{"type":"belief"}\n',
            capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.run_cli("log").stdout.strip(), "",
                         "a batch with a bad record must write nothing")

    def test_verdict_vocabulary_is_data(self):
        r = self.run_cli("verdicts")
        vocab = json.loads(r.stdout)["verdicts"]
        self.assertIn("unsound", vocab)
        self.assertFalse(vocab["unsound"]["prunes"])
        self.assertTrue(vocab["sound"]["prunes"])


if __name__ == "__main__":
    unittest.main()
