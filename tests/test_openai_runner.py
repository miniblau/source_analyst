"""The generic OpenAI-compatible runner shim.

Everything here runs against a stdlib HTTP server in-process: no model, no
network, no vendor. What is under test is that the shim is honest about what it
did — in particular that it never quietly falls back to unconstrained output,
because then a scorecard would be measuring a different setup than you think.
"""

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "tools" / "openai_chat.py"

RECORDED: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    status = 200
    content = "hello"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        RECORDED.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        cls = type(self)
        self.send_response(cls.status)
        self.send_header("Content-Type", "application/json")
        payload = (json.dumps({"choices": [{"message": {"content": cls.content}}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 3}})
                   if cls.status == 200 else json.dumps({"error": "no constrained decoding here"}))
        raw = payload.encode()
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


class ShimCase(unittest.TestCase):
    def setUp(self):
        RECORDED.clear()
        Handler.status, Handler.content = 200, "hello"
        self.srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}/v1"
        self.env = dict(os.environ, LLM_BASE_URL=self.base, LLM_MODEL="test-model")

    def run_shim(self, stdin="a briefing\n", extra=(), env=None):
        return subprocess.run([sys.executable, str(SHIM), *extra], input=stdin,
                              capture_output=True, text=True, cwd=ROOT,
                              env=env or self.env, timeout=60)


class TestTransport(ShimCase):
    def test_unconstrained_output_passes_through(self):
        Handler.content = '{"a":1}\n{"b":2}'
        r = self.run_shim()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, '{"a":1}\n{"b":2}\n')

    def test_request_is_deterministic_and_unstreamed(self):
        self.run_shim()
        body = RECORDED[0]["body"]
        self.assertEqual(body["temperature"], 0.0, "a scored run must be repeatable")
        self.assertFalse(body["stream"])
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(RECORDED[0]["path"], "/v1/chat/completions")

    def test_api_key_sent_only_when_set(self):
        self.run_shim()
        self.assertNotIn("Authorization", RECORDED[0]["headers"])
        self.run_shim(env=dict(self.env, LLM_API_KEY="sekrit"))
        self.assertEqual(RECORDED[1]["headers"]["Authorization"], "Bearer sekrit")

    def test_empty_stdin_rejected(self):
        r = self.run_shim(stdin="")
        self.assertEqual(r.returncode, 2)
        self.assertIn("nothing on stdin", r.stderr)

    def test_unreachable_endpoint_is_reported(self):
        r = self.run_shim(env=dict(self.env, LLM_BASE_URL="http://127.0.0.1:1/v1"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot reach", r.stderr)


class TestConstrainedMode(ShimCase):
    SCHEMA = str(ROOT / "config" / "schemas" / "hypothesize.json")

    def test_schema_is_sent_and_records_are_flattened_to_jsonl(self):
        Handler.content = json.dumps({"records": [{"a": 1}, {"b": 2}]})
        r = self.run_shim(extra=["--schema", self.SCHEMA])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, '{"a":1}\n{"b":2}\n')
        fmt = RECORDED[0]["body"]["response_format"]
        self.assertEqual(fmt["type"], "json_schema")
        self.assertIn("records", fmt["json_schema"]["schema"]["properties"])

    def test_rejection_is_not_retried_unconstrained(self):
        """The failure mode that matters: believing output was constrained when it
        was not. Loud failure beats a silent downgrade you would score anyway."""
        Handler.status = 400
        r = self.run_shim(extra=["--schema", self.SCHEMA])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(len(RECORDED), 1, "must not retry")
        self.assertIn("drop --schema", r.stderr)

    def test_missing_schema_file_never_degrades_to_unconstrained(self):
        r = self.run_shim(extra=["--schema", "/nope/missing.json"])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(RECORDED, [], "no request may be sent without the schema it promised")

    def test_unparseable_constrained_output_is_fatal(self):
        Handler.content = "not json at all"
        r = self.run_shim(extra=["--schema", self.SCHEMA])
        self.assertEqual(r.returncode, 2)
        self.assertIn("did not parse", r.stderr)

    def test_meta_says_whether_the_schema_was_used(self):
        Handler.content = json.dumps({"records": []})
        for extra, want in (([], False), (["--schema", self.SCHEMA], True)):
            Handler.content = json.dumps({"records": []}) if extra else "{}"
            r = self.run_shim(extra=extra)
            meta = json.loads([l for l in r.stderr.splitlines() if l.startswith("{")][-1])
            self.assertEqual(meta["schema"], want)


class TestSchemasMatchTheGate(unittest.TestCase):
    """A schema that drifts from `admit` produces output that is well-formed and
    rejected — the most annoying possible failure, and a mechanical one to prevent."""

    def load(self, agent):
        doc = json.loads((ROOT / "config" / "schemas" / f"{agent}.json").read_text())
        return doc["properties"]["records"]["items"]

    def test_hypothesis_schema_requires_what_admit_requires(self):
        from source_analyst.lifecycle.admit import HYPOTHESIS_FIELDS
        required = set(self.load("hypothesize")["required"])
        self.assertTrue(set(HYPOTHESIS_FIELDS) <= required,
                        f"schema is missing {set(HYPOTHESIS_FIELDS) - required}")

    def test_finding_schema_requires_what_admit_requires(self):
        from source_analyst.lifecycle.admit import FINDING_FIELDS
        required = set(self.load("report")["required"])
        self.assertTrue(set(FINDING_FIELDS) <= required,
                        f"schema is missing {set(FINDING_FIELDS) - required}")

    def test_status_enum_is_the_config_vocabulary_minus_the_impossible(self):
        vocab = yaml.safe_load((ROOT / "config" / "hypothesis.yaml").read_text())
        allowed = {k for k, v in vocab.items() if not v["requires_dynamic"]}
        self.assertEqual(set(self.load("hypothesize")["properties"]["status"]["enum"]), allowed,
                         "a status the gate always refuses must not be offerable")

    def test_tier_enum_excludes_tiers_no_static_run_can_reach(self):
        tiers = yaml.safe_load((ROOT / "config" / "tiers.yaml").read_text())
        offered = set(self.load("report")["properties"]["tier"]["enum"])
        self.assertTrue(offered <= set(tiers))
        for tier in offered:
            self.assertLessEqual(tiers[tier]["ordinal"], tiers["static_trace"]["ordinal"],
                                 f"{tier} needs a dynamic run")

    def test_severity_enum_matches_admit(self):
        from source_analyst.lifecycle.admit import SEVERITIES
        self.assertEqual(set(self.load("report")["properties"]["severity"]["enum"]),
                         set(SEVERITIES))

    def test_every_agent_prompt_has_a_schema(self):
        for prompt in sorted((ROOT / "agents").glob("*.md")):
            self.assertTrue((ROOT / "config" / "schemas" / f"{prompt.stem}.json").is_file(),
                            f"no schema for agent {prompt.stem}")


class TestThroughRunAgent(ShimCase):
    """The whole seam over HTTP: run_agent -> shim -> server -> JSONL."""

    def test_run_agent_drives_the_generic_runner(self):
        Handler.content = json.dumps({"records": [
            {"statement": "s", "vuln_class": "sqli", "status": "needs_proof",
             "confidence": 0.4, "evidence": ["f_x"], "case": "A.java:20", "reasoning": "r"}]})
        r = subprocess.run(
            [sys.executable, "-m", "source_analyst.lifecycle.run_agent",
             "--agent", "hypothesize", "--runner", "openai_compat"],
            input='{"kind":"briefing"}\n', capture_output=True, text=True, cwd=ROOT,
            env=self.env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads(r.stdout.strip())
        self.assertEqual(rec["status"], "needs_proof")
        # the model saw the prompt, not just the briefing
        self.assertIn("# hypothesize", RECORDED[0]["body"]["messages"][-1]["content"])


class TestRunnerConfig(unittest.TestCase):
    def test_generic_runner_is_configured_for_every_agent(self):
        from source_analyst.lifecycle import run_agent as ra
        doc = ra.load_runners()
        for agent in ("hypothesize", "report"):
            cmd = ra.build_cmd(doc["runners"]["openai_compat"], agent)
            self.assertIn(f"{agent}.json", cmd[-1])
            self.assertTrue(Path(cmd[-1]).is_file())

    def test_no_endpoint_is_hardcoded_in_the_config(self):
        """Which server answers is environment, not a line in the repo — that is
        what lets the same runner follow you from the desk to work."""
        text = (ROOT / "config" / "runners.yaml").read_text()
        self.assertNotIn("http://127.0.0.1:8080/v1\"", text)


if __name__ == "__main__":
    unittest.main()
