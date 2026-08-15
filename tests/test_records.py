"""Record contract tests (§10.4). No Joern, no LLM."""

import io
import json
import unittest

from source_analyst import records


class TestFact(unittest.TestCase):
    def test_envelope_fields(self):
        f = records.fact({"kind": "calls", "subject": "A.b", "object": "C.d"}, src="cpg:callers")
        for field in ("v", "type", "id", "ts", "src"):
            self.assertIn(field, f)
        self.assertEqual(f["type"], "fact")
        self.assertEqual(f["src"], "cpg:callers")
        self.assertTrue(f["id"].startswith("f_"))

    def test_id_is_content_hash_stable_across_time(self):
        payload = {"kind": "calls", "subject": "A.b", "object": "C.d"}
        a = records.fact(dict(payload), "cpg:callers")
        b = records.fact(dict(payload), "cpg:callers")
        self.assertEqual(a["id"], b["id"])

    def test_id_ignores_key_order(self):
        a = records.fact({"kind": "calls", "subject": "A.b", "object": "C.d"}, "cpg:callers")
        b = records.fact({"object": "C.d", "subject": "A.b", "kind": "calls"}, "cpg:callers")
        self.assertEqual(a["id"], b["id"])

    def test_id_tracks_payload_and_provenance(self):
        base = {"kind": "calls", "subject": "A.b", "object": "C.d"}
        a = records.fact(dict(base), "cpg:callers")
        b = records.fact({**base, "object": "C.e"}, "cpg:callers")
        c = records.fact(dict(base), "cpg:reachable")
        self.assertNotEqual(a["id"], b["id"])
        self.assertNotEqual(a["id"], c["id"], "same claim from a different query is a distinct fact")

    def test_kind_required(self):
        with self.assertRaises(ValueError):
            records.fact({"subject": "A.b"}, "cpg:callers")

    def test_payload_cannot_forge_envelope(self):
        for reserved in ("v", "type", "id", "ts", "src"):
            with self.assertRaises(ValueError):
                records.fact({"kind": "calls", reserved: "x"}, "cpg:callers")

    def test_write_jsonl_is_one_bare_record_per_line(self):
        buf = io.StringIO()
        n = records.write_jsonl(
            [records.fact({"kind": "k", "subject": str(i)}, "cpg:q") for i in range(3)], buf
        )
        lines = buf.getvalue().splitlines()
        self.assertEqual((n, len(lines)), (3, 3))
        for line in lines:
            self.assertEqual(json.loads(line)["type"], "fact")


if __name__ == "__main__":
    unittest.main()
