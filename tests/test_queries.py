"""Named-vocabulary and injection tests (§10.3). No Joern, no LLM."""

import base64
import json
import re
import unittest
from pathlib import Path

from source_analyst.cpg import queries


class TestVocabulary(unittest.TestCase):
    def test_catalog_is_the_queries_dir(self):
        self.assertIn("sql_sinks", queries.available())

    def test_unknown_query_rejected(self):
        with self.assertRaises(SystemExit):
            queries.resolve("no_such_query")

    def test_path_traversal_rejected(self):
        for name in ["../etc/passwd", "a/b", "sql_sinks.sc", "SQL_SINKS", "a;b"]:
            with self.assertRaises(SystemExit, msg=name):
                queries.resolve(name)


class TestPrelude(unittest.TestCase):
    def test_params_survive_hostile_strings(self):
        """Patterns come from data files; no quoting in them may reach Scala source."""
        nasty = {"sinks": ['"""; System.exit(1); val x = """', "back\\slash", 'q"uote', "nl\nnl"]}
        code = queries.prelude(Path("/tmp/out.json"), nasty)
        for value in nasty["sinks"]:
            self.assertNotIn(value, code, "raw param text must not be inlined into Scala")
        blob = re.search(r'decode\("([^"]+)"\)', code).group(1)
        self.assertEqual(json.loads(base64.b64decode(blob).decode()), nasty)

    def test_injected_contract_is_present(self):
        code = queries.source("sql_sinks", Path("/tmp/out.json"), {"sinks": ["executeQuery"]})
        for binding in ["val outFile", "val params", "def strList", "def str", "def emit"]:
            self.assertIn(binding, code)
        self.assertIn("sql_sinks", code)

    def test_out_file_path_is_escaped(self):
        code = queries.prelude(Path('/tmp/we"ird/out.json'), {})
        self.assertIn(r'\"', code)


class TestResultParsing(unittest.TestCase):
    def test_reads_rows_and_meta(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"rows": [{"kind": "sink_candidate"}], "meta": {"cpg_calls": 3}}, fh)
            path = Path(fh.name)
        rows, meta = queries.read_result(path)
        self.assertEqual(rows, [{"kind": "sink_candidate"}])
        self.assertEqual(meta, {"cpg_calls": 3})
        path.unlink()


if __name__ == "__main__":
    unittest.main()
