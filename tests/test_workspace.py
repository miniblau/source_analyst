"""Cache identity tests (§10.5). No Joern, no LLM."""

import os
import base64
import stat
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from source_analyst.cpg import workspace


class TestSourceHash(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.java").write_text("class A {}\n")
        (self.root / "b.java").write_text("class B {}\n")
        self.addCleanup(self.tmp.cleanup)

    def test_deterministic(self):
        self.assertEqual(workspace.source_hash(self.root), workspace.source_hash(self.root))

    def test_content_change_invalidates(self):
        before = workspace.source_hash(self.root)
        (self.root / "b.java").write_text("class B { int x; }\n")
        self.assertNotEqual(before, workspace.source_hash(self.root))

    def test_rename_invalidates(self):
        before = workspace.source_hash(self.root)
        (self.root / "b.java").rename(self.root / "c.java")
        self.assertNotEqual(before, workspace.source_hash(self.root))

    def test_mtime_alone_does_not_invalidate(self):
        before = workspace.source_hash(self.root)
        os.utime(self.root / "b.java", (0, 0))
        self.assertEqual(before, workspace.source_hash(self.root), "cache keys on content, not mtime")

    def test_git_metadata_ignored(self):
        before = workspace.source_hash(self.root)
        (self.root / ".git").mkdir()
        (self.root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        self.assertEqual(before, workspace.source_hash(self.root))

    def test_symlink_recorded_not_followed(self):
        before = workspace.source_hash(self.root)
        (self.root / "link.java").symlink_to(self.root / "b.java")
        self.assertNotEqual(before, workspace.source_hash(self.root))

    def test_workspace_paths_derive_from_hash(self):
        ws = workspace.Workspace.of(self.root)
        self.assertTrue(ws.root.name.startswith(ws.source_hash[: workspace.KEY_LEN]))
        self.assertFalse(ws.is_built())


if __name__ == "__main__":
    unittest.main()


class TestPrivateArtefacts(unittest.TestCase):
    """This tool ingests client source and writes it back out — the log holds code
    excerpts and a transcript holds a whole briefing verbatim. Default 0644 makes
    that readable by every account on the box."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def test_private_dir_is_owner_only(self):
        from source_analyst.cpg.workspace import private_dir
        p = private_dir(self.d / "a" / "b")
        self.assertTrue(p.is_dir())
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)

    def test_private_file_is_owner_only(self):
        from source_analyst.cpg.workspace import private_file
        f = self.d / "x.txt"
        f.write_text("secret")
        private_file(f)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)

    def test_the_log_is_created_owner_only(self):
        from source_analyst import records
        from source_analyst.belief import store
        log = self.d / "nested" / "log.jsonl"
        store.append([records.fact({"kind": "x"}, "test")], log)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(log.parent.stat().st_mode), 0o700)


class TestServerAuth(unittest.TestCase):
    """The CPGQL server evaluates arbitrary Scala, so an unauthenticated one is a
    local RCE endpoint open for the length of a review. Verified against a live
    server: 401 without the credential, 200 with it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def ws(self):
        from source_analyst.cpg.workspace import Workspace
        return Workspace(src=Path(self.tmp.name), source_hash="h" * 64,
                         root=Path(self.tmp.name) / "cpg")

    def test_credential_is_random_and_owner_only(self):
        from source_analyst.cpg import server
        ws = self.ws()
        a, b = server._new_auth(ws), server._new_auth(ws)
        self.assertNotEqual(a, b, "a fixed credential is not a credential")
        self.assertGreaterEqual(len(a), 32)
        self.assertEqual(stat.S_IMODE(server._auth_file(ws).stat().st_mode), 0o600)

    def test_credential_round_trips(self):
        from source_analyst.cpg import server
        ws = self.ws()
        self.assertIsNone(server._read_auth(ws))
        secret = server._new_auth(ws)
        self.assertEqual(server._read_auth(ws), secret)

    def test_post_sends_basic_auth_only_when_a_secret_exists(self):
        """A server started before this credential existed, or by hand, must keep
        working — Joern ignores a header it did not ask for."""
        from source_analyst.cpg import server
        seen = {}

        class FakeResp:
            def read(self): return b"{}"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=None):
            seen["headers"] = dict(req.headers)
            return FakeResp()

        with unittest.mock.patch.object(server.urllib.request, "urlopen", fake_urlopen):
            server._post(1234, "1", timeout=1, secret=None)
            self.assertNotIn("Authorization", seen["headers"])
            server._post(1234, "1", timeout=1, secret="s3cret")
            token = base64.b64encode(b"source_analyst:s3cret").decode()
            self.assertEqual(seen["headers"]["Authorization"], f"Basic {token}")


class TestReapOthers(unittest.TestCase):
    """One CPG server at a time (see server.reap_others). No Joern, no LLM.

    The leak this guards was silent: fifteen servers holding 13.1GB made every
    agent call ~17x slower without failing a single query, so the only way it
    can be caught is a test that counts what is left running.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.var = Path(self.tmp.name)
        (self.var / "cpg").mkdir()
        os.environ["SOURCE_ANALYST_VAR"] = str(self.var)
        self.addCleanup(os.environ.pop, "SOURCE_ANALYST_VAR", None)

    def _ws(self, h: str) -> "workspace.Workspace":
        root = self.var / "cpg" / h
        root.mkdir(exist_ok=True)
        (root / "server.pid").write_text("1\n")
        (root / "server.port").write_text("1234\n")
        return workspace.Workspace(src=Path(h), source_hash=h, root=root)

    def test_reaps_every_other_workspace_but_not_its_own(self):
        from source_analyst.cpg import server

        mine = self._ws("aaaa")
        for h in ("bbbb", "cccc", "dddd"):
            self._ws(h)
        with unittest.mock.patch.object(server, "stop", return_value=True) as stopped:
            reaped = server.reap_others(mine)
        self.assertEqual(sorted(reaped), ["bbbb", "cccc", "dddd"])
        self.assertNotIn("aaaa", reaped)
        self.assertEqual(stopped.call_count, 3)

    def test_reaps_nothing_when_it_is_the_only_workspace(self):
        from source_analyst.cpg import server

        mine = self._ws("aaaa")
        with unittest.mock.patch.object(server, "stop", return_value=True) as stopped:
            self.assertEqual(server.reap_others(mine), [])
        self.assertEqual(stopped.call_count, 0)

    def test_a_workspace_with_no_pid_file_is_not_a_running_server(self):
        from source_analyst.cpg import server

        mine = self._ws("aaaa")
        idle = self.var / "cpg" / "eeee"
        idle.mkdir()  # built but never served
        with unittest.mock.patch.object(server, "stop", return_value=True):
            self.assertEqual(server.reap_others(mine), [])


class TestEmptyCpgIsNotABuild(unittest.TestCase):
    """A frontend that parsed nothing must not produce a cached, successful build.

    Measured 2026-09-04: two Juice Shop `codefixes/*.ts` snippets are spliced
    fragments with one unclosed brace; jssrc2cpg emitted a 4,660-byte CPG holding
    zero files, said nothing on stderr and exited 0. Every later query would then
    answer "0 facts" honestly and the run would read as a clean bill of health for
    code nobody parsed — permanently, because cpg.bin was cached. No Joern here:
    the frontend and the counter are both stubbed, the assertions are about what
    build() leaves on disk.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "ws"
        self.root.mkdir()
        self.ws = workspace.Workspace(src=Path("/src"), source_hash="h" * 64, root=self.root)

    def _build(self, files: int, methods: int = 0):
        from source_analyst.cpg import server

        def fake_run(cmd, **kw):
            (self.root / "cpg.bin.tmp").write_bytes(b"x")
            return unittest.mock.Mock(returncode=0)

        with unittest.mock.patch.object(server.subprocess, "run", fake_run), \
             unittest.mock.patch.object(server, "joern_version", return_value="4.0.0"), \
             unittest.mock.patch.object(server, "is_running", return_value=False), \
             unittest.mock.patch.object(server, "stop", return_value=True), \
             unittest.mock.patch.object(server, "_cpg_counts", return_value=(files, methods)):
            return server.build(self.ws, language="JSSRC")

    def test_zero_files_raises_and_caches_nothing(self):
        with self.assertRaises(SystemExit) as cm:
            self._build(files=0)
        self.assertIn("EMPTY CPG", str(cm.exception))
        self.assertFalse(self.ws.cpg_bin.exists(), "an empty CPG must not be cached")
        self.assertFalse(self.ws.meta_json.exists(), "a failed build must leave no meta")
        self.assertFalse(self.ws.is_built())

    def test_a_real_build_records_what_was_parsed(self):
        self.assertTrue(self._build(files=4, methods=40))
        self.assertTrue(self.ws.is_built())
        meta = self.ws.read_meta()
        self.assertEqual((meta["cpg_files"], meta["cpg_methods"]), (4, 40))

    def test_an_uncountable_cpg_is_a_failure_not_a_zero(self):
        """No marker back means "unknown", and unknown must not be read either way."""
        from source_analyst.cpg import server

        with unittest.mock.patch.object(server, "run_scala", return_value="no marker here"):
            with self.assertRaises(SystemExit) as cm:
                server._cpg_counts(self.ws)
        self.assertIn("must not be assumed", str(cm.exception))

    def test_counts_are_read_from_the_repl_value_echo(self):
        from source_analyst.cpg import server

        echo = 'val res0: String = "CPGCOUNTS 320 2756"\n'
        with unittest.mock.patch.object(server, "run_scala", return_value=echo):
            self.assertEqual(server._cpg_counts(self.ws), (320, 2756))
