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
