"""Cache identity tests (§10.5). No Joern, no LLM."""

import os
import tempfile
import unittest
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
