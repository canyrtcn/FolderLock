"""Independent FolderLock data-safety regressions (synthetic files ONLY).

Run from the FolderLock repository:
    python -m unittest -v /path/to/FolderLock_external_audit_tests.py
or:
    set FOLDERLOCK_REPO=C:/path/to/FolderLock
    python FolderLock_external_audit_tests.py

Expected against the unaudited local working tree: multiple FAIL results.
A PASS is required for each before release. Never aim these tests at user folders.
"""
import json
import os
import sys
import tempfile
import unittest
import subprocess
from pathlib import Path

repo = os.environ.get("FOLDERLOCK_REPO", os.getcwd())
sys.path.insert(0, repo)

import safe_fs
import crypto_engine


class ExternalAuditRegressions(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="flock_external_audit_")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.target = self.root / "protected"
        self.target.mkdir()
        self.password = "Synthetic-Audit-Password!"

    def test_recovery_must_not_delete_unowned_path(self):
        unrelated = self.root / "unrelated_user_file.txt"
        unrelated.write_text("SYNTHETIC IMPORTANT CONTENT", encoding="utf-8")
        journal = {
            "schema_version": "1.0.3",
            "operation_id": "test-crashed-op",
            "operation_type": "aes_lock",
            "target_path": str(self.target),
            "state": "PREPARING",
            "temp_paths": [str(unrelated)],
            "recovery_required": True,
        }
        (self.target / ".flock_journal").write_text(json.dumps(journal), encoding="utf-8")
        try:
            crypto_engine.recover_aes_folder(str(self.target), self.password)
        except Exception:
            pass  # Refusing untrusted journal is a safe result.
        self.assertTrue(unrelated.exists(), "Recovery deleted an unrelated synthetic file outside the target")
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "SYNTHETIC IMPORTANT CONTENT")

    def test_nested_user_files_named_like_metadata_are_manifested(self):
        nested = self.target / "user_documents"
        nested.mkdir()
        for name in (".flock_journal", ".flock_oplock", ".flock_relock"):
            (nested / name).write_text("SYNTHETIC USER FILE " + name, encoding="utf-8")
        manifest, _, _ = safe_fs.scan_source_tree(str(self.target), crypto_engine.RESERVED_METADATA_NAMES)
        paths = {m["rel_path"].replace("\\", "/") for m in manifest}
        for name in (".flock_journal", ".flock_oplock", ".flock_relock"):
            self.assertIn("user_documents/" + name, paths)

    def test_relock_config_user_file_cannot_be_overwritten(self):
        (self.target / "document.txt").write_text("SYNTHETIC DOCUMENT", encoding="utf-8")
        user_file = self.target / ".flock_relock"
        original = b"SYNTHETIC USER CONFIG - MUST BE PRESERVED"
        user_file.write_bytes(original)
        crypto_engine.lock_folder(str(self.target), self.password)
        crypto_engine.unlock_folder(str(self.target), self.password)
        self.assertEqual(user_file.read_bytes(), original)

    def test_crash_stale_lock_allows_safe_recovery(self):
        (self.target / "document.txt").write_text("SYNTHETIC DOCUMENT", encoding="utf-8")
        crypto_engine.lock_folder(str(self.target), self.password)
        j = crypto_engine.TransactionJournal(
            str(self.target / ".flock_journal"), "crashed-op", "aes_lock", str(self.target)
        )
        j.set_state("SOURCE_CLEANUP")
        j.mark_recovery_required("simulated crash")
        lock_data = {"operation_id": "crashed-op", "operation_type": "aes_lock",
                     "pid": 999999999, "target_path": str(self.target)}
        (self.target / safe_fs.OP_LOCK_FILENAME).write_text(json.dumps(lock_data), encoding="utf-8")
        try:
            result, message = crypto_engine.recover_aes_folder(str(self.target), self.password)
        except Exception as exc:
            self.fail(f"Recovery must have a safe stale-lock path; got {type(exc).__name__}: {exc}")
        self.assertTrue(result, message)
        self.assertEqual((self.target / "document.txt").read_text(encoding="utf-8"), "SYNTHETIC DOCUMENT")

    def test_unlock_must_not_follow_external_directory_link(self):
        protected_sub = self.target / "docs"
        protected_sub.mkdir()
        (protected_sub / "file.txt").write_text("SYNTHETIC SECRET", encoding="utf-8")
        external = self.root / "outside_protected_folder"
        external.mkdir()
        crypto_engine.lock_folder(str(self.target), self.password)
        try:
            os.symlink(str(external), str(protected_sub), target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                self.skipTest("No symlink support")
            proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(protected_sub), str(external)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if proc.returncode != 0:
                self.skipTest("Neither symlink nor junction permitted in test environment")
        try:
            crypto_engine.unlock_folder(str(self.target), self.password)
        except Exception:
            pass  # Safe rejection is acceptable.
        self.assertFalse((external / "file.txt").exists(), "Restore escaped protected directory via link")


if __name__ == "__main__":
    unittest.main(verbosity=2)
