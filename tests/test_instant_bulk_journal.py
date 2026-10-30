"""Bounded Instant Lock logging with durable custody and crash recovery."""

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import crypto_engine as ce
import safe_fs


@unittest.skipUnless(os.name == "nt", "Requires native Windows sharing semantics")
class InstantBulkJournalTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="flock_bulk_journal_")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name) / "protected"
        self.sub = self.root / "s"
        self.sub.mkdir(parents=True)
        self.photo = self.sub / "photo.jpg"
        self.photo.write_bytes(b"synthetic photo")
        (self.sub / "notes.txt").write_bytes(b"synthetic notes")
        (self.sub / "empty").mkdir()
        self.password = "Synthetic-Bulk-Journal!"
        self.addCleanup(self.remove_deny)

    def remove_deny(self):
        container = self.root / ce.INSTANT_DATA_DIRNAME
        if container.exists():
            safe_fs.run_icacls_safe([str(container), "/remove:d", "*S-1-1-0"])

    def open_reader(self):
        handle = safe_fs._CreateFileW(str(self.photo), safe_fs.GENERIC_READ, 7, None, 3, 0, None)
        self.assertNotEqual(handle, safe_fs.INVALID_HANDLE_VALUE, ctypes.get_last_error())
        self.addCleanup(safe_fs._CloseHandle, handle)

    def test_complete_recursive_intent_is_on_disk_before_any_entry_moves(self):
        self.open_reader()
        original = ce.move_no_replace
        checked = []

        def inspect_then_move(src, dst):
            # The first atomic directory attempt may fail without changing
            # anything; the plan must already be durable even for that attempt.
            journal = safe_fs.read_verified_json(str(self.root / ce.INSTANT_JOURNAL_FILENAME))
            plan = journal["move_plan"]
            self.assertEqual(plan["source"], str(self.root))
            self.assertEqual(plan["destination"], str(self.root / ce.INSTANT_DATA_DIRNAME))
            self.assertIn("s", plan["items"])
            self.assertTrue(plan["recursive"])
            self.assertTrue(plan["no_replace"])
            self.assertEqual(journal["state"], "MOVING_ITEMS")
            checked.append(src)
            return original(src, dst)

        with patch.object(ce, "move_no_replace", side_effect=inspect_then_move):
            ce.lock_folder_instant(str(self.root), self.password)
        self.assertGreater(len(checked), 1)
        ce.unlock_folder_instant(str(self.root), self.password)
        self.assertEqual(self.photo.read_bytes(), b"synthetic photo")

    def test_journal_io_remains_small_for_nested_and_top_level_files(self):
        # Cover both the new directory fallback and the older top-level loop.
        for index in range(128):
            (self.sub / f"nested_{index:04}.bin").write_bytes(b"data")
            (self.root / f"flat_{index:04}.bin").write_bytes(b"data")
        self.open_reader()
        sizes = []
        original = ce.TransactionJournal.save

        def save(journal):
            result = original(journal)
            sizes.append(os.path.getsize(journal.journal_path))
            return result

        with patch.object(ce.TransactionJournal, "save", save):
            ce.lock_folder_instant(str(self.root), self.password)
        self.assertLessEqual(len(sizes), 5, "Checkpoint count must not grow per file")
        self.assertLess(sum(sizes), 64 * 1024, "Small fixtures must not generate megabytes of log writes")
        self.assertLess(max(sizes), 32 * 1024)
        ce.unlock_folder_instant(str(self.root), self.password)
        self.assertEqual(len(list(self.sub.glob("nested_*.bin"))), 128)
        self.assertEqual(len(list(self.root.glob("flat_*.bin"))), 128)

    def test_plan_write_failure_moves_no_user_data(self):
        original = ce.atomic_write_json
        attempted_moves = []

        def fail_plan(path, data, **kwargs):
            if data.get("move_plan"):
                raise OSError("Synthetic write-ahead storage failure")
            return original(path, data, **kwargs)

        with patch.object(ce, "atomic_write_json", side_effect=fail_plan), \
                patch.object(ce, "move_no_replace", side_effect=lambda *args: attempted_moves.append(args)):
            with self.assertRaises(OSError):
                ce.lock_folder_instant(str(self.root), self.password)
        self.assertFalse(attempted_moves)
        self.assertEqual(self.photo.read_bytes(), b"synthetic photo")
        self.assertEqual((self.sub / "notes.txt").read_bytes(), b"synthetic notes")
        ok, message = ce.recover_instant_folder(str(self.root), self.password)
        self.assertTrue(ok, message)

    def test_failed_final_checkpoint_keeps_authenticated_data_recoverable(self):
        self.open_reader()
        original = ce.atomic_write_json

        def fail_commit(path, data, **kwargs):
            if data.get("operation_type") == "instant_lock" and data.get("state") == "COMPLETED":
                raise OSError("Synthetic final checkpoint failure")
            return original(path, data, **kwargs)

        with patch.object(ce, "atomic_write_json", side_effect=fail_commit):
            with self.assertRaises(OSError):
                ce.lock_folder_instant(str(self.root), self.password)
        self.assertTrue((self.root / ce.INSTANT_DATA_DIRNAME).is_dir())
        journal = ce.TransactionJournal.load(str(self.root / ce.INSTANT_JOURNAL_FILENAME))
        self.assertEqual(journal.data["state"], "MOVING_ITEMS")
        self.assertIn("move_plan", journal.data)
        ok, message = ce.recover_instant_folder(str(self.root), self.password)
        self.assertTrue(ok, message)
        self.assertEqual(self.photo.read_bytes(), b"synthetic photo")

    def test_process_crash_mid_fallback_preserves_every_file_and_password_gate(self):
        expected = {"photo.jpg": b"synthetic photo", "notes.txt": b"synthetic notes"}
        for index in range(12):
            name = f"unique_{index:04}.bin"
            expected[name] = f"synthetic payload {index}".encode()
            (self.sub / name).write_bytes(expected[name])
        code = """
import os,sys
from pathlib import Path
import crypto_engine as ce,safe_fs
root=Path(sys.argv[1]);password=sys.stdin.readline().rstrip('\\r\\n')
handle=safe_fs._CreateFileW(str(root/'s'/'photo.jpg'),safe_fs.GENERIC_READ,7,None,3,0,None)
assert handle!=safe_fs.INVALID_HANDLE_VALUE
original=ce.move_no_replace
count=0
def move_then_crash(src,dst):
    global count
    original(src,dst)
    if os.path.isfile(dst):
        count+=1
        if count==2:os._exit(73)
ce.move_no_replace=move_then_crash
ce.lock_folder_instant(str(root),password)
"""
        child = subprocess.run([sys.executable, "-c", code, str(self.root)],
                               input=self.password + "\n", text=True, capture_output=True,
                               cwd=str(Path(__file__).resolve().parents[1] / "src"), timeout=30)
        self.assertEqual(child.returncode, 73, child.stderr)
        journal = ce.TransactionJournal.load(str(self.root / ce.INSTANT_JOURNAL_FILENAME))
        self.assertTrue(journal.data["move_plan"]["recursive"])
        self.assertEqual(journal.data["state"], "MOVING_ITEMS")
        wrong, _ = ce.recover_instant_folder(str(self.root), "Incorrect synthetic password")
        self.assertFalse(wrong)
        ok, message = ce.recover_instant_folder(str(self.root), self.password)
        self.assertTrue(ok, message)
        found = {}
        for file in self.root.rglob("*"):
            if file.is_file() and file.name in expected:
                self.assertNotIn(file.name, found, "Recovery duplicated a protected file")
                found[file.name] = file.read_bytes()
        self.assertEqual(found, expected)
        self.assertFalse((self.root / ce.INSTANT_DATA_DIRNAME).exists())


if __name__ == "__main__":
    unittest.main()
