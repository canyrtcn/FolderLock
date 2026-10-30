"""Real Windows handle regressions; every mutation uses synthetic temp folders."""

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch

import crypto_engine as ce
import safe_fs


@unittest.skipUnless(os.name == "nt", "Requires Windows file sharing and NTFS")
class InstantOpenHandleTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="flock_open_handles_"))
        self.root = self.work / "protected"
        self.sub = self.root / "s"
        self.sub.mkdir(parents=True)
        self.photo = self.sub / "a.jpg"
        self.photo.write_bytes(b"synthetic photo" * 100)
        (self.sub / "z.txt").write_bytes(b"synthetic document")
        (self.sub / "empty").mkdir()
        self.password = "Synthetic-Handle-Regression!"

    def tearDown(self):
        container = self.root / ce.INSTANT_DATA_DIRNAME
        if container.exists():
            safe_fs.run_icacls_safe([str(container), "/remove:d", "*S-1-1-0"])
        for directory, _, files in os.walk(self.work):
            for name in files:
                os.chmod(os.path.join(directory, name), 0o666)
        shutil.rmtree(self.work)

    @contextmanager
    def open_handle(self, path=None, access=0x80, share=3):
        handle = safe_fs._CreateFileW(str(path or self.photo), access, share, None, 3, 0, None)
        self.assertNotEqual(handle, safe_fs.INVALID_HANDLE_VALUE, ctypes.get_last_error())
        try:
            yield handle
        finally:
            safe_fs._CloseHandle(handle)

    def assert_restored(self):
        self.assertEqual(self.photo.read_bytes(), b"synthetic photo" * 100)
        self.assertEqual((self.sub / "z.txt").read_bytes(), b"synthetic document")
        self.assertTrue((self.sub / "empty").is_dir())
        self.assertFalse((self.root / ce.INSTANT_DATA_DIRNAME).exists())
        self.assertFalse((self.root / ce.INSTANT_JOURNAL_FILENAME).exists())

    def test_atomic_move_retains_native_error_code(self):
        with self.open_handle():
            with self.assertRaises(PermissionError) as raised:
                safe_fs.move_no_replace(str(self.sub), str(self.work / "moved"))
        self.assertEqual(raised.exception.winerror, 5)
        self.assertEqual(raised.exception.filename, str(self.sub))
        self.assert_restored()

    def test_metadata_handles_allow_lock_unlock_and_relock(self):
        for access in (0, 0x80):
            for share in (3, 7):
                with self.subTest(access=access, share=share), self.open_handle(access=access, share=share):
                    ce.lock_folder_instant(str(self.root), self.password)
                    self.assertFalse(self.sub.exists())
                    self.assertEqual(ce.is_folder_locked(str(self.root)), "instant")
                    ce.unlock_folder_instant(str(self.root), self.password)
                    self.assert_restored()
                    ce.relock_folder(str(self.root))
                    ce.unlock_folder_instant(str(self.root), self.password)
                    self.assert_restored()

    def test_nested_metadata_handle_preserves_directory_metadata_and_streams(self):
        nested = self.sub / "nested"
        nested.mkdir()
        photo = nested / "photo.jpg"
        photo.write_bytes(b"nested photo")
        with open(str(nested) + ":user_stream", "wb") as stream:
            stream.write(b"directory stream must survive")
        safe_fs.add_hidden_system_attributes(str(nested))
        os.utime(nested, ns=(1600000000000000000, 1600000000000000000))
        before = os.stat(nested)
        attrs = safe_fs.get_file_attributes_safe(str(nested))
        sddl = safe_fs.get_security_descriptor_sddl(str(nested))
        with self.open_handle(path=photo):
            ce.lock_folder_instant(str(self.root), self.password)
            ce.unlock_folder_instant(str(self.root), self.password)
        self.assert_restored()
        self.assertEqual(photo.read_bytes(), b"nested photo")
        self.assertEqual(os.stat(nested).st_mtime_ns, before.st_mtime_ns)
        after = os.stat(nested)
        self.assertEqual(getattr(after, "st_birthtime_ns", after.st_ctime_ns),
                         getattr(before, "st_birthtime_ns", before.st_ctime_ns))
        self.assertEqual(safe_fs.get_file_attributes_safe(str(nested)), attrs)
        # Windows can relabel an identical ACE as inherited when moving it
        # between parents; effective permissions must remain identical.
        after_sddl = safe_fs.get_security_descriptor_sddl(str(nested))
        self.assertEqual(after_sddl.replace("ID;", ";").replace("D:AI", "D:"),
                         sddl.replace("ID;", ";").replace("D:AI", "D:"))
        with open(str(nested) + ":user_stream", "rb") as stream:
            self.assertEqual(stream.read(), b"directory stream must survive")

    def test_active_data_reader_fails_and_restores_everything(self):
        for share in (3, 7):
            with self.subTest(share=share), self.open_handle(access=safe_fs.GENERIC_READ, share=share):
                with self.assertRaises(ce.CryptoError) as raised:
                    ce.lock_folder_instant(str(self.root), self.password)
                self.assertIn("File in use", str(raised.exception))
                self.assert_restored()

    def test_failure_after_a_child_move_rolls_back(self):
        real_move = ce.move_no_replace

        def fail_later_file(src, dst):
            if os.path.basename(src) == "z.txt" and ce.INSTANT_DATA_DIRNAME in dst:
                raise PermissionError(13, "Synthetic sharing violation", src, 32, dst)
            return real_move(src, dst)

        with self.open_handle(), patch.object(ce, "move_no_replace", side_effect=fail_later_file):
            with self.assertRaises(ce.CryptoError):
                ce.lock_folder_instant(str(self.root), self.password)
        self.assert_restored()

    def test_failed_rollback_retains_authenticated_recovery_data(self):
        real_move = ce.move_no_replace

        def fail_forward_and_rollback(src, dst):
            if (os.path.basename(src) == "z.txt" and ce.INSTANT_DATA_DIRNAME in dst
                    or os.path.basename(src) == "a.jpg" and ce.INSTANT_DATA_DIRNAME in src):
                raise PermissionError(13, "Synthetic sharing violation", src, 32, dst)
            return real_move(src, dst)

        with self.open_handle(), patch.object(ce, "move_no_replace", side_effect=fail_forward_and_rollback):
            with self.assertRaises(ce.CryptoError) as raised:
                ce.lock_folder_instant(str(self.root), self.password)
        self.assertIn("Recovery required", str(raised.exception))
        container = self.root / ce.INSTANT_DATA_DIRNAME
        self.assertTrue((container / ce.META_FILENAME).is_file())
        journal = ce.TransactionJournal.load(str(self.root / ce.INSTANT_JOURNAL_FILENAME))
        self.assertTrue(journal.data["recovery_required"])
        ok, message = ce.recover_instant_folder(str(self.root), self.password)
        self.assertTrue(ok, message)
        photos = list(self.root.rglob("a.jpg"))
        self.assertEqual(len(photos), 1)
        self.assertEqual(photos[0].read_bytes(), b"synthetic photo" * 100)
        self.assertEqual((self.sub / "z.txt").read_bytes(), b"synthetic document")

    def test_journal_failure_after_atomic_move_rolls_back(self):
        record = ce.TransactionJournal.record_completed_step

        def fail_completion(journal, step):
            if step["action"] == "MOVE_TO_CONTAINER":
                raise OSError("Synthetic journal failure")
            return record(journal, step)

        with patch.object(ce.TransactionJournal, "record_completed_step", fail_completion):
            with self.assertRaises(ce.CryptoError):
                ce.lock_folder_instant(str(self.root), self.password)
        self.assert_restored()

    def test_journal_failure_after_source_directory_removal_rolls_back(self):
        record = ce.TransactionJournal.record_completed_step

        def fail_completion(journal, step):
            if step["action"] == "REMOVE_MOVED_DIRECTORY":
                raise OSError("Synthetic journal failure")
            return record(journal, step)

        with self.open_handle(), patch.object(ce.TransactionJournal, "record_completed_step", fail_completion):
            with self.assertRaises(ce.CryptoError):
                ce.lock_folder_instant(str(self.root), self.password)
        self.assert_restored()

    def test_recovery_works_while_metadata_handle_remains_open(self):
        with self.open_handle():
            ce.lock_folder_instant(str(self.root), self.password)
            ok, message = ce.recover_instant_folder(str(self.root), self.password)
            self.assertTrue(ok, message)
            self.assert_restored()

    def test_existing_destination_is_never_overwritten(self):
        destination = self.work / "existing"
        destination.mkdir()
        (destination / "a.jpg").write_bytes(b"unrelated existing data")
        with self.open_handle(), self.assertRaises(FileExistsError):
            ce._move_instant_item(str(self.sub), str(destination))
        self.assert_restored()
        self.assertEqual((destination / "a.jpg").read_bytes(), b"unrelated existing data")


if __name__ == "__main__":
    unittest.main()
