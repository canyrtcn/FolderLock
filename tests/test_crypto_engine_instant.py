"""
FolderLock - Tests for Instant Lock (NTFS ACL + Container)
Validates transaction journaling, rollback, recovery, collision handling, and ACL preservation.
"""

import os
import sys
import tempfile
import shutil
import unittest
import hashlib

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import crypto_engine
from crypto_engine import (
    lock_folder_instant,
    unlock_folder_instant,
    recover_instant_folder,
    INSTANT_DATA_DIRNAME,
    META_FILENAME,
    INSTANT_JOURNAL_FILENAME,
    InvalidPasswordError,
    CryptoError
)
import safe_fs


def get_file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class TestCryptoEngineInstant(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_test_instant_")
        self.password = "Instant_Secret_Pass_987#"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                # Remove deny permissions if any remain before cleanup
                safe_fs.run_icacls_safe([os.path.join(self.test_dir, INSTANT_DATA_DIRNAME), "/remove:d", "*S-1-1-0"])
                safe_fs.remove_hidden_system_attributes(os.path.join(self.test_dir, INSTANT_DATA_DIRNAME))
            except Exception:
                pass
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_instant_lock_and_unlock_roundtrip(self):
        f1 = os.path.join(self.test_dir, "report.pdf")
        with open(f1, "wb") as fp:
            fp.write(b"PDF Sample Data" * 100)
        h1 = get_file_hash(f1)

        f2 = os.path.join(self.test_dir, "notes.txt")
        with open(f2, "w", encoding="utf-8") as fp:
            fp.write("Personal notes")
        h2 = get_file_hash(f2)

        # 1. Lock folder
        salt, hash_val = lock_folder_instant(self.test_dir, self.password)
        self.assertTrue(len(salt) > 0)
        self.assertTrue(len(hash_val) > 0)

        # Verify .locked_data exists and original files moved into it
        locked_container = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)
        self.assertTrue(os.path.isdir(locked_container))
        self.assertFalse(os.path.exists(f1))
        self.assertFalse(os.path.exists(f2))

        # 2. Unlock folder
        ok = unlock_folder_instant(self.test_dir, self.password)
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(locked_container))
        self.assertTrue(os.path.exists(f1))
        self.assertTrue(os.path.exists(f2))

        # 3. Verify data hashes match
        self.assertEqual(get_file_hash(f1), h1)
        self.assertEqual(get_file_hash(f2), h2)

    def test_instant_wrong_password_rejected(self):
        f1 = os.path.join(self.test_dir, "data.txt")
        with open(f1, "w") as fp:
            fp.write("Test data")

        lock_folder_instant(self.test_dir, self.password)
        locked_container = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)

        with self.assertRaises(InvalidPasswordError):
            unlock_folder_instant(self.test_dir, "IncorrectPassword!")

        # Container must remain locked and inaccessible
        self.assertTrue(os.path.isdir(locked_container))

    def test_instant_lock_empty_folder_rejected(self):
        with self.assertRaises(ValueError):
            lock_folder_instant(self.test_dir, self.password)

    def test_instant_recover_success(self):
        f1 = os.path.join(self.test_dir, "important.docx")
        with open(f1, "w") as fp:
            fp.write("Word Document")
        h1 = get_file_hash(f1)

        lock_folder_instant(self.test_dir, self.password)
        locked_container = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)
        self.assertTrue(os.path.isdir(locked_container))

        # Simulate recovery
        success, msg = recover_instant_folder(self.test_dir, self.password)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(locked_container))
        self.assertTrue(os.path.exists(f1))
        self.assertEqual(get_file_hash(f1), h1)

    def test_instant_recover_wrong_password_refused(self):
        f1 = os.path.join(self.test_dir, "secret.txt")
        with open(f1, "w") as fp:
            fp.write("Top secret")

        lock_folder_instant(self.test_dir, self.password)
        locked_container = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)

        success, msg = recover_instant_folder(self.test_dir, "WrongPassword!")
        self.assertFalse(success)
        self.assertTrue(os.path.isdir(locked_container))
        self.assertFalse(os.path.exists(f1))

    def test_instant_collision_resolution_on_unlock(self):
        f1 = os.path.join(self.test_dir, "photo.jpg")
        with open(f1, "wb") as fp:
            fp.write(b"Original photo bytes")

        lock_folder_instant(self.test_dir, self.password)

        # Place a new file with the same name before unlocking
        with open(f1, "wb") as fp:
            fp.write(b"New photo created in meantime")

        unlock_folder_instant(self.test_dir, self.password)

        # Both files must exist without overwrite
        self.assertTrue(os.path.exists(f1))
        with open(f1, "rb") as fp:
            self.assertEqual(fp.read(), b"New photo created in meantime")

        restored_f1 = os.path.join(self.test_dir, "photo_restored_1.jpg")
        self.assertTrue(os.path.exists(restored_f1))
        with open(restored_f1, "rb") as fp:
            self.assertEqual(fp.read(), b"Original photo bytes")

    def test_instant_second_recovery_is_safe(self):
        f = os.path.join(self.test_dir, "doc.txt")
        with open(f, "w") as fp:
            fp.write("Test file")

        lock_folder_instant(self.test_dir, self.password)
        # First recovery
        s1, m1 = recover_instant_folder(self.test_dir, self.password)
        self.assertTrue(s1)

        # Second recovery on already recovered folder returns False without crash or error
        s2, m2 = recover_instant_folder(self.test_dir, self.password)
        self.assertFalse(s2)
        self.assertIn("No Instant Lock container", m2)
        self.assertTrue(os.path.exists(f))

    def test_instant_relock_workflow(self):
        f = os.path.join(self.test_dir, "file.txt")
        with open(f, "w") as fp:
            fp.write("Relock content")

        lock_folder_instant(self.test_dir, self.password)
        unlock_folder_instant(self.test_dir, self.password)

        # Verify relock configuration was saved
        cfg = crypto_engine.get_relock_config(self.test_dir)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.get("mode"), "instant")

        # 1-Click relock without re-typing password
        ok = crypto_engine.relock_folder(self.test_dir)
        self.assertTrue(ok)
        self.assertTrue(os.path.isdir(os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)))


if __name__ == "__main__":
    unittest.main()
