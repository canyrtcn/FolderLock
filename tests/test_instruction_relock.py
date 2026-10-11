"""Regressions: FolderLock must protect pre-existing instruction notes on re-lock.

Run against synthetic TemporaryDirectory fixtures only.
"""
import hashlib
import os
import tempfile
import unittest

from crypto_engine import (
    INSTRUCTION_FILENAME,
    README_UNLOCKED_TEXT,
    README_GENERAL_GUIDE,
    FOLDERLOCK_OWNERSHIP_TAG,
    lock_folder,
    unlock_folder,
    lock_folder_instant,
    unlock_folder_instant,
    write_instruction_file,
)


class InstructionRelockRegression(unittest.TestCase):
    def test_aes_relock_same_directory_twice(self):
        with tempfile.TemporaryDirectory(prefix="fl_instr_relock_") as directory:
            user_file = os.path.join(directory, "personal_document.txt")
            expected = b"SYNTHETIC IMPORTANT FILE" * 40
            with open(user_file, "wb") as f:
                f.write(expected)
            for _ in range(4):
                lock_folder(directory, "Synthetic-Test-Only-Password!")
                self.assertFalse(os.path.exists(user_file))
                unlock_folder(directory, "Synthetic-Test-Only-Password!")
                with open(user_file, "rb") as f:
                    self.assertEqual(f.read(), expected)
                notes = [n for n in os.listdir(directory) if n.startswith("FolderLock_Instructions")]
                self.assertEqual(len(notes), 1, "Repeated locking must not multiply guide files")

    def test_preexisting_note_with_marker_is_encrypted_and_restored(self):
        with tempfile.TemporaryDirectory(prefix="fl_instr_marker_") as directory:
            user_file = os.path.join(directory, INSTRUCTION_FILENAME)
            original = (FOLDERLOCK_OWNERSHIP_TAG + "\nUSER-DATA-DO-NOT-DELETE").encode()
            with open(user_file, "wb") as f:
                f.write(original)
            with open(os.path.join(directory, "doc.txt"), "wb") as f:
                f.write(b"SYNTHETIC CONTENT")
            lock_folder(directory, "Synthetic-Test-Only-Password!")
            self.assertFalse(os.path.exists(user_file), "User note must not remain plaintext")
            unlock_folder(directory, "Synthetic-Test-Only-Password!")
            with open(user_file, "rb") as f:
                self.assertEqual(f.read(), original, "User note must never be overwritten")

    def test_existing_generated_unlocked_note_can_be_relocked(self):
        with tempfile.TemporaryDirectory(prefix="fl_instr_generated_") as directory:
            user_file = os.path.join(directory, INSTRUCTION_FILENAME)
            with open(user_file, "w", encoding="utf-8") as f:
                f.write(README_UNLOCKED_TEXT)
            with open(os.path.join(directory, "doc.txt"), "wb") as f:
                f.write(b"SYNTHETIC CONTENT")
            lock_folder(directory, "Synthetic-Test-Only-Password!")
            self.assertFalse(os.path.exists(user_file), "Unlocked note must be secured as user data")
            unlock_folder(directory, "Synthetic-Test-Only-Password!")
            with open(user_file, encoding="utf-8") as f:
                self.assertEqual(f.read(), README_UNLOCKED_TEXT)


    def test_created_guide_bytes_are_platform_independent(self):
        with tempfile.TemporaryDirectory(prefix="fl_guide_bytes_") as directory:
            self.assertTrue(write_instruction_file(directory, README_GENERAL_GUIDE))
            with open(os.path.join(directory, INSTRUCTION_FILENAME), "rb") as stream:
                self.assertEqual(stream.read(), README_GENERAL_GUIDE.encode("utf-8"))

    def test_legacy_windows_crlf_guide_relock_without_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="fl_legacy_crlf_") as directory:
            path = os.path.join(directory, INSTRUCTION_FILENAME)
            original = README_GENERAL_GUIDE.replace("\n", "\r\n").encode("utf-8")
            with open(path, "wb") as stream:
                stream.write(original)
            with open(os.path.join(directory, "doc.txt"), "wb") as stream:
                stream.write(b"SYNTHETIC DOCUMENT")
            for _ in range(3):
                lock_folder(directory, "Synthetic-Test-Only-Password!")
                self.assertEqual(open(path, "rb").read(), original)
                unlock_folder(directory, "Synthetic-Test-Only-Password!")
                with open(path, "rb") as stream:
                    self.assertEqual(stream.read(), original)
                self.assertEqual(
                    len([n for n in os.listdir(directory)
                         if n.startswith("FolderLock_Instructions")]), 1
                )

    @unittest.skipUnless(os.name == "nt", "Requires Windows NTFS ACLs")
    def test_instant_legacy_crlf_guide_does_not_multiply(self):
        with tempfile.TemporaryDirectory(prefix="fl_instant_crlf_") as directory:
            path = os.path.join(directory, INSTRUCTION_FILENAME)
            original = README_GENERAL_GUIDE.replace("\n", "\r\n").encode("utf-8")
            with open(path, "wb") as stream:
                stream.write(original)
            with open(os.path.join(directory, "doc.txt"), "wb") as stream:
                stream.write(b"SYNTHETIC DOCUMENT")
            lock_folder_instant(directory, "Synthetic-Test-Only-Password!")
            unlock_folder_instant(directory, "Synthetic-Test-Only-Password!")
            with open(path, "rb") as stream:
                self.assertEqual(stream.read(), original)
            self.assertEqual(
                len([n for n in os.listdir(directory)
                     if n.startswith("FolderLock_Instructions")]), 1
            )


if __name__ == "__main__":
    unittest.main()
