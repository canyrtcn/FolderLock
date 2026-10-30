"""Native move errors and postconditions stay strict after reducing probes."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import safe_fs


@unittest.skipUnless(os.name == "nt", "Windows no-replace semantics required")
class NativeMoveSafetyTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="flock_native_move_")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.source = self.root / "source.txt"
        self.destination = self.root / "destination.txt"
        self.source.write_bytes(b"synthetic source")

    def test_existing_readonly_destination_is_preserved(self):
        self.destination.write_bytes(b"unrelated existing contents")
        attributes = safe_fs.get_file_attributes_safe(str(self.destination))
        safe_fs._SetFileAttributesW(str(self.destination), attributes | safe_fs.FILE_ATTRIBUTE_READONLY)
        try:
            with self.assertRaises(FileExistsError):
                safe_fs.move_no_replace(str(self.source), str(self.destination))
            self.assertEqual(self.source.read_bytes(), b"synthetic source")
            self.assertEqual(self.destination.read_bytes(), b"unrelated existing contents")
        finally:
            safe_fs._SetFileAttributesW(str(self.destination), attributes)

    def test_false_native_success_does_not_skip_verification(self):
        with patch.object(safe_fs, "_MoveFileExW", return_value=True):
            with self.assertRaises(safe_fs.SafeFSError):
                safe_fs.move_no_replace(str(self.source), str(self.destination))
        self.assertEqual(self.source.read_bytes(), b"synthetic source")
        self.assertFalse(self.destination.exists())

    def test_missing_source_reports_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            safe_fs.move_no_replace(str(self.root / "missing.txt"), str(self.destination))
        self.assertFalse(self.destination.exists())

    def test_cross_volume_move_is_refused_before_native_mutation(self):
        other_drive = "Z:" if self.root.drive.upper() != "Z:" else "Y:"
        with patch.object(safe_fs, "_MoveFileExW") as move:
            with self.assertRaises(safe_fs.SafeFSError):
                safe_fs.move_no_replace(str(self.source), other_drive + "\\synthetic_destination.txt")
        move.assert_not_called()
        self.assertEqual(self.source.read_bytes(), b"synthetic source")


if __name__ == "__main__":
    unittest.main()
