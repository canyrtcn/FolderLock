"""
FolderLock - Tests for safe_fs Layer
Validates path security, atomic operations, attribute preservation, and exclusive locking.
"""

import os
import sys
import tempfile
import shutil
import unittest
import ctypes

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import safe_fs
from safe_fs import (
    validate_protection_root,
    is_safe_relative_path,
    is_same_volume,
    move_no_replace,
    atomic_write_json,
    read_verified_json,
    OperationLock,
    OperationLockError,
    PathValidationError,
    SafeFSError,
    get_file_attributes_safe,
    add_hidden_system_attributes,
    remove_hidden_system_attributes,
    get_security_descriptor_sddl,
    restore_security_descriptor_sddl,
    scan_source_tree
)


class TestSafeFS(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_test_safefs_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_validate_protection_root(self):
        # Valid directory
        validated = validate_protection_root(self.test_dir)
        self.assertEqual(os.path.normcase(validated), os.path.normcase(self.test_dir))

        # Non-existent path
        with self.assertRaises(PathValidationError):
            validate_protection_root(os.path.join(self.test_dir, "non_existent"))

        # Drive root
        drive, _ = os.path.splitdrive(self.test_dir)
        with self.assertRaises(PathValidationError):
            validate_protection_root(drive + "\\")

        # Empty/invalid inputs
        with self.assertRaises(PathValidationError):
            validate_protection_root("")
        with self.assertRaises(PathValidationError):
            validate_protection_root(None)

    def test_is_safe_relative_path(self):
        root = self.test_dir
        # Safe paths
        self.assertTrue(is_safe_relative_path("file.txt", root))
        self.assertTrue(is_safe_relative_path("sub/file.txt", root))
        self.assertTrue(is_safe_relative_path("sub/sub2/file_123.dat", root))

        # Traversal attempts
        self.assertFalse(is_safe_relative_path("../outside.txt", root))
        self.assertFalse(is_safe_relative_path("sub/../../outside.txt", root))
        self.assertFalse(is_safe_relative_path("/root/file.txt", root))
        self.assertFalse(is_safe_relative_path("\\root\\file.txt", root))

        # Windows reserved names
        self.assertFalse(is_safe_relative_path("CON.txt", root))
        self.assertFalse(is_safe_relative_path("prn", root))
        self.assertFalse(is_safe_relative_path("aux.dat", root))
        self.assertFalse(is_safe_relative_path("sub/NUL.txt", root))
        self.assertFalse(is_safe_relative_path("com1", root))
        self.assertFalse(is_safe_relative_path("lpt9.log", root))

        # Alternate Data Streams (ADS)
        self.assertFalse(is_safe_relative_path("file.txt:hidden_stream", root))

        # Illegal Windows characters
        self.assertFalse(is_safe_relative_path("file<test>.txt", root))
        self.assertFalse(is_safe_relative_path("file|pipe.txt", root))

    def test_is_same_volume(self):
        p1 = os.path.join(self.test_dir, "a.txt")
        p2 = os.path.join(self.test_dir, "b.txt")
        self.assertTrue(is_same_volume(p1, p2))

    def test_move_no_replace(self):
        src = os.path.join(self.test_dir, "source.txt")
        dst = os.path.join(self.test_dir, "destination.txt")
        with open(src, "w") as f:
            f.write("content to move")

        # Successful move
        move_no_replace(src, dst)
        self.assertFalse(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))

        # Attempt to move to an existing destination must fail with FileExistsError
        with open(src, "w") as f:
            f.write("new content")

        with self.assertRaises(FileExistsError):
            move_no_replace(src, dst)

        # Ensure both files preserved without clobbering
        self.assertTrue(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))
        with open(dst, "r") as f:
            self.assertEqual(f.read(), "content to move")

    def test_atomic_write_json(self):
        json_file = os.path.join(self.test_dir, "test.json")
        payload = {"operation_id": "op-1234", "key": "value", "count": 42}

        atomic_write_json(json_file, payload, expected_op_id="op-1234")
        self.assertTrue(os.path.exists(json_file))

        loaded = read_verified_json(json_file)
        self.assertEqual(loaded, payload)

        # Overwrite with matching expected_op_id
        updated = {"operation_id": "op-1234", "key": "new_value", "count": 43}
        atomic_write_json(json_file, updated, expected_op_id="op-1234")
        self.assertEqual(read_verified_json(json_file)["key"], "new_value")

        # Refusal when expected_op_id does not match
        with self.assertRaises(SafeFSError):
            atomic_write_json(json_file, {"operation_id": "wrong_op"}, expected_op_id="foreign_op")

    @unittest.skipUnless(os.name == 'nt', "Windows-specific attributes test")
    def test_file_attributes_safe(self):
        target = os.path.join(self.test_dir, "attr_file.txt")
        with open(target, "w") as f:
            f.write("attributes test")

        orig_attrs = get_file_attributes_safe(target)
        # Add hidden and system
        add_hidden_system_attributes(target)
        new_attrs = get_file_attributes_safe(target)
        self.assertTrue(new_attrs & safe_fs.FILE_ATTRIBUTE_HIDDEN)
        self.assertTrue(new_attrs & safe_fs.FILE_ATTRIBUTE_SYSTEM)

        # Remove hidden and system
        remove_hidden_system_attributes(target, orig_attrs=orig_attrs)
        restored_attrs = get_file_attributes_safe(target)
        self.assertFalse(restored_attrs & safe_fs.FILE_ATTRIBUTE_HIDDEN)
        self.assertFalse(restored_attrs & safe_fs.FILE_ATTRIBUTE_SYSTEM)

    @unittest.skipUnless(os.name == 'nt', "Windows-specific SDDL test")
    def test_sddl_security_descriptor(self):
        sub = os.path.join(self.test_dir, "sddl_dir")
        os.makedirs(sub)
        sddl = get_security_descriptor_sddl(sub)
        self.assertIsNotNone(sddl)
        self.assertTrue(sddl.startswith("D:"))

        # Restore SDDL
        ok = restore_security_descriptor_sddl(sub, sddl)
        self.assertTrue(ok)
        self.assertEqual(get_security_descriptor_sddl(sub), sddl)

    def test_operation_lock_exclusive(self):
        # 1. Acquire lock
        lock1 = OperationLock(self.test_dir, "test_op")
        lock1.acquire()

        # 2. Concurrently attempt another lock on the same directory
        lock2 = OperationLock(self.test_dir, "concurrent_op")
        with self.assertRaises(OperationLockError):
            lock2.acquire()

        # 3. Release lock1 and verify lock2 can now acquire
        lock1.release()
        lock2.acquire()
        lock2.release()

    def test_scan_source_tree(self):
        # Create sample folder hierarchy
        sub1 = os.path.join(self.test_dir, "docs")
        os.makedirs(sub1)
        with open(os.path.join(self.test_dir, "root.txt"), "w") as f:
            f.write("root file")
        with open(os.path.join(sub1, "inner.txt"), "w") as f:
            f.write("inner file")

        manifest, total_files, total_bytes = scan_source_tree(self.test_dir, set())
        self.assertEqual(total_files, 2)
        self.assertTrue(total_bytes > 0)
        rel_paths = {item["rel_path"] for item in manifest}
        self.assertIn("root.txt", rel_paths)
        self.assertIn("docs/inner.txt", rel_paths)


if __name__ == "__main__":
    unittest.main()
