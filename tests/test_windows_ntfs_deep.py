"""
Deep Windows NTFS & Process Lifecycle Regressions for FolderLock.
Tests real NTFS junctions, Win32 kernel handle lifecycle, process termination (kill),
stale lock recovery, and complete nested metadata roundtrips on Windows.
"""
import os
import sys
import json
import time
import shutil
import tempfile
import unittest
import subprocess
from pathlib import Path

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import safe_fs
import crypto_engine


@unittest.skipUnless(os.name == 'nt', "Windows NTFS-specific tests")
class TestWindowsNTFSDeep(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_ntfs_test_")
        self.password = "WinNTFS-SecurePass-2026!"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_real_ntfs_junction_rejection_on_unlock(self):
        """Creates a real NTFS directory junction and verifies unlock fails closed without writing outside."""
        protected_dir = os.path.join(self.test_dir, "protected")
        outside_dir = os.path.join(self.test_dir, "outside_victim")
        os.makedirs(os.path.join(protected_dir, "docs"), exist_ok=True)
        os.makedirs(outside_dir, exist_ok=True)

        secret_file = os.path.join(protected_dir, "docs", "secret.txt")
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("SECRET CORPORATE ASSET")

        # Lock the folder
        crypto_engine.lock_folder(protected_dir, self.password)
        self.assertTrue(os.path.isfile(os.path.join(protected_dir, ".locked_vault")))

        # Create NTFS junction: docs -> outside_victim
        docs_target = os.path.join(protected_dir, "docs")
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", docs_target, outside_dir],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            self.skipTest("mklink /J not permitted in current environment")

        self.assertTrue(safe_fs.is_reparse_point(docs_target))

        # Attempt unlock: MUST FAIL and MUST NOT write into outside_victim
        with self.assertRaises(Exception):
            crypto_engine.unlock_folder(protected_dir, self.password)

        victim_file = os.path.join(outside_dir, "secret.txt")
        self.assertFalse(os.path.exists(victim_file), "CRITICAL: Secret written through junction into external directory!")
        self.assertTrue(os.path.isfile(os.path.join(protected_dir, ".locked_vault")), "Vault was deleted despite error!")

    def test_process_killed_stale_lock_kernel_release_and_recovery(self):
        """
        Launches a worker process that holds a Win32 exclusive lock.
        Kills the worker process and verifies OS kernel immediately releases the handle,
        allowing recover_aes_folder to safely recover the folder.
        """
        protected_dir = os.path.join(self.test_dir, "crash_target")
        os.makedirs(protected_dir, exist_ok=True)
        data_file = os.path.join(protected_dir, "report.pdf")
        with open(data_file, "wb") as f:
            f.write(b"%PDF-1.4 TEST REPORT CONTENT")

        # 1. Lock folder
        crypto_engine.lock_folder(protected_dir, self.password)
        self.assertTrue(os.path.isfile(os.path.join(protected_dir, ".locked_vault")))

        # 2. Simulate interrupted operation midway by creating journal in SOURCE_CLEANUP
        j = crypto_engine.TransactionJournal(
            os.path.join(protected_dir, ".flock_journal"), "crashed_op_42", "aes_lock", protected_dir
        )
        j.set_state("SOURCE_CLEANUP")
        j.mark_recovery_required("Simulated hard crash")

        # 3. Start child process that acquires and HOLDS the Win32 handle lock
        child_code = f"""
import sys, os, time
sys.path.insert(0, {repr(repo_root)})
import safe_fs
lock = safe_fs.OperationLock({repr(protected_dir)}, "aes_lock")
lock.acquire()
print("LOCKED", flush=True)
while True:
    time.sleep(0.1)
"""
        proc = subprocess.Popen([sys.executable, "-c", child_code],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            self.assertIn("LOCKED", line)

            # While child process is alive, parent lock acquisition must be blocked
            lock_obj = safe_fs.OperationLock(protected_dir, "aes_lock")
            self.assertTrue(lock_obj._is_lock_active(lock_obj.lock_file))
            with self.assertRaises(safe_fs.OperationLockError):
                safe_fs.acquire_operation_lock(protected_dir, "recovery", is_recovery=True)

            # Kill child process forcefully
            proc.kill()
            proc.wait(timeout=5)
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            if proc.poll() is None:
                proc.kill()

        # 4. Now that child is dead, kernel has freed handle: recovery MUST succeed
        success, msg = crypto_engine.recover_aes_folder(protected_dir, self.password)
        self.assertTrue(success, f"Recovery failed after process kill: {msg}")

        # Verify file is restored
        self.assertTrue(os.path.isfile(data_file))
        with open(data_file, "rb") as f:
            self.assertEqual(f.read(), b"%PDF-1.4 TEST REPORT CONTENT")

    def test_nested_metadata_complete_roundtrip(self):
        """Verifies full roundtrip for nested user files named like metadata."""
        folder = os.path.join(self.test_dir, "nested_meta_target")
        sub1 = os.path.join(folder, "sub1")
        sub2 = os.path.join(folder, "sub2")
        os.makedirs(sub1, exist_ok=True)
        os.makedirs(sub2, exist_ok=True)

        user_j = os.path.join(sub1, ".flock_journal")
        user_op = os.path.join(sub2, ".flock_oplock")
        user_relock = os.path.join(sub1, ".flock_relock")

        with open(user_j, "w", encoding="utf-8") as f:
            f.write("USER FLOCK JOURNAL CONTENT")
        with open(user_op, "w", encoding="utf-8") as f:
            f.write("USER FLOCK OPLOCK CONTENT")
        with open(user_relock, "w", encoding="utf-8") as f:
            f.write("USER FLOCK RELOCK CONTENT")

        h_j = safe_fs.compute_file_sha256(user_j)
        h_op = safe_fs.compute_file_sha256(user_op)
        h_re = safe_fs.compute_file_sha256(user_relock)

        # Lock with AES
        crypto_engine.lock_folder(folder, self.password)

        # Plaintext user files must NOT remain in source folder
        self.assertFalse(os.path.exists(user_j))
        self.assertFalse(os.path.exists(user_op))
        self.assertFalse(os.path.exists(user_relock))

        # Unlock with AES
        crypto_engine.unlock_folder(folder, self.password)

        # Verify all nested files restored and identical SHA-256
        self.assertTrue(os.path.isfile(user_j))
        self.assertTrue(os.path.isfile(user_op))
        self.assertTrue(os.path.isfile(user_relock))

        self.assertEqual(safe_fs.compute_file_sha256(user_j), h_j)
        self.assertEqual(safe_fs.compute_file_sha256(user_op), h_op)
        self.assertEqual(safe_fs.compute_file_sha256(user_relock), h_re)


if __name__ == "__main__":
    unittest.main()
