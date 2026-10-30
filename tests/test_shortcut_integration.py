"""
FolderLock v1.0.5 - Comprehensive In-Folder Shortcuts Integration & Security Regression Tests
Validates:
1. Shell link authenticity verification and ownership validation.
2. Defense against plaintext exclusion and user data loss (fails closed on non-authentic files).
3. 10x repeated Instant Lock and Unlock cycles with zero shortcut proliferation and exact SHA-256 integrity.
4. 10x repeated AES-256 Lock and Unlock cycles with zero shortcut proliferation and exact SHA-256 integrity.
5. Quick re-lock workflow with shortcuts.
6. Reparse point and tampered shortcut rejection.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import crypto_engine
import safe_fs
import shell_shortcuts
from shell_integration import get_app_exe_path


@unittest.skipUnless(os.name == 'nt', 'Windows COM and NTFS required')
class TestShortcutIntegration(unittest.TestCase):
    def setUp(self):
        self.test_root = tempfile.mkdtemp(prefix="flock_sc_test_")
        self.folder = os.path.join(self.test_root, "Protected Vault Folder")
        os.makedirs(self.folder, exist_ok=True)
        self.exe = get_app_exe_path()
        self.password = "Secr3t_P@ssw0rd_2026!"

    def tearDown(self):
        if os.path.exists(self.test_root):
            try:
                # If locked, unlock first to clean up
                mode = crypto_engine.is_folder_locked(self.folder)
                if mode == "instant":
                    crypto_engine.unlock_folder_instant(self.folder, self.password)
                elif mode == "crypto":
                    crypto_engine.unlock_folder(self.folder, self.password)
            except Exception:
                pass
            try:
                shutil.rmtree(self.test_root, ignore_errors=True)
            except Exception:
                pass

    def _create_synthetic_files(self) -> dict:
        files = {
            "notes.txt": b"Confidential synthetic user notes.\r\nLine 2.\r\n",
            "data.bin": bytes([x % 256 for x in range(2048)]),
            "nested/report.pdf": b"%PDF-1.4 synthetic PDF document bytes for validation.\r\n",
        }
        hashes = {}
        for rel_path, data in files.items():
            full_p = os.path.join(self.folder, rel_path.replace("/", os.sep))
            os.makedirs(os.path.dirname(full_p), exist_ok=True)
            with open(full_p, "wb") as f:
                f.write(data)
            hashes[rel_path] = hashlib.sha256(data).hexdigest()
        return hashes

    def _verify_synthetic_files(self, expected_hashes: dict):
        for rel_path, expected_h in expected_hashes.items():
            full_p = os.path.join(self.folder, rel_path.replace("/", os.sep))
            self.assertTrue(os.path.isfile(full_p), f"Missing restored file: {rel_path}")
            with open(full_p, "rb") as f:
                actual_h = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(actual_h, expected_h, f"Hash mismatch for {rel_path}")

    def test_authentic_shortcut_verification(self):
        # 1. Genuine shortcuts created for this folder
        self.assertTrue(shell_shortcuts.create_prototype(self.folder, self.exe, "lock"))
        self.assertTrue(shell_shortcuts.create_prototype(self.folder, self.exe, "unlock"))

        lock_path = os.path.join(self.folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
        unlock_path = os.path.join(self.folder, shell_shortcuts.SHORTCUT_UNLOCK_NAME)

        self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(lock_path, self.folder, "lock"))
        self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(unlock_path, self.folder, "unlock"))
        self.assertFalse(shell_shortcuts.is_authentic_folderlock_shortcut(lock_path, self.folder, "unlock"))

        # 2. Tampered arguments: shortcut pointing to different folder
        other_folder = os.path.join(self.test_root, "OtherFolder")
        os.makedirs(other_folder, exist_ok=True)
        other_link = os.path.join(other_folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
        self.assertTrue(shell_shortcuts.create_prototype(other_folder, self.exe, "lock"))
        self.assertFalse(shell_shortcuts.is_authentic_folderlock_shortcut(other_link, self.folder, "lock"))

        # 3. Non-shortcut text file with shortcut name
        fake_path = os.path.join(self.folder, "fake.lnk")
        with open(fake_path, "wb") as f:
            f.write(b"NOT A SHELL LINK FILE")
        self.assertFalse(shell_shortcuts.is_authentic_folderlock_shortcut(fake_path, self.folder))

    def test_preflight_refuses_user_file_collision_instant(self):
        # Place non-authentic user data named FolderLock - Lock.lnk in folder
        user_file = os.path.join(self.folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
        user_content = b"USER SECRET DATA - MUST NEVER BE LOST OR EXCLUDED"
        with open(user_file, "wb") as f:
            f.write(user_content)

        # Instant Lock must fail closed
        with self.assertRaises(crypto_engine.CryptoError):
            crypto_engine.lock_folder_instant(self.folder, self.password)

        # Verify user file is completely untouched
        self.assertTrue(os.path.isfile(user_file))
        with open(user_file, "rb") as f:
            self.assertEqual(f.read(), user_content)
        self.assertIsNone(crypto_engine.is_folder_locked(self.folder))

    def test_preflight_refuses_user_file_collision_aes(self):
        # Place non-authentic user data named FolderLock - Unlock.lnk in folder
        user_file = os.path.join(self.folder, shell_shortcuts.SHORTCUT_UNLOCK_NAME)
        user_content = b"USER SECRET DATA - AES PRESERVATION TEST"
        with open(user_file, "wb") as f:
            f.write(user_content)

        # AES Lock must fail closed
        with self.assertRaises(crypto_engine.CryptoError):
            crypto_engine.lock_folder(self.folder, self.password)

        # Verify user file is completely untouched
        self.assertTrue(os.path.isfile(user_file))
        with open(user_file, "rb") as f:
            self.assertEqual(f.read(), user_content)
        self.assertIsNone(crypto_engine.is_folder_locked(self.folder))

    def test_e2e_instant_lock_10_cycles_no_duplication(self):
        hashes = self._create_synthetic_files()

        for cycle in range(1, 11):
            # Lock Instant
            crypto_engine.lock_folder_instant(self.folder, self.password)
            self.assertEqual(crypto_engine.is_folder_locked(self.folder), "instant")

            # Check locked folder contents
            locked_items = os.listdir(self.folder)
            self.assertIn(shell_shortcuts.SHORTCUT_LOCK_NAME, locked_items)
            self.assertIn(shell_shortcuts.SHORTCUT_UNLOCK_NAME, locked_items)
            # Ensure no user files leaked into root
            self.assertNotIn("notes.txt", locked_items)
            self.assertNotIn("data.bin", locked_items)

            # Unlock Instant
            ok = crypto_engine.unlock_folder_instant(self.folder, self.password)
            self.assertTrue(ok)
            self.assertIsNone(crypto_engine.is_folder_locked(self.folder))

            # Verify no duplicate _1.lnk files anywhere in the folder
            for r, _, files in os.walk(self.folder):
                for f in files:
                    self.assertFalse(f.endswith("_1.lnk"), f"Cycle {cycle}: Proliferated shortcut detected: {f}")

            # Verify user files and hashes
            self._verify_synthetic_files(hashes)

            # Verify shortcuts remain authentic
            lock_p = os.path.join(self.folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
            unlock_p = os.path.join(self.folder, shell_shortcuts.SHORTCUT_UNLOCK_NAME)
            self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(lock_p, self.folder, "lock"))
            self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(unlock_p, self.folder, "unlock"))

    def test_e2e_aes_lock_10_cycles_no_duplication(self):
        hashes = self._create_synthetic_files()

        for cycle in range(1, 11):
            # Lock AES
            crypto_engine.lock_folder(self.folder, self.password)
            self.assertEqual(crypto_engine.is_folder_locked(self.folder), "crypto")

            # Check locked folder contents
            locked_items = os.listdir(self.folder)
            self.assertIn(shell_shortcuts.SHORTCUT_LOCK_NAME, locked_items)
            self.assertIn(shell_shortcuts.SHORTCUT_UNLOCK_NAME, locked_items)
            self.assertIn("FolderLock_Instructions.txt", locked_items)
            self.assertNotIn("notes.txt", locked_items)
            self.assertNotIn("data.bin", locked_items)

            # Unlock AES
            unlocked_dir = crypto_engine.unlock_folder(self.folder, self.password)
            self.assertEqual(os.path.normpath(unlocked_dir), os.path.normpath(self.folder))
            self.assertIsNone(crypto_engine.is_folder_locked(self.folder))

            # Verify no duplicate _1.lnk files
            for r, _, files in os.walk(self.folder):
                for f in files:
                    self.assertFalse(f.endswith("_1.lnk"), f"Cycle {cycle}: Proliferated shortcut detected: {f}")

            # Verify user files and hashes
            self._verify_synthetic_files(hashes)

            # Verify shortcuts remain authentic
            lock_p = os.path.join(self.folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
            unlock_p = os.path.join(self.folder, shell_shortcuts.SHORTCUT_UNLOCK_NAME)
            self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(lock_p, self.folder, "lock"))
            self.assertTrue(shell_shortcuts.is_authentic_folderlock_shortcut(unlock_p, self.folder, "unlock"))

    def test_quick_relock_flow_with_shortcuts(self):
        hashes = self._create_synthetic_files()

        # 1. Lock and Unlock to establish .flock_relock
        crypto_engine.lock_folder_instant(self.folder, self.password)
        crypto_engine.unlock_folder_instant(self.folder, self.password)
        self.assertIsNotNone(crypto_engine.get_relock_config(self.folder))

        # 2. Quick relock
        self.assertTrue(crypto_engine.relock_folder(self.folder))
        self.assertEqual(crypto_engine.is_folder_locked(self.folder), "instant")

        # Shortcuts present while locked
        locked_items = os.listdir(self.folder)
        self.assertIn(shell_shortcuts.SHORTCUT_LOCK_NAME, locked_items)
        self.assertIn(shell_shortcuts.SHORTCUT_UNLOCK_NAME, locked_items)

        # 3. Unlock again
        self.assertTrue(crypto_engine.unlock_folder_instant(self.folder, self.password))
        self._verify_synthetic_files(hashes)

    def test_symlink_rejection_for_shortcuts(self):
        target_file = os.path.join(self.test_root, "dummy.txt")
        with open(target_file, "w") as f:
            f.write("target")
        symlink_path = os.path.join(self.folder, shell_shortcuts.SHORTCUT_LOCK_NAME)
        try:
            os.symlink(target_file, symlink_path)
        except (OSError, NotImplementedError):
            # SeCreateSymbolicLinkPrivilege might not be available for non-elevated user
            return

        self.assertFalse(shell_shortcuts.is_authentic_folderlock_shortcut(symlink_path, self.folder, "lock"))
        with self.assertRaises(crypto_engine.CryptoError):
            shell_shortcuts.audit_and_clean_authentic_shortcuts(self.folder)


if __name__ == "__main__":
    unittest.main(verbosity=2)
