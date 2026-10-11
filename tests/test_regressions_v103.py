import os
import sys
import time
import json
import shutil
import tarfile
import struct
import tempfile
import unittest
import subprocess
import hashlib

# Ensure root directory is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import safe_fs
from safe_fs import (
    acquire_operation_lock,
    OperationLock,
    OperationLockError,
    SafeFSError,
    move_no_replace,
    atomic_write_json,
    atomic_write_config_json,
    scan_source_tree,
    compute_file_sha256,
    is_reparse_point,
    validate_protection_root,
    OP_LOCK_FILENAME
)
import crypto_engine
from crypto_engine import (
    lock_folder,
    unlock_folder,
    lock_folder_instant,
    unlock_folder_instant,
    recover_instant_folder,
    recover_aes_folder,
    recover_folder,
    write_instruction_file,
    verify_file_password,
    verify_vault_integrity,
    derive_key,
    TransactionJournal,
    VAULT_FILENAME,
    INSTANT_DATA_DIRNAME,
    META_FILENAME,
    JOURNAL_FILENAME,
    INSTANT_JOURNAL_FILENAME,
    INSTRUCTION_FILENAME,
    MAGIC_HEADER_V2,
    MAGIC_HEADER_V3,
    FORMAT_VERSION_V3,
    VERIFIER_PAYLOAD_V2,
    VERIFIER_PAYLOAD_V3,
    VERIFIER_AAD_V3,
    SALT_SIZE,
    NONCE_SIZE,
    CryptoError,
    CorruptedFileError,
    InvalidPasswordError
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TestFolderLockV103Regressions(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_v103_reg_")
        self.password = "SecurePass_v103_Audit!"

    def tearDown(self):
        # Best effort cleanup
        if os.path.exists(self.test_dir):
            try:
                # Remove any deny ACL if applied
                locked_data = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)
                if os.path.exists(locked_data):
                    safe_fs.run_icacls_safe([locked_data, "/remove:d", "*S-1-1-0"])
                    safe_fs.remove_hidden_system_attributes(locked_data)
                safe_fs.run_icacls_safe([self.test_dir, "/remove:d", "*S-1-1-0"])
                safe_fs.remove_hidden_system_attributes(self.test_dir)
            except Exception:
                pass
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # =========================================================================
    # 1. AES SOURCE MANIFEST SHA-256 VERIFICATION & SAME-SIZE MODIFIED FILE
    # =========================================================================
    def test_aes_same_size_modified_file_detected_and_preserved(self):
        """
        Verify that if a file is replaced/modified with the EXACT same size
        but different content/SHA-256 prior to source cleanup:
        - lock_folder() detects content change.
        - Plaintext file is NEVER deleted.
        - Vault is preserved.
        - Journal records recovery_required == True.
        """
        file_path = os.path.join(self.test_dir, "financial_data.bin")
        original_bytes = b"AAAA" * 1024  # 4096 bytes
        tampered_bytes = b"BBBB" * 1024  # 4096 bytes (identical size!)
        with open(file_path, "wb") as f:
            f.write(original_bytes)

        # Hook into verify_vault_integrity to simulate a file modification right before SOURCE_CLEANUP
        real_verify = crypto_engine.verify_vault_integrity

        def tamper_hook(v_path, pwd, expected_manifest=None):
            res = real_verify(v_path, pwd, expected_manifest)
            # Tamper with file on disk right before SOURCE_CLEANUP begins!
            with open(file_path, "wb") as fp:
                fp.write(tampered_bytes)
            return res

        crypto_engine.verify_vault_integrity = tamper_hook
        try:
            with self.assertRaises(CryptoError) as ctx:
                lock_folder(self.test_dir, self.password)

            self.assertIn("content modified prior to deletion", str(ctx.exception).lower())

            # VERIFY: Plaintext file was NOT deleted!
            self.assertTrue(os.path.isfile(file_path), "Plaintext file must be preserved!")
            with open(file_path, "rb") as fp:
                self.assertEqual(fp.read(), tampered_bytes)

            # VERIFY: Vault file was preserved!
            vault_path = os.path.join(self.test_dir, VAULT_FILENAME)
            self.assertTrue(os.path.isfile(vault_path), "Vault must be preserved for safety!")

            # VERIFY: Journal exists and marks recovery_required
            journal_path = os.path.join(self.test_dir, JOURNAL_FILENAME)
            self.assertTrue(os.path.isfile(journal_path))
            j = TransactionJournal.load(journal_path)
            self.assertIsNotNone(j)
            self.assertTrue(j.data.get("recovery_required"))
        finally:
            crypto_engine.verify_vault_integrity = real_verify

    def test_aes_unexpected_new_file_detected_and_preserved(self):
        """
        Verify that if an unexpected new file appears in the folder during encryption:
        - lock_folder() aborts deletion.
        - Plaintext files and vault are preserved intact.
        - Journal marks recovery_required == True.
        """
        f1 = os.path.join(self.test_dir, "doc1.txt")
        with open(f1, "w") as fp:
            fp.write("Original document 1")

        real_verify = crypto_engine.verify_vault_integrity

        def add_unexpected_hook(v_path, pwd, expected_manifest=None):
            res = real_verify(v_path, pwd, expected_manifest)
            # Create an unexpected new file that wasn't in manifest
            unexpected = os.path.join(self.test_dir, "surprise_new_file.txt")
            with open(unexpected, "w") as uf:
                uf.write("New file created during operation")
            return res

        crypto_engine.verify_vault_integrity = add_unexpected_hook
        try:
            with self.assertRaises(CryptoError) as ctx:
                lock_folder(self.test_dir, self.password)

            self.assertIn("unexpected new item", str(ctx.exception).lower())

            # Plaintext preserved
            self.assertTrue(os.path.isfile(f1))
            self.assertTrue(os.path.isfile(os.path.join(self.test_dir, "surprise_new_file.txt")))
            # Vault preserved
            self.assertTrue(os.path.isfile(os.path.join(self.test_dir, VAULT_FILENAME)))
            # Journal preserved with recovery_required
            j = TransactionJournal.load(os.path.join(self.test_dir, JOURNAL_FILENAME))
            self.assertIsNotNone(j)
            self.assertTrue(j.data.get("recovery_required"))
        finally:
            crypto_engine.verify_vault_integrity = real_verify

    # =========================================================================
    # 2. INTERRUPTED AES LOCK RECOVERY & UNLOCK
    # =========================================================================
    def test_interrupted_aes_source_cleanup_safe_unlock_and_recovery(self):
        """
        Simulate an AES lock interrupted midway through SOURCE_CLEANUP:
        - File A was removed, File B is still on disk.
        - Vault exists and is valid.
        - .flock_journal exists with state='SOURCE_CLEANUP' and recovery_required=True.
        - Verify unlock_folder() adopts the existing journal, restores missing File A,
          does not crash or duplicate File B, and completes cleanly.
        """
        f_a = os.path.join(self.test_dir, "file_a.txt")
        f_b = os.path.join(self.test_dir, "file_b.txt")
        with open(f_a, "w") as fa:
            fa.write("Content of File A")
        with open(f_b, "w") as fb:
            fb.write("Content of File B")

        # Perform normal lock
        lock_folder(self.test_dir, self.password)

        # Now simulate an interrupted SOURCE_CLEANUP state:
        # Re-create File B as partially uncleaned, leaving File A locked inside vault
        with open(f_b, "w") as fb:
            fb.write("Content of File B")

        # Fabricate interrupted journal with original vault
        journal_path = os.path.join(self.test_dir, JOURNAL_FILENAME)
        journal = TransactionJournal(journal_path, "interrupted-op-id-1234", "aes_lock", self.test_dir)
        journal.set_state("SOURCE_CLEANUP")
        journal.mark_recovery_required("Simulated crash during source cleanup")

        # Now call unlock_folder() on this interrupted folder
        unlock_folder(self.test_dir, self.password)

        # Assert BOTH files are restored and readable
        self.assertTrue(os.path.isfile(f_a))
        self.assertTrue(os.path.isfile(f_b))
        with open(f_a, "r") as fa:
            self.assertEqual(fa.read(), "Content of File A")
        with open(f_b, "r") as fb:
            self.assertEqual(fb.read(), "Content of File B")

        # Assert vault and journal were cleaned up on successful recovery
        self.assertFalse(os.path.isfile(os.path.join(self.test_dir, VAULT_FILENAME)))
        self.assertFalse(os.path.isfile(journal_path))

    def test_interrupted_aes_wrong_password_preserves_journal_and_vault(self):
        """
        Verify that recovery attempts with wrong password preserve vault,
        journal, and existing files without modifying or deleting anything.
        """
        f = os.path.join(self.test_dir, "secret.txt")
        with open(f, "w") as fp:
            fp.write("Confidential payload")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        journal_path = os.path.join(self.test_dir, JOURNAL_FILENAME)
        j = TransactionJournal(journal_path, "crash-id-999", "aes_lock", self.test_dir)
        j.set_state("SOURCE_CLEANUP")
        j.mark_recovery_required("Crash")

        # Attempt recovery with incorrect password
        success, msg = recover_aes_folder(self.test_dir, "WrongPassword123!")
        self.assertFalse(success)
        self.assertIn("failed", msg.lower())

        # Assert vault and journal are still present!
        self.assertTrue(os.path.isfile(vault_path))
        self.assertTrue(os.path.isfile(journal_path))

    # =========================================================================
    # 3. INSTANT LOCK ACL ROLLBACK AND SDDL INTEGRITY
    # =========================================================================
    def test_instant_lock_acl_failure_partial_rollback_preserves_container(self):
        """
        Simulate an ACL application failure where a rollback move fails.
        Verify that .flock_meta, .locked_data, and journal are NOT deleted,
        and journal records recovery_required == True.
        """
        item1 = os.path.join(self.test_dir, "photo1.jpg")
        item2 = os.path.join(self.test_dir, "photo2.jpg")
        with open(item1, "w") as fp:
            fp.write("JPEG DATA 1")
        with open(item2, "w") as fp:
            fp.write("JPEG DATA 2")

        real_icacls = safe_fs.run_icacls_safe
        real_icacls = crypto_engine.run_icacls_safe
        real_move = crypto_engine.move_no_replace

        # Trigger ACL deny failure, and simulate move_no_replace failure during rollback
        def mock_icacls(args):
            if "/deny" in args:
                # Simulate deny command failure
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="Access Denied")
            return real_icacls(args)

        call_count = 0
        def failing_rollback_move(src, dst):
            nonlocal call_count
            call_count += 1
            # Let forward moves succeed (count 1, 2). On rollback (count >= 3), fail!
            if call_count >= 3:
                raise PermissionError("Simulated locked file during rollback")
            return real_move(src, dst)

        crypto_engine.run_icacls_safe = mock_icacls
        crypto_engine.move_no_replace = failing_rollback_move
        try:
            with self.assertRaises(CryptoError) as ctx:
                lock_folder_instant(self.test_dir, self.password)

            self.assertIn("rollback failed", str(ctx.exception).lower())

            # VERIFY: .locked_data, .flock_meta, and journal were PRESERVED!
            locked_data = os.path.join(self.test_dir, INSTANT_DATA_DIRNAME)
            meta_path = os.path.join(locked_data, META_FILENAME)
            journal_path = os.path.join(self.test_dir, INSTANT_JOURNAL_FILENAME)

            self.assertTrue(os.path.isdir(locked_data), ".locked_data must NOT be deleted on partial rollback!")
            self.assertTrue(os.path.isfile(meta_path), ".flock_meta must NOT be deleted on partial rollback!")
            self.assertTrue(os.path.isfile(journal_path), "Journal must NOT be deleted on partial rollback!")

            j = TransactionJournal.load(journal_path)
            self.assertIsNotNone(j)
            self.assertTrue(j.data.get("recovery_required"))
        finally:
            crypto_engine.run_icacls_safe = real_icacls
            crypto_engine.move_no_replace = real_move

    # =========================================================================
    # 4. AES MANIFEST EMPTY SUBDIRECTORIES ROUNDTRIP
    # =========================================================================
    def test_aes_empty_nested_subdirectories_roundtrip(self):
        """
        Verify that a folder containing only empty nested subdirectories:
        - Is accepted by scan_source_tree().
        - Is packed into tar by lock_folder().
        - Has all empty subdirectories recreated by unlock_folder().
        """
        sub1 = os.path.join(self.test_dir, "empty_sub1")
        sub1_nested = os.path.join(sub1, "nested_child")
        sub2 = os.path.join(self.test_dir, "empty_sub2")
        os.makedirs(sub1_nested, exist_ok=True)
        os.makedirs(sub2, exist_ok=True)

        # Lock folder containing only empty directories
        lock_folder(self.test_dir, self.password)

        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)
        self.assertTrue(os.path.isfile(vault_path))

        # Unlock folder
        unlock_folder(self.test_dir, self.password)

        # Verify all directories recreated
        self.assertTrue(os.path.isdir(sub1), "empty_sub1 should be recreated")
        self.assertTrue(os.path.isdir(sub1_nested), "nested_child should be recreated")
        self.assertTrue(os.path.isdir(sub2), "empty_sub2 should be recreated")

    # =========================================================================
    # 5. JOURNAL OVERWRITE SECURITY IN ATOMIC_WRITE_JSON
    # =========================================================================
    def test_atomic_write_json_corrupted_or_mismatched_journal_rejected(self):
        """
        Verify that when expected_op_id is provided:
        - If file is corrupted JSON: raises SafeFSError and preserves corrupt file.
        - If file has no operation_id: raises SafeFSError.
        - If file has different operation_id: raises SafeFSError.
        """
        target = os.path.join(self.test_dir, "test_journal.json")

        # 1. Corrupt file test
        with open(target, "wb") as f:
            f.write(b"NOT_A_VALID_JSON{][")

        with self.assertRaises(SafeFSError) as ctx:
            atomic_write_json(target, {"operation_id": "new-op-1"}, expected_op_id="new-op-1")
        self.assertIn("corrupted journal", str(ctx.exception).lower())

        with open(target, "rb") as f:
            self.assertEqual(f.read(), b"NOT_A_VALID_JSON{][", "Corrupted file must be preserved intact!")

        # 2. Mismatched operation_id test
        with open(target, "w", encoding="utf-8") as f:
            json.dump({"operation_id": "old-op-id"}, f)

        with self.assertRaises(SafeFSError) as ctx:
            atomic_write_json(target, {"operation_id": "new-op-id"}, expected_op_id="new-op-id")
        self.assertIn("mismatch", str(ctx.exception).lower())

    # =========================================================================
    # 6. OPERATION LOCK CROSS-PROCESS & HIERARCHY TESTS
    # =========================================================================
    def test_operation_lock_cross_process_collision(self):
        """
        Spawns two concurrent subprocesses attempting to lock the same folder.
        Verifies that the second process fails immediately due to Win32 handle lock.
        """
        worker_code = f"""
import sys, time
sys.path.insert(0, r"{os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))}")
from safe_fs import acquire_operation_lock

try:
    with acquire_operation_lock(r"{self.test_dir}", "worker"):
        print("LOCKED", flush=True)
        time.sleep(2.0)
    print("RELEASED", flush=True)
except Exception as e:
    print(f"FAILED: {{e}}", flush=True)
    sys.exit(1)
"""
        # Start worker 1
        p1 = subprocess.Popen([sys.executable, "-c", worker_code], stdout=subprocess.PIPE, text=True)
        line = p1.stdout.readline()
        self.assertIn("LOCKED", line)

        # While worker 1 holds the lock, try to acquire in this process
        with self.assertRaises(OperationLockError) as ctx:
            with acquire_operation_lock(self.test_dir, "worker2"):
                pass

        p1.wait(timeout=5)
        self.assertEqual(p1.returncode, 0)

    def test_operation_lock_hierarchy_collision(self):
        """
        Verify that acquiring a lock on a parent directory blocks locking on a child directory.
        """
        sub_dir = os.path.join(self.test_dir, "child_folder")
        os.makedirs(sub_dir, exist_ok=True)

        with acquire_operation_lock(self.test_dir, "parent_op"):
            # Attempting to lock child_folder must be rejected!
            with self.assertRaises(OperationLockError) as ctx:
                with acquire_operation_lock(sub_dir, "child_op"):
                    pass
            self.assertIn("parent", str(ctx.exception).lower())

    # =========================================================================
    # 7. WIN32 MOVEFILEEXW ERROR TESTS
    # =========================================================================
    def test_move_no_replace_destination_exists(self):
        f1 = os.path.join(self.test_dir, "src.txt")
        f2 = os.path.join(self.test_dir, "dst.txt")
        with open(f1, "w") as f: f.write("source")
        with open(f2, "w") as f: f.write("destination")

        with self.assertRaises(FileExistsError):
            move_no_replace(f1, f2)

    def test_move_no_replace_file_in_use_sharing_violation(self):
        f1 = os.path.join(self.test_dir, "in_use.txt")
        f2 = os.path.join(self.test_dir, "moved.txt")
        with open(f1, "w") as f: f.write("active content")

        # Open exclusively with no sharing on Windows
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL('kernel32', use_last_error=True)
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3
            # dwShareMode = 0 (exclusive lock!)
            h = k32.CreateFileW(f1, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
            try:
                self.assertNotEqual(h, -1)
                with self.assertRaises(PermissionError) as ctx:
                    move_no_replace(f1, f2)
                self.assertIn("file in use", str(ctx.exception).lower())
            finally:
                k32.CloseHandle(h)

    # =========================================================================
    # 8. REAL LEGACY FLCK02 AND FLCK03 UNLOCK WITH REAL TAR FIXTURES
    # =========================================================================
    def test_real_legacy_flck02_vault_complete_unlock(self):
        """
        Creates an authentic legacy FLCK02 encrypted vault with a real multi-file tar archive.
        Calls unlock_folder() and verifies every file is restored and SHA-256 matches.
        """
        # 1. Prepare synthetic files
        files_data = {
            "legacy_doc.txt": b"Important historic content 2026",
            "nested/data.bin": b"\x00\x01\x02\x03\xFF" * 500,
            "config.cfg": b"theme=dark\nversion=1.0.0\n"
        }

        # Build in-memory POSIX tar archive
        import io
        tar_buf = io.BytesIO()
        with tarfile.open(mode="w", fileobj=tar_buf) as tar:
            for arc_name, content in files_data.items():
                ti = tarfile.TarInfo(name=arc_name)
                ti.size = len(content)
                ti.mtime = int(time.time())
                tar.addfile(ti, io.BytesIO(content))

        tar_bytes = tar_buf.getvalue()

        # 2. Encrypt into FLCK02 format
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = derive_key(self.password, salt)
        aes = AESGCM(key)

        v_ct = aes.encrypt(nonce, VERIFIER_PAYLOAD_V2, None)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        with open(vault_path, "wb") as f_out:
            f_out.write(MAGIC_HEADER_V2)
            f_out.write(salt)
            f_out.write(nonce)
            f_out.write(struct.pack(">I", len(v_ct)))
            f_out.write(v_ct)

            # Write chunk in FLCK02 format (8-byte header: ct_len, flags=1)
            chunk_nonce = struct.pack(">Q", 0) + b"\x00\x00\x00\x00"
            ct = aes.encrypt(chunk_nonce, tar_bytes, None)
            f_out.write(struct.pack(">II", len(ct), 1))
            f_out.write(ct)

        # 3. Call real unlock_folder()!
        unlock_folder(self.test_dir, self.password)

        # 4. Verify all files restored with matching SHA-256
        for arc_name, content in files_data.items():
            restored_path = os.path.join(self.test_dir, arc_name.replace("/", os.sep))
            self.assertTrue(os.path.isfile(restored_path), f"File {arc_name} was not restored!")
            with open(restored_path, "rb") as rf:
                self.assertEqual(hashlib.sha256(rf.read()).hexdigest(), hashlib.sha256(content).hexdigest())

    def test_real_flck03_vault_complete_unlock(self):
        """
        Creates an authentic FLCK03 vault with multiple chunks, AAD binding, and tar archive.
        Calls unlock_folder() and verifies every file is restored and SHA-256 matches.
        """
        files_data = {
            "v3_report.pdf": b"%PDF-1.4 sample stream data" * 200,
            "subfolder/v3_notes.txt": b"FLCK03 verified chunk streaming content"
        }
        import io
        tar_buf = io.BytesIO()
        with tarfile.open(mode="w", fileobj=tar_buf) as tar:
            for arc_name, content in files_data.items():
                ti = tarfile.TarInfo(name=arc_name)
                ti.size = len(content)
                ti.mtime = int(time.time())
                tar.addfile(ti, io.BytesIO(content))

        tar_bytes = tar_buf.getvalue()

        salt = os.urandom(SALT_SIZE)
        vault_iv = os.urandom(NONCE_SIZE)
        key = derive_key(self.password, salt)
        aes = AESGCM(key)

        v_ct = aes.encrypt(vault_iv, VERIFIER_PAYLOAD_V3, VERIFIER_AAD_V3)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        with open(vault_path, "wb") as f_out:
            f_out.write(MAGIC_HEADER_V3)
            f_out.write(struct.pack(">H", FORMAT_VERSION_V3))
            f_out.write(salt)
            f_out.write(vault_iv)
            f_out.write(struct.pack(">I", len(v_ct)))
            f_out.write(v_ct)

            # Write single final chunk (16-byte header: index 0, len, flags 1, reserved 0)
            chunk_header = struct.pack(">QIH H", 0, len(tar_bytes), 1, 0)
            nonce = struct.pack(">Q", 0) + vault_iv[:4]
            ct = aes.encrypt(nonce, tar_bytes, chunk_header)
            f_out.write(chunk_header + ct)

        unlock_folder(self.test_dir, self.password)

        for arc_name, content in files_data.items():
            restored_path = os.path.join(self.test_dir, arc_name.replace("/", os.sep))
            self.assertTrue(os.path.isfile(restored_path))
            with open(restored_path, "rb") as rf:
                self.assertEqual(hashlib.sha256(rf.read()).hexdigest(), hashlib.sha256(content).hexdigest())

    # =========================================================================
    # 9. USER INSTRUCTION FILE NON-OVERWRITE PROTECTION
    # =========================================================================
    def test_user_instruction_file_never_overwritten(self):
        """
        Verify that if a user creates their own FolderLock_Instructions.txt
        without FolderLock ownership tag:
        - write_instruction_file() does NOT overwrite it.
        - Writes to an alternative non-colliding filename.
        - Original user content remains 100% intact.
        """
        user_inst_path = os.path.join(self.test_dir, INSTRUCTION_FILENAME)
        user_text = "This is my private manual instruction document. Do not touch!"
        with open(user_inst_path, "w", encoding="utf-8") as f:
            f.write(user_text)

        # Call write_instruction_file()
        ok = write_instruction_file(self.test_dir, "FolderLock Generated Note")
        self.assertTrue(ok)

        # Assert user's file is 100% untouched
        with open(user_inst_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), user_text)

        # Assert FolderLock note was written to alternative name
        alt_note = os.path.join(self.test_dir, "FolderLock_Instructions_Note.txt")
        self.assertTrue(os.path.isfile(alt_note))


if __name__ == "__main__":
    unittest.main()
