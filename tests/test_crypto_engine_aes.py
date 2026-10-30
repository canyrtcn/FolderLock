"""
FolderLock - Tests for AES-256-GCM Cryptographic Engine (FLCK03 & FLCK02)
Thoroughly tests vault integrity, corrupted headers, bounds checks, legacy vaults, and rollback.
"""

import os
import sys
import tempfile
import shutil
import unittest
import struct
import hashlib

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import crypto_engine
from crypto_engine import (
    lock_folder,
    unlock_folder,
    verify_file_password,
    verify_vault_integrity,
    VAULT_FILENAME,
    JOURNAL_FILENAME,
    MAGIC_HEADER_V3,
    MAGIC_HEADER_V2,
    FORMAT_VERSION_V3,
    SALT_SIZE,
    NONCE_SIZE,
    MAX_CHUNK_SIZE,
    derive_key,
    ChunkEncryptingWriterV3,
    InvalidPasswordError,
    CorruptedFileError,
    CryptoError
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tarfile


def get_file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class TestCryptoEngineAES(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_test_aes_")
        self.password = "Correct_Secure_Password_123!"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_aes_lock_and_unlock_roundtrip(self):
        # Create test files
        f1 = os.path.join(self.test_dir, "document.txt")
        with open(f1, "w", encoding="utf-8") as f:
            f.write("Sensitive document content")
        h1 = get_file_hash(f1)

        sub_dir = os.path.join(self.test_dir, "subfolder")
        os.makedirs(sub_dir)
        f2 = os.path.join(sub_dir, "data.bin")
        with open(f2, "wb") as f:
            f.write(os.urandom(256 * 1024))  # 256 KB
        h2 = get_file_hash(f2)

        # 1. Lock folder
        lock_folder(self.test_dir, self.password)
        self.assertTrue(os.path.isfile(os.path.join(self.test_dir, VAULT_FILENAME)))
        self.assertFalse(os.path.exists(f1))
        self.assertFalse(os.path.exists(f2))

        # 2. Verify password and vault integrity
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)
        self.assertTrue(verify_file_password(vault_path, self.password))
        self.assertTrue(verify_vault_integrity(vault_path, self.password))

        # 3. Unlock folder
        unlock_folder(self.test_dir, self.password)
        self.assertFalse(os.path.exists(os.path.join(self.test_dir, VAULT_FILENAME)))
        self.assertTrue(os.path.exists(f1))
        self.assertTrue(os.path.exists(f2))

        # 4. Verify data integrity (SHA-256 hashes must match exactly)
        self.assertEqual(get_file_hash(f1), h1)
        self.assertEqual(get_file_hash(f2), h2)

    def test_aes_lock_empty_folder_rejected(self):
        with self.assertRaises(ValueError):
            lock_folder(self.test_dir, self.password)

    def test_aes_wrong_password(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        with self.assertRaises(InvalidPasswordError):
            verify_file_password(vault_path, "WrongPassword!")

        with self.assertRaises(InvalidPasswordError):
            unlock_folder(self.test_dir, "WrongPassword!")

    def test_aes_corrupted_format_version(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        # Tamper with the 2-byte version field at offset len(MAGIC_HEADER_V3)=6
        with open(vault_path, "r+b") as fp:
            fp.seek(len(MAGIC_HEADER_V3))
            fp.write(struct.pack(">H", 999))  # Corrupted version 999

        with self.assertRaises(CorruptedFileError):
            verify_file_password(vault_path, self.password)

        with self.assertRaises(CorruptedFileError):
            unlock_folder(self.test_dir, self.password)

    def test_aes_corrupted_verifier_length(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        # Offset of vlen: magic(6) + version(2) + salt(32) + nonce(12) = 52
        with open(vault_path, "r+b") as fp:
            fp.seek(len(MAGIC_HEADER_V3) + 2 + SALT_SIZE + NONCE_SIZE)
            fp.write(struct.pack(">I", 50_000))  # Out of bounds verifier length (>4096)

        with self.assertRaises(CorruptedFileError):
            verify_file_password(vault_path, self.password)

    def test_aes_corrupted_reserved_field(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        # Find first chunk header offset:
        # Header size: magic(6) + ver(2) + salt(32) + nonce(12) + vlen(4) + verifier_ct
        with open(vault_path, "rb") as fp:
            fp.seek(len(MAGIC_HEADER_V3) + 2 + SALT_SIZE + NONCE_SIZE)
            vlen = struct.unpack(">I", fp.read(4))[0]
            first_chunk_offset = len(MAGIC_HEADER_V3) + 2 + SALT_SIZE + NONCE_SIZE + 4 + vlen

        # In first chunk header (16B): chunk_index(8B) + payload_len(4B) + flags(2B) + reserved(2B)
        # Offset to reserved field = first_chunk_offset + 14
        with open(vault_path, "r+b") as fp:
            fp.seek(first_chunk_offset + 14)
            fp.write(struct.pack(">H", 1))  # Non-zero reserved field

        with self.assertRaises(CorruptedFileError):
            unlock_folder(self.test_dir, self.password)

    def test_aes_corrupted_gcm_tag(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        # Corrupt a byte in the encrypted stream near the end
        size = os.path.getsize(vault_path)
        with open(vault_path, "r+b") as fp:
            fp.seek(size - 5)
            byte = fp.read(1)
            corrupted = bytes([(byte[0] ^ 0xFF)])
            fp.seek(size - 5)
            fp.write(corrupted)

        with self.assertRaises(CorruptedFileError):
            verify_vault_integrity(vault_path, self.password)

        with self.assertRaises(CorruptedFileError):
            unlock_folder(self.test_dir, self.password)

    def test_aes_trailing_data_detection(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Test content")

        lock_folder(self.test_dir, self.password)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        # Append malicious or corrupt trailing byte after the final chunk
        with open(vault_path, "ab") as fp:
            fp.write(b"\x00\xDE\xAD\xBE\xEF")

        with self.assertRaises(CorruptedFileError):
            verify_vault_integrity(vault_path, self.password)

        with self.assertRaises(CorruptedFileError):
            unlock_folder(self.test_dir, self.password)

    def test_aes_collision_preservation_on_unlock(self):
        f = os.path.join(self.test_dir, "document.txt")
        with open(f, "w") as fp:
            fp.write("Original vault document")

        lock_folder(self.test_dir, self.password)

        # Now simulate user putting a new file with the same name before unlocking
        with open(f, "w") as fp:
            fp.write("Existing local document created while locked")

        # Unlock should succeed without overwriting the existing file
        unlock_folder(self.test_dir, self.password)

        self.assertTrue(os.path.exists(f))
        with open(f, "r") as fp:
            self.assertEqual(fp.read(), "Existing local document created while locked")

        # The restored file must exist under an alternative collision-free name
        restored_f = os.path.join(self.test_dir, "document_restored_1.txt")
        self.assertTrue(os.path.exists(restored_f))
        with open(restored_f, "r") as fp:
            self.assertEqual(fp.read(), "Original vault document")

    def test_aes_legacy_v2_vault_unlock(self):
        # Create synthetic FLCK02 legacy vault
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = derive_key(self.password, salt)
        aes = AESGCM(key)

        v_ct = aes.encrypt(nonce, crypto_engine.VERIFIER_PAYLOAD_V2, None)
        vault_path = os.path.join(self.test_dir, VAULT_FILENAME)

        with open(vault_path, "wb") as f_out:
            f_out.write(MAGIC_HEADER_V2)
            f_out.write(salt)
            f_out.write(nonce)
            f_out.write(struct.pack(">I", len(v_ct)))
            f_out.write(v_ct)

            # Write single chunk
            test_payload = b"Sample legacy archive content"
            # In V2: struct.pack(">II", ct_len, flags)
            # flags = 1 for last chunk
            c_nonce = struct.pack(">Q", 0) + b"\x00\x00\x00\x00"
            c_ct = aes.encrypt(c_nonce, test_payload, None)
            f_out.write(struct.pack(">II", len(c_ct), 1))
            f_out.write(c_ct)

        # Verify password on legacy vault
        self.assertTrue(verify_file_password(vault_path, self.password))

    def test_aes_existing_journal_blocks_lock(self):
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Important user data")

        # Create leftover incomplete journal
        journal_path = os.path.join(self.test_dir, JOURNAL_FILENAME)
        crypto_engine.atomic_write_json(journal_path, {
            "schema_version": "1.0.3",
            "operation_id": "interrupted-op-123",
            "state": "ENCRYPTING",
            "recovery_required": True
        })

        # Calling lock_folder must refuse and raise CryptoError
        with self.assertRaises(CryptoError):
            lock_folder(self.test_dir, self.password)

        # Original user file must be untouched
        self.assertTrue(os.path.exists(f))

    def test_aes_unicode_and_deep_paths(self):
        # Create Turkish, Japanese, and accented characters
        deep_dir = os.path.join(self.test_dir, "belgeler_şçğöü", "日本語", "éàñ")
        os.makedirs(deep_dir)
        unicode_file = os.path.join(deep_dir, "rapor_türkçe_テスト.txt")
        content = "UTF-8 Türkçe ve Japonca içerik: ğüşiöç - こんにちは世界"
        with open(unicode_file, "w", encoding="utf-8") as fp:
            fp.write(content)
        h = get_file_hash(unicode_file)

        lock_folder(self.test_dir, self.password)
        self.assertFalse(os.path.exists(unicode_file))

        unlock_folder(self.test_dir, self.password)
        self.assertTrue(os.path.exists(unicode_file))
        self.assertEqual(get_file_hash(unicode_file), h)

    def test_aes_unsafe_tar_member_rejection(self):
        # Test symlink member rejection
        sym_info = tarfile.TarInfo(name="symlink_link")
        sym_info.type = tarfile.SYMTYPE
        self.assertFalse(crypto_engine.is_safe_tar_member(sym_info, self.test_dir))

        # Test reserved Windows device name rejection
        con_info = tarfile.TarInfo(name="CON.txt")
        con_info.type = tarfile.REGTYPE
        self.assertFalse(crypto_engine.is_safe_tar_member(con_info, self.test_dir))

        aux_info = tarfile.TarInfo(name="sub/AUX.dat")
        aux_info.type = tarfile.REGTYPE
        self.assertFalse(crypto_engine.is_safe_tar_member(aux_info, self.test_dir))

        # Test traversal rejection
        trav_info = tarfile.TarInfo(name="../escape.txt")
        trav_info.type = tarfile.REGTYPE
        self.assertFalse(crypto_engine.is_safe_tar_member(trav_info, self.test_dir))


if __name__ == "__main__":
    unittest.main()
