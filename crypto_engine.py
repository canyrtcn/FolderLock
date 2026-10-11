"""
FolderLock - Cryptographic Engine (Hardened v1.0.3)
Implements AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256,
instant NTFS-based folder protection, and two-phase journaled transactions.

Version 1.0.3 Architecture Updates:
- Integrated with safe_fs: path validation, exclusive operation locking, atomic JSON writes,
  and same-volume atomic no-replace file moves.
- Two-phase journaled transaction model (pending_step -> sync -> execute -> verify -> completed_step).
- Hardened AES lock: full preflight scan, authenticated FLCK03 encryption, pre-commit integrity
  verification, atomic commit, and verified source cleanup (preserves source & committed vault on failure).
- Hardened AES unlock: full integrity check, unique mkdtemp, reader drained to authentic EOF,
  extracted manifest verification, and zero-data-loss collision resolution before removing vault.
- Hardened Instant Lock: pre-record MOVE_PENDING, no-replace move, verified destination,
  strict non-swallowing rollback, and SDDL capture/restoration without icacls /reset.
- Reader validation: enforces FORMAT_VERSION_V3 == 3, bounded verifier length, zero reserved field,
  bounded chunk payload, single final marker, and trailing data detection.
- Full backward compatibility for legacy FLCK02 and FLCK03 vaults.
"""

import os
import sys
import stat
import time
import struct
import shutil
import tarfile
import ctypes
import subprocess
import tempfile
import hashlib
import hmac
import json
import uuid
from typing import Callable, Optional, Tuple, Dict, Any, List, Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

import safe_fs
from safe_fs import (
    validate_protection_root,
    is_safe_relative_path,
    move_no_replace,
    atomic_write_json,
    read_verified_json,
    acquire_operation_lock,
    OperationLock,
    OperationLockError,
    SafeFSError,
    get_file_attributes_safe,
    add_hidden_system_attributes,
    remove_hidden_system_attributes,
    get_security_descriptor_sddl,
    restore_security_descriptor_sddl,
    run_icacls_safe,
    scan_source_tree,
    compute_file_sha256,
    is_same_volume,
    verify_destination_path_safe,
    safe_recreate_directories,
    WIN_NO_WINDOW
)

# Format Magic Headers
MAGIC_HEADER_V2 = b"FLCK02"
MAGIC_HEADER_V3 = b"FLCK03"
FORMAT_VERSION_V3 = 3

VERIFIER_PAYLOAD_V2 = b"FLOCK_V2_AUTH_KEY_VERIFICATION_TOKEN_SECURE"
VERIFIER_PAYLOAD_V3 = b"FLOCK_V3_AUTH_KEY_VERIFICATION_TOKEN_SECURE"
VERIFIER_AAD_V3 = b"FLCK03_VERIFIER_AAD"

SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 300_000
CHUNK_SIZE = 1024 * 1024  # 1 MB streaming chunks for minimal RAM usage (< 2 MB)
MAX_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB maximum allowable chunk payload size (DoS defense)

# Internal metadata file and directory names
VAULT_FILENAME = ".locked_vault"
INSTANT_DATA_DIRNAME = ".locked_data"
META_FILENAME = ".flock_meta"
RELOCK_CONFIG_FILENAME = ".flock_relock"
JOURNAL_FILENAME = ".flock_journal"
INSTANT_JOURNAL_FILENAME = ".flock_instant_journal"

# Legacy helper constants (retained for backward compatibility)
UNLOCKER_FILENAME = "Unlock.exe"
UNLOCKER_TR_FILENAME = "Kilidi Ac.exe"
LOCKER_FILENAME = "Lock.exe"
LOCKER_TR_FILENAME = "Kilitle.exe"
README_FILENAME = "Readme.txt"

# Reserved internal metadata names (ONLY internal artifacts, NEVER user files)
RESERVED_METADATA_NAMES = {
    VAULT_FILENAME,
    VAULT_FILENAME + ".tmp",
    INSTANT_DATA_DIRNAME,
    META_FILENAME,
    RELOCK_CONFIG_FILENAME,
    JOURNAL_FILENAME,
    INSTANT_JOURNAL_FILENAME,
    safe_fs.OP_LOCK_FILENAME,
}

INSTRUCTION_FILENAME = "FolderLock_Instructions.txt"
FOLDERLOCK_OWNERSHIP_TAG = "<!-- FOLDERLOCK_INSTRUCTION_NOTE_V1 -->"

INSTANT_DENY_PERMS = "*S-1-1-0:(OI)(CI)(RD,WD,AD,X,DC,DE,RA,WA)"

README_LOCKED_TEXT = (
    f"{FOLDERLOCK_OWNERSHIP_TAG}\n"
    "====================================================\n"
    "FOLDERLOCK - PROTECTED DIRECTORY / KORUMALI KLASOR\n"
    "====================================================\n\n"
    "[EN] TO UNLOCK THIS FOLDER:\n"
    "1. Open the FolderLock application.\n"
    "2. Drag and drop this folder into FolderLock (or select it in 'Unlock Folder').\n"
    "3. Alternatively, right-click this folder and choose 'FolderLock - Lock / Unlock'.\n"
    "4. Enter your password to restore your files.\n\n"
    "[TR] BU KLASORUN KILIDINI ACMAK ICIN:\n"
    "1. FolderLock uygulamasini acin.\n"
    "2. Bu klasoru FolderLock penceresine surukleyin (veya 'Kilit Ac' sekmesinden secin).\n"
    "3. Alternatif olarak, klasore sag tiklayip 'FolderLock - Lock / Unlock' secenegini secin.\n"
    "4. Sifrenizi girerek dosyalarinizi aninda geri yukleyin.\n"
    "====================================================\n"
)

README_UNLOCKED_TEXT = (
    f"{FOLDERLOCK_OWNERSHIP_TAG}\n"
    "====================================================\n"
    "FOLDERLOCK - UNLOCKED DIRECTORY / ACILMIS KLASOR\n"
    "====================================================\n\n"
    "[EN] TO RE-LOCK THIS FOLDER:\n"
    "1. Open FolderLock and navigate to 'Locked Vault'.\n"
    "2. Click 'Lock' next to this folder to re-lock instantly\n"
    "   with the SAME password without re-typing!\n"
    "3. Or select this folder in the 'Lock Folder' tab.\n\n"
    "[TR] BU KLASORU TEKRAR KILITLEMEK ICIN:\n"
    "1. FolderLock uygulamasinda 'Kilitli Kasam' sekmesine gidin.\n"
    "2. Bu klasorun yanindaki 'Kilitle' dugmesine basarak\n"
    "   sifre yazmadan AYNI sifreyle aninda tekrar kilitleyin!\n"
    "3. Ya da 'Klasor Kilitle' sekmesinden bu klasoru secin.\n"
    "====================================================\n"
)


class CryptoError(Exception):
    """Custom exception for cryptography and protection errors."""
    pass


class InvalidPasswordError(CryptoError):
    """Raised when the password provided is incorrect."""
    pass


class CorruptedFileError(CryptoError):
    """Raised when an encrypted file is corrupted or tampered with."""
    pass


class OperationCancelledError(CryptoError):
    """Raised when the user cancels the operation."""
    pass


# ---------------- WIN32 ATTRIBUTES & ACL WRAPPERS ----------------

def set_file_attributes(path: str, hidden: bool = False, system: bool = False):
    """Legacy helper: adds or removes hidden/system attributes without clobbering existing flags."""
    if os.name != 'nt':
        return
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return
    try:
        if hidden or system:
            add_hidden_system_attributes(path)
        else:
            remove_hidden_system_attributes(path)
    except Exception:
        pass


def run_icacls(args: List[str]) -> subprocess.CompletedProcess:
    """Executes icacls safely without flashing console windows."""
    return run_icacls_safe(args)


# ---------------- NARROW AUDITED FILE REMOVAL APIS ----------------

def remove_verified_file(file_path: str, allowed_names: Optional[Set[str]] = None) -> bool:
    """
    Safely removes a single verified file.
    Refuses to delete directories, symlinks, or files outside allowed_names (if specified).
    Clears read-only attributes on Windows before removal.
    """
    if not os.path.lexists(file_path):
        return True
    if os.path.islink(file_path):
        raise CryptoError(f"Refusing to remove symlink: {file_path}")
    if os.path.isdir(file_path):
        raise CryptoError(f"Refusing to remove directory via remove_verified_file: {file_path}")
    if allowed_names is not None:
        basename = os.path.basename(file_path)
        if basename not in allowed_names and not any(basename.startswith(prefix) for prefix in allowed_names):
            raise CryptoError(f"Refusing to remove file outside allowed set: {file_path}")

    try:
        if os.name == 'nt':
            try:
                get_file_attributes_safe(file_path)
                remove_hidden_system_attributes(file_path)
            except Exception:
                pass
            os.chmod(file_path, stat.S_IWRITE)
        os.remove(file_path)
    except Exception as e:
        raise CryptoError(f"Failed to remove verified file {file_path}: {e}")

    if os.path.lexists(file_path):
        raise CryptoError(f"File still exists after removal attempt: {file_path}")
    return True


def remove_empty_directory(dir_path: str) -> bool:
    """Safely removes an empty directory using os.rmdir (NEVER rmtree)."""
    if not os.path.lexists(dir_path):
        return True
    if os.path.islink(dir_path) or not os.path.isdir(dir_path):
        return False
    try:
        os.rmdir(dir_path)
        return True
    except OSError:
        return False


def remove_temp_extract_dir(temp_dir: str, operation_id: Optional[str] = None) -> bool:
    """
    Safely removes FolderLock's own temporary extraction directory.
    Verifies that the directory is empty before removing, or only contains restored/cleaned items.
    Never recursively deletes un-restored files!
    """
    if not os.path.lexists(temp_dir):
        return True
    basename = os.path.basename(os.path.abspath(temp_dir))
    if not basename.startswith(".tmp_flock_extract_"):
        raise CryptoError(f"Refusing to remove non-temporary directory: {temp_dir}")
    if os.path.islink(temp_dir):
        raise CryptoError(f"Refusing to remove symlink as temp extract dir: {temp_dir}")

    # Check if empty
    try:
        remaining = os.listdir(temp_dir)
        if remaining:
            raise CryptoError(f"Temporary extract directory is not empty ({len(remaining)} items remain): {temp_dir}")
        os.rmdir(temp_dir)
        return True
    except OSError as e:
        raise CryptoError(f"Failed to remove temporary extract directory: {e}")


def remove_source_item_after_commit(item_path: str) -> bool:
    """
    Safely removes a source item after vault commit during SOURCE_CLEANUP state.
    Clears read-only attributes and removes files or directories.
    Returns True if removed, raises CryptoError if removal failed.
    """
    if not os.path.lexists(item_path):
        return True
    if os.path.islink(item_path):
        raise CryptoError(f"Refusing to remove symlink source item {item_path}")
    if os.path.isfile(item_path):
        try:
            if os.name == 'nt':
                os.chmod(item_path, stat.S_IWRITE)
            os.remove(item_path)
        except Exception as e:
            raise CryptoError(f"Failed to remove source file {item_path}: {e}")
        if os.path.lexists(item_path):
            raise CryptoError(f"Source file still exists after removal: {item_path}")
        return True
    elif os.path.isdir(item_path):
        try:
            os.rmdir(item_path)
            return True
        except OSError as e:
            raise CryptoError(f"Directory not empty or locked during cleanup {item_path}: {e}")
    return True


# ---------------- PATH SAFETY & COLLISION PRESERVATION ----------------

def resolve_collision(dest_dir: str, name: str) -> str:
    """
    Finds a safe, non-colliding destination path if a file or directory with the same
    name already exists in dest_dir, preventing accidental overwriting or deletion.
    """
    dest_dir = os.path.abspath(dest_dir)
    clean_name = os.path.basename(name.replace("\\", os.sep).replace("/", os.sep))
    dest_path = os.path.join(dest_dir, clean_name)
    if not os.path.lexists(dest_path):
        return dest_path

    base, ext = os.path.splitext(clean_name)
    counter = 1
    while counter < 100_000:
        candidate = f"{base}_restored_{counter}{ext}"
        candidate_path = os.path.join(dest_dir, candidate)
        if not os.path.lexists(candidate_path):
            if not is_safe_relative_path(candidate, dest_dir):
                raise CryptoError("Path safety violation during collision resolution.")
            return candidate_path
        counter += 1
    raise CryptoError(f"Too many collision candidates for {name} in {dest_dir}")


def is_folderlock_instruction_file(file_path: str) -> bool:
    """Legacy parser, *not* proof that an existing file belongs to FolderLock.

    A user can author the same textual marker, so callers must never use this
    predicate to overwrite or delete a file.
    """
    return False


def write_instruction_file(folder_path: str, content: str, prefer_alternate: bool = False) -> bool:
    """Create a note without changing any pre-existing user file."""
    candidates = (("FolderLock_Instructions_Note.txt",) if prefer_alternate else
                  (INSTRUCTION_FILENAME, "FolderLock_Instructions_Note.txt"))
    for candidate in candidates:
        target = os.path.join(folder_path, candidate)
        try:
            with open(target, "x", encoding="utf-8") as stream:
                stream.write(content)
            return True
        except FileExistsError:
            continue
        except OSError:
            return False
    for _ in range(16):
        target = os.path.join(folder_path, f"FolderLock_Instructions_{uuid.uuid4().hex}.txt")
        try:
            with open(target, "x", encoding="utf-8") as stream:
                stream.write(content)
            return True
        except FileExistsError:
            continue
        except OSError:
            return False
    return False


# ---------------- CRYPTOGRAPHIC UTILITIES ----------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from the password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))


def derive_instant_hash(password: str, salt_bytes: bytes) -> str:
    """Derives verification hash for Instant Lock using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode("utf-8")).hex()


# ---------------- WINDOWS DPAPI ----------------

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def dpapi_protect(data: bytes) -> bytes:
    """Encrypts bytes using Windows DPAPI for the current logged-in user."""
    if os.name != 'nt':
        raise RuntimeError("DPAPI is only supported on Windows.")
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), "flock", None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("CryptProtectData failed")
    res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return res


def dpapi_unprotect(cipher: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI for the current logged-in user."""
    if os.name != 'nt':
        raise RuntimeError("DPAPI is only supported on Windows.")
    in_blob = DATA_BLOB(len(cipher), ctypes.cast(ctypes.create_string_buffer(cipher), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("CryptUnprotectData failed")
    res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return res


def is_authentic_relock_config(file_path: str) -> bool:
    """
    Validates whether an existing .flock_relock file is an authentic FolderLock configuration.
    Must be a regular file (not symlink), valid JSON dict, with magic header 'FLCK_RELOCK_V1',
    valid mode ('crypto' or 'instant'), and valid hex encoded salt and hash fields.
    """
    if not os.path.isfile(file_path):
        return False
    try:
        st = os.lstat(file_path)
        if stat.S_ISLNK(st.st_mode) or safe_fs.is_reparse_point(file_path):
            return False
        data = read_verified_json(file_path)
        if not isinstance(data, dict):
            return False
        if data.get("magic") != "FLCK_RELOCK_V1":
            return False
        if data.get("mode") not in ("crypto", "instant"):
            return False
        salt = data.get("salt", "")
        if not isinstance(salt, str) or (salt and not all(c in "0123456789abcdefABCDEF" for c in salt)):
            return False
        hash_val = data.get("hash", "")
        if not isinstance(hash_val, str) or (hash_val and not all(c in "0123456789abcdefABCDEF" for c in hash_val)):
            return False
        if "dpapi_pwd" in data:
            dpapi_hex = data.get("dpapi_pwd")
            if not isinstance(dpapi_hex, str) or not all(c in "0123456789abcdefABCDEF" for c in dpapi_hex):
                return False
        return True
    except Exception:
        return False


def save_relock_config(folder_path: str, mode: str, salt_hex: str,
                       hash_val: str, password: Optional[str] = None) -> bool:
    """Best-effort convenience metadata. Never replace an existing file.

    The public JSON magic/schema is not an ownership proof. Callers must not
    overwrite even a JSON-shaped file. Existing re-lock data remains untouched.
    """
    relock_file = os.path.join(os.path.abspath(folder_path), RELOCK_CONFIG_FILENAME)
    if os.path.lexists(relock_file):
        return False
    data = {"magic": "FLCK_RELOCK_V1", "mode": mode,
            "salt": salt_hex, "hash": hash_val}
    if mode == "crypto" and password:
        try:
            data["dpapi_pwd"] = dpapi_protect(password.encode("utf-8")).hex()
        except Exception:
            return False
    try:
        with open(relock_file, "x", encoding="utf-8") as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        set_file_attributes(relock_file, hidden=True, system=True)
        return True
    except FileExistsError:
        return False
    except OSError:
        # A partially written newly-created config is not trusted as source data.
        # Do not perform a blind delete because ownership may have changed.
        return False


def get_relock_config(folder_path: str) -> Optional[Dict[str, Any]]:
    """Reads saved re-lock configuration if available."""
    folder_path = os.path.abspath(folder_path)
    relock_file = os.path.join(folder_path, RELOCK_CONFIG_FILENAME)
    if not os.path.isfile(relock_file):
        return None
    try:
        data = read_verified_json(relock_file)
        if data.get("mode") == "crypto" and "dpapi_pwd" in data:
            try:
                dec = dpapi_unprotect(bytes.fromhex(data["dpapi_pwd"]))
                data["password"] = dec.decode("utf-8")
            except Exception:
                data["password"] = None
        return data
    except Exception:
        return None


def deploy_lockers(folder_path: str):
    """Deprecated no-op retained for backward interface compatibility."""
    pass


def deploy_unlockers(folder_path: str):
    """Deprecated no-op retained for backward interface compatibility."""
    pass


def clean_legacy_in_folder_binaries(folder_path: str):
    """Deprecated no-op retained for backward interface compatibility."""
    pass


def is_folder_locked(folder_path: str) -> Optional[str]:
    """
    Checks if a folder is currently locked by FolderLock.
    Returns 'instant', 'crypto', or None.
    """
    if not folder_path or not os.path.isdir(folder_path):
        return None
    if os.path.isdir(os.path.join(folder_path, INSTANT_DATA_DIRNAME)):
        return "instant"
    if os.path.isfile(os.path.join(folder_path, VAULT_FILENAME)):
        return "crypto"
    return None


def get_folder_stats(folder_path: str, exclude_vault: bool = True) -> Tuple[int, int]:
    """Returns (total_files, total_bytes) for the given folder."""
    total_files = 0
    total_bytes = 0
    reserved = RESERVED_METADATA_NAMES
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            if exclude_vault and f in reserved:
                continue
            p = os.path.join(root, f)
            try:
                if not os.path.islink(p):
                    total_bytes += os.path.getsize(p)
                total_files += 1
            except OSError:
                pass
    return total_files, total_bytes


def format_bytes(size_bytes: int) -> str:
    """Formats bytes into human readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


# ---------------- STREAMING AES-256-GCM WRITER (FLCK03) ----------------

class ChunkEncryptingWriterV3:
    """
    Acts as a writable stream for tarfile that encrypts data in 1MB chunks using AES-256-GCM (FLCK03).
    Binds chunk_index, payload_length, and flags into Authenticated Additional Data (AAD).
    Uses a unique 96-bit nonce per chunk derived from vault_iv.
    """
    def __init__(self, out_file, aes_key: bytes, vault_iv: bytes,
                 chunk_size: int = CHUNK_SIZE,
                 on_chunk: Optional[Callable[[int], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.out_file = out_file
        self.aes = AESGCM(aes_key)
        self.vault_iv = vault_iv
        self.chunk_size = chunk_size
        self.buffer = bytearray()
        self.chunk_index = 0
        self.on_chunk = on_chunk
        self.cancel_check = cancel_check
        self._pos = 0

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return False

    def write(self, b: bytes) -> int:
        if self.cancel_check and self.cancel_check():
            raise OperationCancelledError("Operation cancelled by user.")
        self.buffer.extend(b)
        self._pos += len(b)
        while len(self.buffer) >= self.chunk_size:
            chunk = bytes(self.buffer[:self.chunk_size])
            del self.buffer[:self.chunk_size]
            self._write_chunk(chunk, is_last=False)
            if self.on_chunk:
                self.on_chunk(len(chunk))
        return len(b)

    def _write_chunk(self, data: bytes, is_last: bool):
        flags = 1 if is_last else 0
        payload_len = len(data)
        # 16-byte chunk header: chunk_index (8B) + payload_len (4B) + flags (2B) + reserved (2B == 0)
        chunk_header = struct.pack(">QIH H", self.chunk_index, payload_len, flags, 0)
        # Unique 96-bit nonce bound to vault_iv
        nonce = struct.pack(">Q", self.chunk_index) + self.vault_iv[:4]
        # AES-GCM encryption with chunk_header as Associated Authenticated Data (AAD)
        ct = self.aes.encrypt(nonce, data, chunk_header)
        # Write header (16B) followed by ciphertext + tag (payload_len + 16B)
        self.out_file.write(chunk_header + ct)
        self.chunk_index += 1

    def close(self):
        if hasattr(self, 'buffer') and self.buffer is not None:
            remaining = bytes(self.buffer)
            self._write_chunk(remaining, is_last=True)
            if self.on_chunk and len(remaining) > 0:
                self.on_chunk(len(remaining))
            self.buffer = None


# ---------------- STREAMING AES-256-GCM READERS (FLCK03 & FLCK02) ----------------

class ChunkDecryptingReaderV3:
    """
    Acts as a readable stream for tarfile that decrypts FLCK03 AES-256-GCM chunks on-the-fly.
    Strictly verifies chunk index, payload size, reserved field == 0, flags in AAD,
    single final authenticated marker, and trailing data.
    """
    def __init__(self, in_file, aes_key: bytes, vault_iv: bytes,
                 on_chunk: Optional[Callable[[int], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.in_file = in_file
        self.aes = AESGCM(aes_key)
        self.vault_iv = vault_iv
        self.buffer = bytearray()
        self.expected_chunk_index = 0
        self.saw_last_chunk = False
        self.eof = False
        self._pos = 0
        self.on_chunk = on_chunk
        self.cancel_check = cancel_check

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            res = bytearray()
            while not self.eof:
                chunk = self.read(65536)
                if not chunk:
                    break
                res.extend(chunk)
            return bytes(res)

        while len(self.buffer) < size and not self.eof:
            if self.cancel_check and self.cancel_check():
                raise OperationCancelledError("Operation cancelled by user.")

            header_bytes = self.in_file.read(16)
            if len(header_bytes) == 0:
                if not self.saw_last_chunk:
                    raise CorruptedFileError("Vault file truncated prematurely: missing authenticated final chunk marker.")
                self.eof = True
                break

            if len(header_bytes) < 16:
                raise CorruptedFileError("Vault file damaged: incomplete chunk header.")

            if self.saw_last_chunk:
                raise CorruptedFileError("Unexpected trailing data after final authenticated chunk.")

            chunk_index, payload_len, flags, reserved = struct.unpack(">QIH H", header_bytes)

            if reserved != 0:
                raise CorruptedFileError(f"Invalid chunk header: non-zero reserved field ({reserved}).")

            if chunk_index != self.expected_chunk_index:
                raise CorruptedFileError(f"Vault chunk sequence error: expected {self.expected_chunk_index}, got {chunk_index}.")

            if payload_len > MAX_CHUNK_SIZE:
                raise CorruptedFileError(f"Vault chunk size {payload_len} exceeds maximum allowed size.")

            if flags not in (0, 1):
                raise CorruptedFileError(f"Invalid chunk flag: {flags}.")

            # Read ciphertext + 16-byte authentication tag
            ct_len = payload_len + 16
            ct = self.in_file.read(ct_len)
            if len(ct) != ct_len:
                raise CorruptedFileError("Vault chunk truncated prematurely: incomplete ciphertext or missing authentication tag.")

            nonce = struct.pack(">Q", chunk_index) + self.vault_iv[:4]
            try:
                pt = self.aes.decrypt(nonce, ct, header_bytes)
            except InvalidTag:
                raise CorruptedFileError(f"Integrity check failed at chunk {chunk_index}. Data may be corrupted or modified.")

            self.buffer.extend(pt)
            self.expected_chunk_index += 1
            if self.on_chunk:
                self.on_chunk(ct_len + 16)

            if flags == 1:
                if self.saw_last_chunk:
                    raise CorruptedFileError("Duplicate final chunk marker in vault.")
                self.saw_last_chunk = True
                # Check for trailing data immediately
                trailing = self.in_file.read(1)
                if trailing:
                    raise CorruptedFileError("Unexpected trailing data after final authenticated chunk.")
                self.eof = True
                break

        n = min(size, len(self.buffer))
        res = bytes(self.buffer[:n])
        del self.buffer[:n]
        self._pos += n
        return res

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n


class ChunkDecryptingReaderV2:
    """Legacy reader for FLCK02 vaults (v1.0.0 and v1.0.1)."""
    def __init__(self, in_file, aes_key: bytes,
                 on_chunk: Optional[Callable[[int], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.in_file = in_file
        self.aes = AESGCM(aes_key)
        self.buffer = bytearray()
        self.chunk_index = 0
        self.saw_last_chunk = False
        self.eof = False
        self._pos = 0
        self.on_chunk = on_chunk
        self.cancel_check = cancel_check

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            res = bytearray()
            while not self.eof:
                chunk = self.read(65536)
                if not chunk:
                    break
                res.extend(chunk)
            return bytes(res)

        while len(self.buffer) < size and not self.eof:
            if self.cancel_check and self.cancel_check():
                raise OperationCancelledError("Operation cancelled by user.")
            header = self.in_file.read(8)
            if not header or len(header) < 8:
                if not self.saw_last_chunk:
                    raise CorruptedFileError("Legacy vault file truncated prematurely: missing last chunk marker.")
                self.eof = True
                break
            ct_len, flags = struct.unpack(">II", header)
            if ct_len > MAX_CHUNK_SIZE + 64:
                raise CorruptedFileError(f"Invalid chunk size in legacy vault: {ct_len}")
            ct = self.in_file.read(ct_len)
            if len(ct) != ct_len:
                raise CorruptedFileError("File ends prematurely or is damaged.")
            nonce = struct.pack(">Q", self.chunk_index) + b"\x00\x00\x00\x00"
            try:
                pt = self.aes.decrypt(nonce, ct, None)
            except InvalidTag:
                raise CorruptedFileError(f"Integrity check failed at chunk {self.chunk_index}. Data may be corrupted or modified.")

            self.buffer.extend(pt)
            self.chunk_index += 1
            if self.on_chunk:
                self.on_chunk(ct_len + 8)
            if flags == 1:
                self.saw_last_chunk = True
                self.eof = True
                break

        n = min(size, len(self.buffer))
        res = bytes(self.buffer[:n])
        del self.buffer[:n]
        self._pos += n
        return res

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n


# ---------------- VAULT VERIFICATION ----------------

def verify_file_password(vault_path: str, password: str) -> bool:
    """Verifies whether the provided password can authenticate the vault header (supports V2 and V3)."""
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, "rb") as f:
        magic = f.read(len(MAGIC_HEADER_V3))
        if magic == MAGIC_HEADER_V3:
            ver_bytes = f.read(2)
            if len(ver_bytes) != 2:
                raise CorruptedFileError("Damaged vault header.")
            ver = struct.unpack(">H", ver_bytes)[0]
            if ver != FORMAT_VERSION_V3:
                raise CorruptedFileError(f"Unsupported vault format version: {ver}")

            salt = f.read(SALT_SIZE)
            vault_iv = f.read(NONCE_SIZE)
            if len(salt) != SALT_SIZE or len(vault_iv) != NONCE_SIZE:
                raise CorruptedFileError("Damaged vault header.")

            vlen_bytes = f.read(4)
            if len(vlen_bytes) != 4:
                raise CorruptedFileError("Damaged vault header.")
            vlen = struct.unpack(">I", vlen_bytes)[0]
            if vlen < 16 or vlen > 4096:
                raise CorruptedFileError(f"Invalid verifier length: {vlen}")

            v_ct = f.read(vlen)
            if len(v_ct) != vlen:
                raise CorruptedFileError("Damaged vault header.")

            key = derive_key(password, salt)
            aes = AESGCM(key)
            try:
                dec = aes.decrypt(vault_iv, v_ct, VERIFIER_AAD_V3)
                if dec == VERIFIER_PAYLOAD_V3:
                    return True
                raise InvalidPasswordError("Password verification token mismatch.")
            except InvalidTag:
                raise InvalidPasswordError("Incorrect password.")

        elif magic == MAGIC_HEADER_V2:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
                raise CorruptedFileError("Damaged vault header.")
            vlen_bytes = f.read(4)
            if len(vlen_bytes) != 4:
                raise CorruptedFileError("Damaged vault header.")
            vlen = struct.unpack(">I", vlen_bytes)[0]
            if vlen < 16 or vlen > 4096:
                raise CorruptedFileError(f"Invalid verifier length: {vlen}")

            v_ct = f.read(vlen)
            if len(v_ct) != vlen:
                raise CorruptedFileError("Damaged vault header.")

            key = derive_key(password, salt)
            aes = AESGCM(key)
            try:
                dec = aes.decrypt(nonce, v_ct, None)
                if dec == VERIFIER_PAYLOAD_V2:
                    return True
                raise InvalidPasswordError("Password verification token mismatch.")
            except InvalidTag:
                raise InvalidPasswordError("Incorrect password.")
        else:
            raise CorruptedFileError("The selected file is not a valid FolderLock vault.")


def is_safe_tar_member(member: tarfile.TarInfo, dest_dir: str) -> bool:
    """
    Audits a tar archive member before extraction:
    - Blocks non-regular file types (symlinks, hard links, character/block devices, FIFOs).
    - Blocks absolute paths, Windows drive letters, directory traversal ('..').
    - Blocks Windows reserved device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9).
    - Ensures extracted file target stays strictly within dest_dir.
    """
    if not (member.isreg() or member.isdir()):
        return False
    if not is_safe_relative_path(member.name, dest_dir):
        return False
    target = os.path.abspath(os.path.join(dest_dir, member.name))
    prefix = os.path.abspath(dest_dir) + os.sep
    if not (target.startswith(prefix) or target == os.path.abspath(dest_dir)):
        return False
    return True


def verify_vault_integrity(vault_path: str, password: str, expected_manifest: Optional[List[Dict[str, Any]]] = None) -> bool:
    """
    Verifies the complete end-to-end integrity of an encrypted AES-256-GCM vault archive:
    1. Verifies header verifier token with AES-GCM (FLCK03 or FLCK02).
    2. Decrypts every chunk through ChunkDecryptingReader, checking all GCM tags and AAD.
    3. Validates tar stream and all members with is_safe_tar_member.
    4. If expected_manifest is provided, computes SHA-256 of each decrypted member stream
       and verifies 1:1 match with manifest.
    5. Drains stream to authenticated EOF, verifying saw_last_chunk and no trailing data.
    """
    if not os.path.isfile(vault_path):
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, "rb") as f_in:
        magic = f_in.read(len(MAGIC_HEADER_V3))
        if magic == MAGIC_HEADER_V3:
            ver_bytes = f_in.read(2)
            if len(ver_bytes) != 2:
                raise CorruptedFileError("Damaged vault header.")
            ver = struct.unpack(">H", ver_bytes)[0]
            if ver != FORMAT_VERSION_V3:
                raise CorruptedFileError(f"Unsupported vault format version: {ver}")

            salt = f_in.read(SALT_SIZE)
            vault_iv = f_in.read(NONCE_SIZE)
            if len(salt) != SALT_SIZE or len(vault_iv) != NONCE_SIZE:
                raise CorruptedFileError("Damaged vault header.")
            vlen_bytes = f_in.read(4)
            if len(vlen_bytes) != 4:
                raise CorruptedFileError("Damaged vault header.")
            vlen = struct.unpack(">I", vlen_bytes)[0]
            if vlen < 16 or vlen > 4096:
                raise CorruptedFileError(f"Invalid verifier length: {vlen}")
            v_ct = f_in.read(vlen)
            if len(v_ct) != vlen:
                raise CorruptedFileError("Damaged vault header.")

            key = derive_key(password, salt)
            aes = AESGCM(key)
            try:
                dec = aes.decrypt(vault_iv, v_ct, VERIFIER_AAD_V3)
                if dec != VERIFIER_PAYLOAD_V3:
                    raise InvalidPasswordError("Password verification token mismatch.")
            except InvalidTag:
                raise InvalidPasswordError("Incorrect password.")

            dec_reader = ChunkDecryptingReaderV3(f_in, key, vault_iv)

        elif magic == MAGIC_HEADER_V2:
            salt = f_in.read(SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
                raise CorruptedFileError("Damaged vault header.")
            vlen_bytes = f_in.read(4)
            if len(vlen_bytes) != 4:
                raise CorruptedFileError("Damaged vault header.")
            vlen = struct.unpack(">I", vlen_bytes)[0]
            if vlen < 16 or vlen > 4096:
                raise CorruptedFileError(f"Invalid verifier length: {vlen}")
            v_ct = f_in.read(vlen)
            if len(v_ct) != vlen:
                raise CorruptedFileError("Damaged vault header.")

            key = derive_key(password, salt)
            aes = AESGCM(key)
            try:
                dec = aes.decrypt(nonce, v_ct, None)
                if dec != VERIFIER_PAYLOAD_V2:
                    raise InvalidPasswordError("Password verification token mismatch.")
            except InvalidTag:
                raise InvalidPasswordError("Incorrect password.")

            dec_reader = ChunkDecryptingReaderV2(f_in, key)
        else:
            raise CorruptedFileError("The selected file is not a valid FolderLock vault.")

        # Header verified. Now verify the entire encrypted payload stream
        dummy_dir = os.path.dirname(os.path.abspath(vault_path))
        expected_files: Dict[str, Optional[str]] = {}
        verified_files: Set[str] = set()
        if expected_manifest is not None:
            expected_files = {m["rel_path"]: m.get("sha256") for m in expected_manifest if not m.get("is_dir")}

        try:
            with tarfile.open(mode="r|", fileobj=dec_reader) as tar:
                for member in tar:
                    if not is_safe_tar_member(member, dummy_dir):
                        raise CorruptedFileError(f"Security error: unsafe member in archive: {member.name}")
                    clean_name = member.name.replace("\\", "/")
                    if member.isreg():
                        f_mem = tar.extractfile(member)
                        if f_mem:
                            h = hashlib.sha256()
                            while True:
                                chunk = f_mem.read(65536)
                                if not chunk:
                                    break
                                h.update(chunk)
                            mem_hash = h.hexdigest()
                            if expected_manifest is not None and clean_name in expected_files:
                                exp_hash = expected_files[clean_name]
                                if exp_hash and exp_hash != mem_hash:
                                    raise CorruptedFileError(
                                        f"Vault content mismatch: decrypted file {clean_name} SHA-256 "
                                        f"({mem_hash}) does not match manifest ({exp_hash})."
                                    )
                                verified_files.add(clean_name)
                    elif member.isdir():
                        if expected_manifest is not None:
                            verified_files.add(clean_name)
        except (tarfile.TarError, InvalidTag, CorruptedFileError) as e:
            raise CorruptedFileError(f"Vault data stream verification failed: {e}")

        if expected_manifest is not None:
            missing_files = set(expected_files.keys()) - verified_files
            if missing_files:
                raise CorruptedFileError(
                    f"Vault archive incomplete: missing {len(missing_files)} file(s): {list(missing_files)[:5]}"
                )

        # Drain dec_reader to EOF
        while dec_reader.read(65536):
            pass

        if not dec_reader.saw_last_chunk or not dec_reader.eof:
            raise CorruptedFileError("Vault ends prematurely without authentic last chunk marker.")

    return True


# ---------------- TRANSACTION JOURNAL ----------------

class TransactionJournal:
    """
    Two-phase transactional journal for crash resilience and zero data loss.
    Persists operation_id, state, source_manifest, pending_step, and completed_steps.
    """
    def __init__(self, journal_path: str, operation_id: str, operation_type: str, target_path: str):
        self.journal_path = os.path.abspath(journal_path)
        self.data: Dict[str, Any] = {
            "schema_version": "1.0.3",
            "operation_id": operation_id,
            "operation_type": operation_type,
            "target_path": os.path.abspath(target_path),
            "state": "PREPARING",
            "created_at": time.time(),
            "updated_at": time.time(),
            "source_manifest": [],
            "pending_step": None,
            "completed_steps": [],
            "temp_paths": [],
            "vault_identity": {},
            "recovery_required": False
        }
        self.save()

    @classmethod
    def load(cls, journal_path: str) -> Optional['TransactionJournal']:
        if not os.path.isfile(journal_path):
            return None
        try:
            data = read_verified_json(journal_path)
            if not isinstance(data, dict):
                return None
            obj = cls.__new__(cls)
            obj.journal_path = os.path.abspath(journal_path)
            obj.data = data
            return obj
        except Exception:
            return None

    def save(self):
        self.data["updated_at"] = time.time()
        atomic_write_json(self.journal_path, self.data, expected_op_id=self.data.get("operation_id"))
        if os.name == 'nt' and os.path.isfile(self.journal_path):
            try:
                add_hidden_system_attributes(self.journal_path)
            except Exception:
                pass

    def set_state(self, state: str):
        self.data["state"] = state
        self.save()

    def record_pending_step(self, step: Dict[str, Any]):
        self.data["pending_step"] = step
        self.save()

    def record_completed_step(self, step_result: Dict[str, Any]):
        self.data["completed_steps"].append(step_result)
        self.data["pending_step"] = None
        self.save()

    def add_temp_path(self, path: str):
        if path not in self.data["temp_paths"]:
            self.data["temp_paths"].append(path)
            self.save()

    def mark_recovery_required(self, reason: str):
        self.data["recovery_required"] = True
        self.data["recovery_reason"] = reason
        self.save()

    def remove(self):
        if os.path.lexists(self.journal_path):
            try:
                if os.name == 'nt':
                    remove_hidden_system_attributes(self.journal_path)
                os.remove(self.journal_path)
            except Exception:
                pass


def _write_journal(journal_path: str, data: Dict[str, Any]):
    """Legacy helper for backward interface compatibility."""
    atomic_write_json(journal_path, data)


# ---------------- AES LOCK OPERATION (FLCK03 & TRANSACTION STATE MACHINE) ----------------

def lock_folder(folder_path: str, password: str,
                progress_callback: Optional[Callable[[float, str], None]] = None,
                cancel_check: Optional[Callable[[], bool]] = None) -> str:
    """
    In-Place Folder Locking (AES-256-GCM / FLCK03):
    - Full preflight audit: path validation, reparse point rejection, journal check, disk space check.
    - Two-phase journaled transaction model.
    - Verifies archive integrity end-to-end BEFORE committing vault.
    - Safe source cleanup: verifies item hashes, removes items, never advances on error.
    - Zero data loss: preserves source files and committed vault on failure (RECOVERY_REQUIRED).
    """
    folder_path = validate_protection_root(folder_path)

    if is_folder_locked(folder_path):
        raise ValueError("The folder is already locked.")

    if not password:
        raise ValueError("Password cannot be empty.")

    # A legacy instruction-name collision is ambiguous: the textual ownership
    # marker is user-forgeable. Refuse before changing the folder rather than
    # deleting the file or silently replacing it with a generated note.
    if os.path.lexists(os.path.join(folder_path, INSTRUCTION_FILENAME)):
        raise CryptoError("Existing FolderLock_Instructions.txt cannot be authenticated as internal data; rename or back up this file before locking.")

    vault_file = os.path.join(folder_path, VAULT_FILENAME)
    if os.path.lexists(vault_file):
        raise CryptoError("A locked vault (.locked_vault) already exists in this directory. Please resolve before locking.")

    if os.path.lexists(os.path.join(folder_path, INSTANT_DATA_DIRNAME)):
        raise CryptoError("An Instant Lock container already exists in this directory. Please unlock or recover it first.")

    journal_path = os.path.join(folder_path, JOURNAL_FILENAME)

    # Check for existing uncompleted journal
    if os.path.isfile(journal_path):
        prev_journal = TransactionJournal.load(journal_path)
        if prev_journal:
            state = prev_journal.data.get("state")
            if state in ("VAULT_COMMITTED", "SOURCE_CLEANUP") and os.path.isfile(vault_file):
                # Interrupted cleanup after vault was committed: resume cleanup
                pass
            else:
                raise CryptoError(
                    f"An interrupted operation was detected in this folder (state: {state}). "
                    "Please run recovery before locking."
                )
        else:
            raise CryptoError("An unrecognized journal file was found. Recovery required.")

    with acquire_operation_lock(folder_path, "aes_lock") as op_lock:
        if progress_callback:
            progress_callback(0.02, "Scanning folder contents...")

        # Preserve pre-existing instruction name; pack it as user data.
        instruction_path = os.path.join(folder_path, INSTRUCTION_FILENAME)
        original_instruction_existed = os.path.lexists(instruction_path)
        # Existing instruction-named files are user data; never delete by marker.

        # Only this operation's verified root lock and journal are internal.
        # Root .flock_meta and .flock_relock may be user-owned and must be packed.
        active_reserved = {
            VAULT_FILENAME, INSTANT_DATA_DIRNAME, JOURNAL_FILENAME,
            INSTANT_JOURNAL_FILENAME, safe_fs.OP_LOCK_FILENAME,
        }
        # Ambiguous root journal names must never be silently excluded.
        if os.path.lexists(os.path.join(folder_path, INSTANT_JOURNAL_FILENAME)):
            raise CryptoError("Unexpected Instant journal in AES source folder; recovery required.")

        # Safe preflight scan
        manifest, total_files, total_bytes = scan_source_tree(folder_path, active_reserved)
        if not manifest:
            raise ValueError("The folder contains no items to protect.")

        if total_bytes == 0:
            total_bytes = 1024

        temp_vault_file = os.path.join(folder_path, f".flock_tmp_vault_{op_lock.operation_id}.tmp")

        # Initialize transaction journal
        journal = TransactionJournal(journal_path, op_lock.operation_id, "aes_lock", folder_path)
        journal.data["source_manifest"] = manifest
        journal.add_temp_path(temp_vault_file)
        journal.set_state("PREPARING")

        processed_bytes = 0

        def on_chunk(bytes_written: int):
            nonlocal processed_bytes
            processed_bytes += bytes_written
            pct = min(0.90, 0.05 + (processed_bytes / total_bytes) * 0.85)
            if progress_callback:
                progress_callback(pct, f"Encrypting: {format_bytes(processed_bytes)} / {format_bytes(total_bytes)}")

        try:
            # State: ENCRYPTING
            journal.set_state("ENCRYPTING")

            salt = os.urandom(SALT_SIZE)
            vault_iv = os.urandom(NONCE_SIZE)
            key = derive_key(password, salt)
            aes = AESGCM(key)

            verifier_ct = aes.encrypt(vault_iv, VERIFIER_PAYLOAD_V3, VERIFIER_AAD_V3)

            with open(temp_vault_file, "wb") as f_out:
                f_out.write(MAGIC_HEADER_V3)
                f_out.write(struct.pack(">H", FORMAT_VERSION_V3))
                f_out.write(salt)
                f_out.write(vault_iv)
                f_out.write(struct.pack(">I", len(verifier_ct)))
                f_out.write(verifier_ct)

                enc_writer = ChunkEncryptingWriterV3(
                    f_out, key, vault_iv,
                    chunk_size=CHUNK_SIZE,
                    on_chunk=on_chunk,
                    cancel_check=cancel_check
                )
                with tarfile.open(mode="w|", fileobj=enc_writer) as tar:
                    for item_info in manifest:
                        if cancel_check and cancel_check():
                            raise OperationCancelledError("Operation cancelled by user.")
                        rel_p = item_info["rel_path"]
                        full_p = os.path.join(folder_path, rel_p.replace("/", os.sep))

                        if not os.path.lexists(full_p):
                            raise CryptoError(f"Source item disappeared during encryption: {rel_p}")

                        if item_info.get("is_dir"):
                            tar.add(full_p, arcname=rel_p, recursive=False)
                        else:
                            st = os.lstat(full_p)
                            if st.st_size != item_info["size"]:
                                raise CryptoError(f"Source file modified during encryption: {rel_p}")
                            tar.add(full_p, arcname=rel_p, recursive=False)
                enc_writer.close()

            # State: VERIFYING
            if progress_callback:
                progress_callback(0.92, "Verifying encryption archive integrity...")

            journal.set_state("VERIFYING")
            verify_vault_integrity(temp_vault_file, password, expected_manifest=manifest)

            # State: VAULT_COMMITTED
            if progress_callback:
                progress_callback(0.95, "Committing secure vault...")

            journal.record_pending_step({
                "action": "COMMIT_VAULT",
                "src": temp_vault_file,
                "dst": vault_file
            })
            move_no_replace(temp_vault_file, vault_file)
            set_file_attributes(vault_file, hidden=True, system=True)

            journal.record_completed_step({
                "action": "COMMIT_VAULT",
                "src": temp_vault_file,
                "dst": vault_file,
                "status": "COMMITTED"
            })
            journal.set_state("VAULT_COMMITTED")

            # State: SOURCE_CLEANUP
            if progress_callback:
                progress_callback(0.97, "Securing folder contents...")

            journal.set_state("SOURCE_CLEANUP")

            # 1. Audit for any unexpected new items created during encryption
            current_on_disk = set()
            for r, d_list, f_list in os.walk(folder_path):
                rel_r = os.path.relpath(r, folder_path)
                if rel_r == ".":
                    d_list[:] = [d for d in d_list if d not in active_reserved]
                for d in d_list:
                    current_on_disk.add(os.path.relpath(os.path.join(r, d), folder_path).replace("\\", "/"))
                for f in f_list:
                    if rel_r == "." and f in active_reserved:
                        continue
                    current_on_disk.add(os.path.relpath(os.path.join(r, f), folder_path).replace("\\", "/"))

            manifest_paths = {item["rel_path"] for item in manifest}
            unexpected = current_on_disk - manifest_paths
            if unexpected:
                journal.mark_recovery_required(
                    f"Unexpected new items detected prior to cleanup: {list(unexpected)[:5]}"
                )
                raise CryptoError(
                    f"Unexpected new item(s) detected in folder prior to source cleanup: {list(unexpected)[:5]}. "
                    "Plaintext deletion refused; original files and verified vault preserved. Recovery required."
                )

            # 2. For each file, verify initial SHA-256 and size immediately before deletion
            for item_info in manifest:
                if item_info.get("is_dir"):
                    continue
                rel_p = item_info["rel_path"]
                full_p = os.path.join(folder_path, rel_p.replace("/", os.sep))

                if not os.path.lexists(full_p):
                    journal.mark_recovery_required(f"Source file disappeared prior to deletion: {rel_p}")
                    raise CryptoError(f"Source file disappeared before deletion: {rel_p}")

                # Record intent *before* acquiring the exclusive handle. This
                # eliminates journal callbacks between the final verification
                # and deletion of the same file identity.
                journal.record_pending_step({"action": "CLEANUP_FILE", "path": rel_p})
                try:
                    safe_fs.delete_verified_source_file(
                        full_p, item_info["sha256"], item_info["size"]
                    )
                except Exception as ex:
                    journal.mark_recovery_required(f"Source cleanup refused for {rel_p}: {ex}")
                    raise CryptoError(
                        f"Source content modified prior to deletion or source cleanup refused for {rel_p}; verified vault, "
                        "remaining source files, and recovery journal retained."
                    ) from ex

                journal.record_completed_step({"action": "CLEANUP_FILE", "path": rel_p, "status": "REMOVED"})

            # Clean empty directories left behind (from deepest to shallowest)
            all_dirs = []
            for root, dirs, files in os.walk(folder_path):
                if root != folder_path:
                    all_dirs.append(root)

            for d_path in sorted(all_dirs, key=lambda p: len(p.split(os.sep)), reverse=True):
                try:
                    if os.path.isdir(d_path) and not os.listdir(d_path):
                        os.rmdir(d_path)
                except OSError:
                    pass

            # Write instruction note
            write_instruction_file(folder_path, README_LOCKED_TEXT,
                                   prefer_alternate=original_instruction_existed)

            # State: COMPLETED -> remove journal only upon full success
            journal.set_state("COMPLETED")
            journal.remove()

            if progress_callback:
                progress_callback(1.0, "Folder successfully locked!")

            return folder_path

        except Exception as e:
            # If temp vault still exists, clean it up
            if os.path.isfile(temp_vault_file):
                try:
                    os.remove(temp_vault_file)
                except Exception:
                    pass
            # If vault was committed, keep journal with RECOVERY_REQUIRED
            if journal.data.get("state") in ("VAULT_COMMITTED", "SOURCE_CLEANUP"):
                journal.mark_recovery_required(str(e))
            else:
                journal.remove()
            raise e


# ---------------- AES UNLOCK OPERATION (SAFE EXTRACTION & COLLISION RESOLUTION) ----------------

def unlock_folder(folder_path: str, password: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  cancel_check: Optional[Callable[[], bool]] = None,
                  is_recovery: bool = False) -> str:
    """
    Unlocks an in-place locked folder (AES-256-GCM / FLCK03 or legacy FLCK02).
    - Verifies password & end-to-end archive integrity before altering files.
    - Extracts tar into unique temporary directory with member safety checks.
    - Drains decrypting reader to verify authentic final chunk marker.
    - Restores files with non-clobbering collision resolution.
    - Removes .locked_vault ONLY AFTER all files are restored and verified.
    """
    folder_path = os.path.abspath(folder_path)

    if os.path.isdir(folder_path):
        target_dir = folder_path
        vault_file = os.path.join(folder_path, VAULT_FILENAME)
        if not os.path.isfile(vault_file):
            raise FileNotFoundError(f"No locked vault found inside: {folder_path}")
    elif os.path.isfile(folder_path):
        target_dir = os.path.dirname(folder_path)
        vault_file = folder_path
    else:
        raise FileNotFoundError(f"Path not found: {folder_path}")

    target_dir = validate_protection_root(target_dir)

    if progress_callback:
        progress_callback(0.05, "Verifying password and vault integrity...")

    verify_file_password(vault_file, password)
    verify_vault_integrity(vault_file, password)

    if progress_callback:
        progress_callback(0.15, "Integrity verified. Preparing safe extraction...")

    vault_size = os.path.getsize(vault_file)
    if vault_size == 0:
        vault_size = 1024

    processed_bytes = 0

    def on_chunk(bytes_read: int):
        nonlocal processed_bytes
        processed_bytes += bytes_read
        pct = min(0.85, 0.15 + (processed_bytes / vault_size) * 0.70)
        if progress_callback:
            progress_callback(pct, f"Decrypting: {format_bytes(processed_bytes)} / {format_bytes(vault_size)}")

    with acquire_operation_lock(target_dir, "aes_recovery" if is_recovery else "aes_unlock", is_recovery=is_recovery) as op_lock:
        journal_path = os.path.join(target_dir, JOURNAL_FILENAME)
        temp_extract_dir = tempfile.mkdtemp(prefix=".tmp_flock_extract_", dir=target_dir)

        # Check for existing journal from interrupted operation:
        existing_journal = TransactionJournal.load(journal_path) if os.path.isfile(journal_path) else None
        if existing_journal is not None:
            # Validate journal schema and adopt its operation_id to prevent overwrite conflicts
            journal = existing_journal
            journal.data["operation_type"] = "aes_unlock_recovery"
            journal.add_temp_path(temp_extract_dir)
            journal.set_state("EXTRACTING")
        else:
            journal = TransactionJournal(journal_path, op_lock.operation_id, "aes_unlock", target_dir)
            journal.add_temp_path(temp_extract_dir)
            journal.set_state("EXTRACTING")

        try:
            with open(vault_file, "rb") as f_in:
                magic = f_in.read(len(MAGIC_HEADER_V3))
                if magic == MAGIC_HEADER_V3:
                    f_in.seek(2, os.SEEK_CUR)  # skip version
                    salt = f_in.read(SALT_SIZE)
                    vault_iv = f_in.read(NONCE_SIZE)
                    verifier_len = struct.unpack(">I", f_in.read(4))[0]
                    f_in.seek(verifier_len, os.SEEK_CUR)
                    key = derive_key(password, salt)
                    dec_reader = ChunkDecryptingReaderV3(
                        f_in, key, vault_iv,
                        on_chunk=on_chunk,
                        cancel_check=cancel_check
                    )
                elif magic == MAGIC_HEADER_V2:
                    salt = f_in.read(SALT_SIZE)
                    nonce = f_in.read(NONCE_SIZE)
                    verifier_len = struct.unpack(">I", f_in.read(4))[0]
                    f_in.seek(verifier_len, os.SEEK_CUR)
                    key = derive_key(password, salt)
                    dec_reader = ChunkDecryptingReaderV2(
                        f_in, key,
                        on_chunk=on_chunk,
                        cancel_check=cancel_check
                    )
                else:
                    raise CorruptedFileError("Unrecognized vault format.")

                with tarfile.open(mode="r|", fileobj=dec_reader) as tar:
                    for member in tar:
                        if not is_safe_tar_member(member, temp_extract_dir):
                            raise CorruptedFileError(f"Security error: dangerous member rejected in archive: {member.name}")
                        if hasattr(tarfile, 'data_filter'):
                            tar.extract(member, path=temp_extract_dir, filter='data')
                        else:
                            tar.extract(member, path=temp_extract_dir)

                # Drain decrypting reader to verify authentic EOF and trailing data checks
                while dec_reader.read(65536):
                    pass

                if not dec_reader.saw_last_chunk or not dec_reader.eof:
                    raise CorruptedFileError("Vault stream ended prematurely without authenticated final chunk.")

            # State: RESTORING_ITEMS
            if progress_callback:
                progress_callback(0.88, "Restoring decrypted files...")

            journal.set_state("RESTORING_ITEMS")

            # Pre-validate all target destination paths against symlinks, junctions, reparse points
            for root_ext, dirs_ext, files_ext in os.walk(temp_extract_dir):
                rel_d = os.path.relpath(root_ext, temp_extract_dir)
                if rel_d != ".":
                    verify_destination_path_safe(target_dir, rel_d)
                for f_name in files_ext:
                    rel_f = os.path.join(rel_d, f_name) if rel_d != "." else f_name
                    verify_destination_path_safe(target_dir, rel_f)

            # 1. Recreate directory hierarchy safely (including empty subdirectories)
            for root_ext, dirs_ext, files_ext in os.walk(temp_extract_dir):
                rel_d = os.path.relpath(root_ext, temp_extract_dir)
                if rel_d != ".":
                    safe_recreate_directories(target_dir, rel_d)

            # 2. Restore all files with collision resolution and duplicate-safe checks
            restored_items = []
            for root_ext, dirs_ext, files_ext in os.walk(temp_extract_dir):
                rel_d = os.path.relpath(root_ext, temp_extract_dir)
                dest_sub = target_dir if rel_d == "." else os.path.join(target_dir, rel_d)
                for f_name in files_ext:
                    src_f = os.path.join(root_ext, f_name)
                    dst_f = os.path.join(dest_sub, f_name)

                    # Re-verify dst_f immediately before moving
                    verify_destination_path_safe(target_dir, os.path.relpath(dst_f, target_dir))

                    if os.path.lexists(dst_f):
                        # File already on disk (e.g. interrupted SOURCE_CLEANUP left it behind):
                        # If identical content, preserve disk copy and delete extract copy
                        if compute_file_sha256(src_f) == compute_file_sha256(dst_f):
                            os.remove(src_f)
                            restored_items.append(dst_f)
                            continue
                        # If content differs, use safe collision resolution
                        dst_f = resolve_collision(dest_sub, f_name)
                        verify_destination_path_safe(target_dir, os.path.relpath(dst_f, target_dir))

                    journal.record_pending_step({
                        "action": "RESTORE_ITEM",
                        "src": src_f,
                        "dst": dst_f
                    })
                    move_no_replace(src_f, dst_f)
                    journal.record_completed_step({
                        "action": "RESTORE_ITEM",
                        "src": src_f,
                        "dst": dst_f,
                        "status": "MOVED"
                    })
                    restored_items.append(dst_f)

            # 3. Clean extracted subdirectories in reverse depth order
            all_ext_dirs = []
            for root_ext, dirs_ext, files_ext in os.walk(temp_extract_dir):
                if root_ext != temp_extract_dir:
                    all_ext_dirs.append(root_ext)
            for d in sorted(all_ext_dirs, key=lambda p: len(p.split(os.sep)), reverse=True):
                try:
                    os.rmdir(d)
                except OSError:
                    pass

            remove_temp_extract_dir(temp_extract_dir, operation_id=journal.data.get("operation_id"))

            if progress_callback:
                progress_callback(0.95, "Finalizing restored folder...")

            # Clean up vault ONLY AFTER all items are safely restored and temp dir removed
            remove_verified_file(vault_file, allowed_names={VAULT_FILENAME})

            # Save re-lock configuration
            save_relock_config(target_dir, mode="crypto", salt_hex=salt.hex(), hash_val="", password=password)

            # Clean old instruction file if present and write unlocked note
            instruction_path = os.path.join(target_dir, INSTRUCTION_FILENAME)
        # Existing instruction-named files are user data; never delete by marker.
            write_instruction_file(target_dir, README_UNLOCKED_TEXT)

            # Complete transaction
            journal.set_state("COMPLETED")
            journal.remove()

            if progress_callback:
                progress_callback(1.0, "Folder successfully unlocked!")

            return target_dir

        except Exception as e:
            # On failure: preserve temp extract dir, preserve vault, preserve journal
            if os.path.isfile(vault_file):
                pass
            journal.mark_recovery_required(str(e))
            raise e


# ---------------- INSTANT LOCK OPERATION (NTFS ACL + METADATA CONTAINER) ----------------

def lock_folder_instant(folder_path: str, password: Optional[str] = None,
                        salt_hex: Optional[str] = None, hash_val: Optional[str] = None,
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> Tuple[str, str]:
    """
    Instant Lock (NTFS ACL + .locked_data Container):
    - Full preflight audit and exclusive lock.
    - Two-phase journaled file moves (MOVE_PENDING -> move_no_replace -> MOVE_DONE).
    - Captures container security descriptor before applying deny ACE.
    - Non-swallowing rollback: verifies each rollback move and reports errors.
    """
    folder_path = validate_protection_root(folder_path)

    if is_folder_locked(folder_path):
        raise ValueError("The folder is already locked.")

    if not salt_hex or not hash_val:
        if not password:
            raise ValueError("Password cannot be empty.")
        salt_bytes = os.urandom(SALT_SIZE)
        salt_hex = salt_bytes.hex()
        pwd_hash = derive_instant_hash(password, salt_bytes)
    else:
        pwd_hash = hash_val

    if progress_callback:
        progress_callback(0.1, "Initializing Instant Lock...")

    with acquire_operation_lock(folder_path, "instant_lock") as op_lock:
        locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)
        if os.path.lexists(locked_data_dir):
            raise CryptoError("Instant lock data container (.locked_data) already exists.")

        # Preserve user-created instruction file.
        instruction_path = os.path.join(folder_path, INSTRUCTION_FILENAME)
        original_instruction_existed = os.path.lexists(instruction_path)
        # Existing instruction-named files are user data; never delete by marker.

        # Collect user items to secure
        items_to_lock = [item for item in os.listdir(folder_path) if item not in RESERVED_METADATA_NAMES]
        if not items_to_lock:
            raise ValueError("The folder contains no items to protect.")

        os.makedirs(locked_data_dir, exist_ok=False)

        # Capture initial DACL / SDDL
        orig_sddl = get_security_descriptor_sddl(locked_data_dir)

        meta_path = os.path.join(locked_data_dir, META_FILENAME)
        meta_data = {
            "magic": "FLCK_INSTANT_V1",
            "salt": salt_hex,
            "hash": pwd_hash,
            "sddl": orig_sddl or ""
        }
        atomic_write_json(meta_path, meta_data)

        instant_journal_path = os.path.join(folder_path, INSTANT_JOURNAL_FILENAME)
        journal = TransactionJournal(instant_journal_path, op_lock.operation_id, "instant_lock", folder_path)
        journal.set_state("MOVING_ITEMS")

        if progress_callback:
            progress_callback(0.4, "Securing items into container...")

        # Transactional file moves
        moved_items: List[Tuple[str, str]] = []
        try:
            for item in items_to_lock:
                src = os.path.join(folder_path, item)
                dst = os.path.join(locked_data_dir, item)
                journal.record_pending_step({
                    "action": "MOVE_TO_CONTAINER",
                    "src": src,
                    "dst": dst
                })
                move_no_replace(src, dst)
                journal.record_completed_step({
                    "action": "MOVE_TO_CONTAINER",
                    "src": src,
                    "dst": dst,
                    "status": "MOVED"
                })
                moved_items.append((src, dst))
        except Exception as e:
            # Strict verified rollback: move back each completed item
            rollback_failed = False
            for orig_src, moved_dst in reversed(moved_items):
                try:
                    if os.path.lexists(moved_dst):
                        move_no_replace(moved_dst, orig_src)
                except Exception:
                    rollback_failed = True

            if rollback_failed:
                journal.mark_recovery_required("Rollback move failed.")
                raise CryptoError(f"Critical error: failed to rollback items. Recovery required: {e}")

            remove_verified_file(meta_path, allowed_names={META_FILENAME})
            remove_empty_directory(locked_data_dir)
            journal.remove()
            raise CryptoError(f"Failed to secure items into container: {e}")

        # Set hidden + system on .locked_data via safe Win32 API
        add_hidden_system_attributes(locked_data_dir)

        # Apply Universal SID deny ACE on .locked_data
        res_deny = run_icacls_safe([locked_data_dir, "/deny", INSTANT_DENY_PERMS])
        if res_deny.returncode != 0:
            # Rollback if ACL application fails
            run_icacls_safe([locked_data_dir, "/remove:d", "*S-1-1-0"])
            remove_hidden_system_attributes(locked_data_dir)
            rollback_failed = False
            rollback_errors = []
            for orig_src, moved_dst in reversed(moved_items):
                try:
                    if os.path.lexists(moved_dst):
                        move_no_replace(moved_dst, orig_src)
                except Exception as ex:
                    rollback_failed = True
                    rollback_errors.append(f"{moved_dst} -> {orig_src}: {ex}")

            # Verify that each moved item is actually restored
            for orig_src, moved_dst in moved_items:
                if not os.path.lexists(orig_src):
                    rollback_failed = True
                    rollback_errors.append(f"Item missing at original path: {orig_src}")

            if rollback_failed:
                journal.mark_recovery_required(f"ACL rollback failed: {'; '.join(rollback_errors)}")
                raise CryptoError(
                    f"Critical error: Failed to apply NTFS permissions and rollback failed to restore all items ({len(rollback_errors)} error(s)). "
                    "Items remain safely in .locked_data container; metadata and journal preserved. Recovery required."
                )

            remove_verified_file(meta_path, allowed_names={META_FILENAME})
            remove_empty_directory(locked_data_dir)
            journal.remove()
            raise CryptoError("Failed to apply NTFS access control permissions. Operation safely rolled back.")

        # Remove instant journal once successfully locked
        journal.set_state("COMPLETED")
        journal.remove()

        if progress_callback:
            progress_callback(0.8, "Finalizing protection...")

        # Write instruction note
        write_instruction_file(folder_path, README_LOCKED_TEXT,
                                   prefer_alternate=original_instruction_existed)

        if progress_callback:
            progress_callback(1.0, "Folder successfully locked!")

        return salt_hex, pwd_hash


# ---------------- INSTANT UNLOCK OPERATION ----------------

def unlock_folder_instant(folder_path: str, password: str,
                          salt_hex: Optional[str] = None,
                          expected_hash_hex: Optional[str] = None) -> bool:
    """
    Unlocks an Instant-Locked folder:
    - Verifies password against .flock_meta.
    - Never uses icacls /reset! Restores original SDDL or uses targeted ACE removal.
    - Moves all protected items back to folder_path with safe collision resolution.
    - Fail-safe: if password check fails, deny ACE is restored immediately.
    """
    folder_path = validate_protection_root(folder_path)
    locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)

    if not os.path.isdir(locked_data_dir):
        # Legacy root-deny mode cannot be authenticated without verifiers.
        # Do not mutate the user's ACL until proof has been validated.
        if not salt_hex or not expected_hash_hex:
            raise CorruptedFileError(
                "Legacy root ACL cannot be unlocked without stored password "
                "verifiers; use documented administrator recovery."
            )
        try:
            salt_bytes = bytes.fromhex(salt_hex)
            if len(salt_bytes) != SALT_SIZE or len(expected_hash_hex) != 64:
                raise ValueError("Invalid legacy password verifier")
            derived = derive_instant_hash(password, salt_bytes)
        except (ValueError, TypeError) as exc:
            raise CorruptedFileError("Invalid legacy verifier") from exc
        if not hmac.compare_digest(derived, expected_hash_hex):
            raise InvalidPasswordError("Incorrect password")
        res_chk = run_icacls_safe([folder_path])
        if "(DENY)" in (res_chk.stdout or "") and res_chk.returncode == 0:
            res_rm = run_icacls_safe([folder_path, "/remove:d", "*S-1-1-0"])
            if res_rm.returncode != 0:
                raise CryptoError("Unable to restore legacy NTFS permissions")
            remove_hidden_system_attributes(folder_path)
            return True
        raise FileNotFoundError(f"No locked data container found inside: {folder_path}")

    with acquire_operation_lock(folder_path, "instant_unlock") as op_lock:
        # Temporarily remove deny ACE to inspect metadata
        res_rm = run_icacls_safe([locked_data_dir, "/remove:d", "*S-1-1-0"])
        try:
            remove_hidden_system_attributes(locked_data_dir)
        except Exception:
            pass

        meta_path = os.path.join(locked_data_dir, META_FILENAME)
        verified = False
        saved_sddl = None

        try:
            if os.path.isfile(meta_path):
                try:
                    meta = read_verified_json(meta_path)
                    salt_hex = meta.get("salt", salt_hex)
                    expected_hash_hex = meta.get("hash", expected_hash_hex)
                    saved_sddl = meta.get("sddl")
                except Exception:
                    pass

            if not salt_hex or not expected_hash_hex or len(salt_hex) != 64 or len(expected_hash_hex) != 64:
                raise CorruptedFileError("Lock metadata is missing or corrupted.")

            salt_bytes = bytes.fromhex(salt_hex)
            derived = derive_instant_hash(password, salt_bytes)

            if not hmac.compare_digest(derived, expected_hash_hex):
                raise InvalidPasswordError("Incorrect password.")

            verified = True

        finally:
            if not verified:
                # FAIL-SAFE: Re-apply deny and hidden attributes immediately if verification failed
                add_hidden_system_attributes(locked_data_dir)
                run_icacls_safe([locked_data_dir, "/deny", INSTANT_DENY_PERMS])

        # Password verified! Restore DACL if SDDL was saved
        if saved_sddl:
            ok_sddl = restore_security_descriptor_sddl(locked_data_dir, saved_sddl)
            if not ok_sddl:
                res_rm_d = run_icacls_safe([locked_data_dir, "/remove:d", "*S-1-1-0"])
                if res_rm_d.returncode != 0:
                    raise CryptoError("Failed to remove NTFS deny permissions or restore security descriptor.")

        # Restore items safely with collision resolution
        for item in os.listdir(locked_data_dir):
            if item == META_FILENAME:
                continue
            src = os.path.join(locked_data_dir, item)
            dst = resolve_collision(folder_path, item)
            move_no_replace(src, dst)

        # Remove metadata only after all items are successfully restored
        remove_verified_file(meta_path, allowed_names={META_FILENAME})

        # Remove container directory only if empty
        remove_empty_directory(locked_data_dir)

        # Save re-lock configuration
        save_relock_config(folder_path, mode="instant", salt_hex=salt_hex, hash_val=expected_hash_hex)

        # Clean old instruction note and write unlocked note
        instruction_path = os.path.join(folder_path, INSTRUCTION_FILENAME)
        # Existing instruction-named files are user data; never delete by marker.
        write_instruction_file(folder_path, README_UNLOCKED_TEXT)

        return True


# ---------------- INSTANT LOCK RECOVERY OPERATION ----------------

def recover_instant_folder(folder_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Recovers items from an interrupted Instant-Locked folder.
    Strict password verification required. Never uses icacls /reset!
    Returns (success: bool, message: str).
    """
    if not password:
        return False, "Password is required for Instant Lock recovery."

    folder_path = validate_protection_root(folder_path)
    locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)

    if not os.path.isdir(locked_data_dir):
        # Check if root folder had deny permissions
        res_chk = run_icacls_safe([folder_path])
        if "*S-1-1-0:(OI)(CI)(DENY)" in (res_chk.stdout or "") or "(DENY)" in (res_chk.stdout or ""):
            return False, "Root folder has deny permissions but no metadata container found. Manual administrator recovery required."
        return False, "No Instant Lock container (.locked_data) found in target directory."

    meta_path = os.path.join(locked_data_dir, META_FILENAME)

    with acquire_operation_lock(folder_path, "instant_recovery", is_recovery=True):
        # Temporarily remove deny ACE to inspect metadata
        run_icacls_safe([locked_data_dir, "/remove:d", "*S-1-1-0"])
        try:
            remove_hidden_system_attributes(locked_data_dir)
        except Exception:
            pass

        verified = False
        try:
            if not os.path.isfile(meta_path):
                return False, "Lock metadata (.flock_meta) not found. Recovery aborted to prevent unauthorized access."

            try:
                meta = read_verified_json(meta_path)
            except Exception as e:
                return False, f"Failed reading lock metadata: {e}"

            salt_hex = meta.get("salt")
            expected_hash_hex = meta.get("hash")
            magic = meta.get("magic")

            if magic != "FLCK_INSTANT_V1" or not salt_hex or not expected_hash_hex:
                return False, "Lock metadata is corrupted or unrecognized."

            if len(salt_hex) != 64 or len(expected_hash_hex) != 64:
                return False, "Invalid metadata field lengths."

            salt_bytes = bytes.fromhex(salt_hex)
            derived = derive_instant_hash(password, salt_bytes)

            if not hmac.compare_digest(derived, expected_hash_hex):
                return False, "Incorrect password."

            verified = True

        finally:
            if not verified:
                # FAIL-SAFE: Restore deny permissions immediately
                add_hidden_system_attributes(locked_data_dir)
                run_icacls_safe([locked_data_dir, "/deny", INSTANT_DENY_PERMS])

        # Password verified! Restore DACL if SDDL present
        saved_sddl = meta.get("sddl")
        if saved_sddl:
            ok_sddl = restore_security_descriptor_sddl(locked_data_dir, saved_sddl)
            if not ok_sddl:
                res_rm_d = run_icacls_safe([locked_data_dir, "/remove:d", "*S-1-1-0"])
                if res_rm_d.returncode != 0:
                    return False, "Failed to restore container security descriptor."

        restored_count = 0
        restore_failed = False
        restore_errors = []
        for item in os.listdir(locked_data_dir):
            if item == META_FILENAME:
                continue
            src = os.path.join(locked_data_dir, item)
            dst = resolve_collision(folder_path, item)
            try:
                move_no_replace(src, dst)
                restored_count += 1
            except Exception as ex:
                restore_failed = True
                restore_errors.append(str(ex))

        if restore_failed:
            return False, f"Failed to restore all items: {'; '.join(restore_errors)}. Metadata and container preserved."

        remove_verified_file(meta_path, allowed_names={META_FILENAME})
        remove_empty_directory(locked_data_dir)

        # Clean journal if present
        instant_journal_path = os.path.join(folder_path, INSTANT_JOURNAL_FILENAME)
        if os.path.isfile(instant_journal_path):
            try:
                os.remove(instant_journal_path)
            except Exception:
                pass

        instruction_path = os.path.join(folder_path, INSTRUCTION_FILENAME)
        # Existing instruction-named files are user data; never delete by marker.
        write_instruction_file(folder_path, README_UNLOCKED_TEXT)

        return True, f"Successfully recovered {restored_count} item(s)."


# ---------------- AES LOCK RECOVERY OPERATION ----------------

def recover_aes_folder(folder_path: str, password: str) -> Tuple[bool, str]:
    """
    Safely recovers an interrupted AES-locked folder.
    - Validates journal and vault existence.
    - Verifies password and vault archive integrity before touching any files.
    - If vault or password invalid: preserves vault, journal, and files intact.
    - Safely extracts and restores all items with collision resolution.
    - Removes vault only after full verification.
    """
    folder_path = validate_protection_root(folder_path)
    vault_file = os.path.join(folder_path, VAULT_FILENAME)
    journal_path = os.path.join(folder_path, JOURNAL_FILENAME)

    if not os.path.isfile(vault_file):
        if os.path.isfile(journal_path):
            j = TransactionJournal.load(journal_path)
            if j and isinstance(j.data, dict):
                j_target = j.data.get("target_path")
                j_op_type = j.data.get("operation_type")
                j_op_id = j.data.get("operation_id")
                j_schema = j.data.get("schema_version")
                j_state = j.data.get("state")

                # Validate journal fields and target match
                if (j_target and os.path.normcase(os.path.abspath(j_target)) == os.path.normcase(folder_path)
                        and j_op_type == "aes_lock"
                        and j_op_id
                        and j_schema in ("1.0.3", "1.0.2")
                        and j_state in ("PREPARING", "ENCRYPTING", "VERIFYING")):
                    # A pre-commit state is not proof that sources survived.
                    # Keep journal if any source has been removed or changed.
                    manifest = j.data.get("source_manifest")
                    if not isinstance(manifest, list) or not manifest:
                        return False, "Journal source manifest missing; manual recovery required."
                    try:
                        expected_paths = set()
                        for item in manifest:
                            if not isinstance(item, dict):
                                raise CryptoError("Invalid manifest entry")
                            rel_path = item.get("rel_path")
                            if not is_safe_relative_path(rel_path, folder_path):
                                raise CryptoError("Unsafe source manifest path")
                            if rel_path in expected_paths:
                                raise CryptoError("Duplicate source manifest path")
                            expected_paths.add(rel_path)
                            full_path = os.path.join(folder_path, rel_path.replace("/", os.sep))
                            if safe_fs.is_reparse_point(full_path):
                                raise CryptoError("Source became a reparse point")
                            if item.get("is_dir"):
                                if not os.path.isdir(full_path):
                                    raise CryptoError(f"Missing source directory: {rel_path}")
                            else:
                                if not os.path.isfile(full_path):
                                    raise CryptoError(f"Missing source file: {rel_path}")
                                if os.path.getsize(full_path) != item.get("size"):
                                    raise CryptoError(f"Source size changed: {rel_path}")
                                if compute_file_sha256(full_path) != item.get("sha256"):
                                    raise CryptoError(f"Source hash changed: {rel_path}")
                    except (OSError, CryptoError, TypeError, ValueError) as exc:
                        return False, f"Cannot confirm pre-commit source integrity: {exc}; journal preserved."
                    # Only when all original inputs are verified may the
                    # incomplete journal be retired; orphaned temporary files
                    # remain untouched for separate forensic recovery.
                    j.remove()
                    if os.path.lexists(journal_path):
                        return False, "Failed retiring journal; retry manual recovery."
                    return True, "Pre-commit source manifest fully verified; journal retired."
                else:
                    return False, "Unrecognized or mismatched journal found without valid vault. Files preserved."
        return False, f"No locked vault found inside: {folder_path}"

    try:
        verify_file_password(vault_file, password)
        verify_vault_integrity(vault_file, password)
    except Exception as e:
        return False, f"Vault recovery verification failed: {e}. Vault and files preserved."

    try:
        unlock_folder(folder_path, password, is_recovery=True)
        return True, "Successfully recovered all items from encrypted vault."
    except Exception as e:
        return False, f"Failed during recovery extraction: {e}"


def recover_folder(folder_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Unified recovery entry point for both Instant Lock and AES-256-GCM folders.
    Requires password verification. Preserves all files on failure.
    """
    folder_path = validate_protection_root(folder_path)
    locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)
    vault_file = os.path.join(folder_path, VAULT_FILENAME)
    journal_path = os.path.join(folder_path, JOURNAL_FILENAME)
    instant_journal_path = os.path.join(folder_path, INSTANT_JOURNAL_FILENAME)

    if os.path.isdir(locked_data_dir) or os.path.isfile(instant_journal_path):
        return recover_instant_folder(folder_path, password)
    elif os.path.isfile(vault_file) or os.path.isfile(journal_path):
        if not password:
            return False, "Password is required for AES vault recovery."
        return recover_aes_folder(folder_path, password)
    else:
        return False, "No locked vault or recovery data found in folder."


# ---------------- 1-CLICK RE-LOCK OPERATION ----------------

def relock_folder(folder_path: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> bool:
    """Instantly re-locks an unlocked folder using saved credentials in .flock_relock."""
    folder_path = os.path.abspath(folder_path)
    cfg = get_relock_config(folder_path)
    if not cfg:
        raise ValueError("No re-lock configuration found.")

    mode = cfg.get("mode", "instant")
    if mode == "instant":
        salt = cfg.get("salt")
        pwd_hash = cfg.get("hash")
        lock_folder_instant(folder_path, salt_hex=salt, hash_val=pwd_hash, progress_callback=progress_callback)
    elif mode == "crypto":
        pwd = cfg.get("password")
        if not pwd:
            raise InvalidPasswordError("Stored password unavailable on this computer.")
        lock_folder(folder_path, password=pwd, progress_callback=progress_callback)
    else:
        raise ValueError(f"Unknown lock mode: {mode}")

    # Remove relock config once re-locked
    remove_verified_file(os.path.join(folder_path, RELOCK_CONFIG_FILENAME), allowed_names={RELOCK_CONFIG_FILENAME})
    return True
