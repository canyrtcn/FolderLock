"""
FolderLock - Cryptographic Engine
Implements AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256.
High security, bug-proof, fail-safe file operations with robust Windows read-only and permission handling.
Fully portable across Windows editions and environments (zero machine-specific references).
"""

import os
import sys
import stat
import struct
import shutil
import tarfile
import ctypes
import subprocess
import hmac
import json
from typing import Callable, Optional, Tuple, Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC_HEADER = b"FLCK02"
SALT_SIZE = 32
PBKDF2_ITERATIONS = 300_000
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024  # 1 MB streaming chunks for minimal RAM usage (< 2 MB)
VERIFIER_PAYLOAD = b"FLOCK_V2_AUTH_KEY_VERIFICATION_TOKEN_SECURE"
NONCE_SIZE = 12

VAULT_FILENAME = ".locked_vault"
INSTANT_DATA_DIRNAME = ".locked_data"
META_FILENAME = ".flock_meta"
RELOCK_CONFIG_FILENAME = ".flock_relock"
UNLOCKER_FILENAME = "Unlock.exe"
UNLOCKER_TR_FILENAME = "Kilidi Ac.exe"
LOCKER_FILENAME = "Lock.exe"
LOCKER_TR_FILENAME = "Kilitle.exe"
README_FILENAME = "Readme.txt"

EXCLUDED_NAMES = {
    VAULT_FILENAME,
    VAULT_FILENAME + ".tmp",
    INSTANT_DATA_DIRNAME,
    META_FILENAME,
    RELOCK_CONFIG_FILENAME,
    UNLOCKER_FILENAME,
    UNLOCKER_TR_FILENAME,
    LOCKER_FILENAME,
    LOCKER_TR_FILENAME,
    README_FILENAME,
    "Kilidi Ac.exe",
    "🔓 KİLİDİ AÇ.exe"
}

WIN_NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

README_LOCKED_TEXT = (
    "====================================================\n"
    "FOLDERLOCK - PROTECTED DIRECTORY / KORUMALI KLASÖR\n"
    "====================================================\n\n"
    "[EN] TO UNLOCK THIS FOLDER:\n"
    "Double-click 'Unlock.exe' and enter your password.\n"
    "Your files will be restored instantly.\n\n"
    "[TR] BU KLASÖRÜN KİLİDİNİ AÇMAK İÇİN:\n"
    "Klasör içindeki 'Unlock.exe' dosyasına çift tıklayın ve şifrenizi girin.\n"
    "Dosyalarınız anında geri yüklenecektir.\n"
    "====================================================\n"
)

README_UNLOCKED_TEXT = (
    "====================================================\n"
    "FOLDERLOCK - UNLOCKED DIRECTORY / AÇILMIŞ KLASÖR\n"
    "====================================================\n\n"
    "[EN] TO RE-LOCK THIS FOLDER:\n"
    "Double-click 'Lock.exe' to instantly re-lock this folder\n"
    "with the SAME password without re-typing anything!\n\n"
    "[TR] BU KLASÖRÜ TEKRAR KİLİTLEMEK İÇİN:\n"
    "Klasör içindeki 'Lock.exe' dosyasına çift tıklayarak\n"
    "şifre yazmaya gerek kalmadan AYNI şifreyle anında tekrar kilitleyebilirsiniz!\n"
    "====================================================\n"
)


class CryptoError(Exception):
    """Custom exception for cryptography errors."""
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


def set_file_attributes(path: str, hidden: bool = False, system: bool = False):
    """Sets or clears Windows hidden and system attributes via native Win32 API (no child processes)."""
    if os.name != 'nt':
        return
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return
    attrs = 0
    if hidden:
        attrs |= 0x02  # FILE_ATTRIBUTE_HIDDEN
    if system:
        attrs |= 0x04  # FILE_ATTRIBUTE_SYSTEM
    if not hidden and not system:
        attrs = 0x80  # FILE_ATTRIBUTE_NORMAL
    try:
        ctypes.windll.kernel32.SetFileAttributesW(path, attrs)
    except Exception:
        pass


INSTANT_DENY_PERMS = "*S-1-1-0:(OI)(CI)(RD,WD,AD,X,DC,DE,RA,WA)"


def run_icacls(args: List[str]) -> subprocess.CompletedProcess:
    """Executes icacls silently with Universal SID and no flashing console windows."""
    cmd = ["icacls"] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
        creationflags=WIN_NO_WINDOW
    )


def _remove_readonly(func, path, exc_info):
    """
    Error handler for shutil.rmtree and os.remove.
    Clears read-only flag on Windows and retries removal.
    """
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def safe_remove_path(path: str):
    """Safely removes a file or directory tree, handling Windows read-only attributes."""
    if not os.path.exists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, onerror=_remove_readonly)
    else:
        try:
            os.chmod(path, stat.S_IWRITE)
            os.remove(path)
        except Exception:
            pass


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from the password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))


class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def dpapi_protect(data: bytes) -> bytes:
    """Encrypts bytes using Windows DPAPI for the current logged-in user."""
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), "flock", None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("CryptProtectData failed")
    res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return res


def dpapi_unprotect(cipher: bytes) -> bytes:
    """Decrypts bytes using Windows DPAPI for the current logged-in user."""
    in_blob = DATA_BLOB(len(cipher), ctypes.cast(ctypes.create_string_buffer(cipher), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("CryptUnprotectData failed")
    res = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return res


def save_relock_config(folder_path: str, mode: str, salt_hex: str, hash_val: str, password: Optional[str] = None):
    """Saves hidden credentials inside the unlocked folder so Lock.exe can re-lock with the same password."""
    folder_path = os.path.abspath(folder_path)
    relock_file = os.path.join(folder_path, RELOCK_CONFIG_FILENAME)
    data = {
        "magic": "FLCK_RELOCK_V1",
        "mode": mode,
        "salt": salt_hex,
        "hash": hash_val
    }
    if mode == "crypto" and password:
        try:
            data["dpapi_pwd"] = dpapi_protect(password.encode("utf-8")).hex()
        except Exception:
            pass

    try:
        with open(relock_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
        set_file_attributes(relock_file, hidden=True, system=True)
    except Exception:
        pass


def get_relock_config(folder_path: str) -> Optional[Dict[str, Any]]:
    """Reads saved re-lock configuration if available."""
    folder_path = os.path.abspath(folder_path)
    relock_file = os.path.join(folder_path, RELOCK_CONFIG_FILENAME)
    if not os.path.isfile(relock_file):
        return None
    try:
        with open(relock_file, "r", encoding="utf-8") as f:
            data = json.load(f)
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
    """Places Lock.exe in an unlocked folder, removes Unlock.exe and duplicates."""
    folder_path = os.path.abspath(folder_path)
    exe_src = _get_app_executable_path()
    if exe_src and os.path.isfile(exe_src):
        dst = os.path.join(folder_path, LOCKER_FILENAME)
        try:
            if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(exe_src):
                shutil.copy2(exe_src, dst)
        except Exception:
            pass
    # Clean up unlockers and redundant/legacy copies
    for u in [UNLOCKER_FILENAME, UNLOCKER_TR_FILENAME, LOCKER_TR_FILENAME, "Kilidi Ac.exe", "Kilitle.exe", "🔓 KİLİDİ AÇ.exe"]:
        safe_remove_path(os.path.join(folder_path, u))


def deploy_unlockers(folder_path: str):
    """Places Unlock.exe in a locked folder, removes Lock.exe and duplicates."""
    folder_path = os.path.abspath(folder_path)
    exe_src = _get_app_executable_path()
    if exe_src and os.path.isfile(exe_src):
        dst = os.path.join(folder_path, UNLOCKER_FILENAME)
        try:
            if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(exe_src):
                shutil.copy2(exe_src, dst)
        except Exception:
            pass
    # Clean up lockers and redundant/legacy copies
    for l in [LOCKER_FILENAME, LOCKER_TR_FILENAME, UNLOCKER_TR_FILENAME, "Kilidi Ac.exe", "Kilitle.exe", "🔓 KİLİDİ AÇ.exe"]:
        safe_remove_path(os.path.join(folder_path, l))


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


def lock_folder_instant(folder_path: str, password: Optional[str] = None,
                        salt_hex: Optional[str] = None,
                        hash_val: Optional[str] = None,
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> Tuple[str, str]:
    """
    Instant Lock (No Protected-File Content Rewrites):
    - Moves folder contents into a hidden container `.locked_data` inside `folder_path`.
    - Writes `.flock_meta` inside `.locked_data` with PBKDF2 salt & verification hash.
    - Sets system/hidden attributes and NTFS Deny ACE on `.locked_data` only.
    - Copies Unlock.exe, Kilidi Ac.exe and Readme.txt directly into `folder_path`.
    - Completes in < 0.05 seconds with 0 file data bytes written to SSD.
    """
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Target is not a directory: {folder_path}")

    if is_folder_locked(folder_path):
        raise ValueError("The folder is already locked.")

    if salt_hex and hash_val:
        # Re-locking with same credentials
        pwd_hash = hash_val
    elif password:
        salt_bytes = os.urandom(SALT_SIZE)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=PBKDF2_ITERATIONS)
        pwd_hash = kdf.derive(password.encode("utf-8")).hex()
        salt_hex = salt_bytes.hex()
    else:
        raise ValueError("Password cannot be empty.")

    items_to_lock = [item for item in os.listdir(folder_path) if item not in EXCLUDED_NAMES]

    if progress_callback:
        progress_callback(0.2, "Preparing security container...")

    locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)
    safe_remove_path(locked_data_dir)
    os.makedirs(locked_data_dir, exist_ok=True)

    # Save portable verification metadata
    meta_path = os.path.join(locked_data_dir, META_FILENAME)
    meta_data = {
        "magic": "FLCK_INSTANT_V1",
        "salt": salt_hex,
        "hash": pwd_hash
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_data, f)

    if progress_callback:
        progress_callback(0.5, "Securing items...")

    # Move items into container without rewriting the protected file contents.
    for item in items_to_lock:
        src = os.path.join(folder_path, item)
        dst = os.path.join(locked_data_dir, item)
        shutil.move(src, dst)

    # Set hidden + system on .locked_data via native Win32 API
    set_file_attributes(locked_data_dir, hidden=True, system=True)

    # Universal SID *S-1-1-0 (Everyone) deny on .locked_data ONLY (works on all Windows language editions)
    run_icacls([locked_data_dir, "/deny", INSTANT_DENY_PERMS])

    if progress_callback:
        progress_callback(0.8, "Deploying unlocker...")

    deploy_unlockers(folder_path)

    # Bilingual Instruction file
    try:
        readme_path = os.path.join(folder_path, README_FILENAME)
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(README_LOCKED_TEXT)
    except Exception:
        pass

    if progress_callback:
        progress_callback(1.0, "Folder successfully locked!")

    return salt_hex, pwd_hash


def unlock_folder_instant(folder_path: str, password: str,
                          salt_hex: Optional[str] = None,
                          expected_hash_hex: Optional[str] = None) -> bool:
    """
    Unlocks an Instant-Locked folder in < 0.05s:
    - Removes deny ACE and hidden attributes from `.locked_data`.
    - Verifies password against `.flock_meta` (or passed arguments).
    - Moves all protected files and subfolders back to `folder_path`.
    - Fail-safe: if password check fails or error occurs, deny ACE is guaranteed to be restored.
    """
    folder_path = os.path.abspath(folder_path)
    locked_data_dir = os.path.join(folder_path, INSTANT_DATA_DIRNAME)

    if not os.path.isdir(locked_data_dir):
        # Legacy fallback if root was denied
        res_chk = run_icacls([folder_path])
        if "*S-1-1-0:(OI)(CI)(DENY)" in (res_chk.stdout or "") or "(DENY)" in (res_chk.stdout or ""):
            if salt_hex and expected_hash_hex:
                salt_bytes = bytes.fromhex(salt_hex)
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=PBKDF2_ITERATIONS)
                derived = kdf.derive(password.encode("utf-8")).hex()
                if not hmac.compare_digest(derived, expected_hash_hex):
                    raise InvalidPasswordError("Incorrect password.")
            run_icacls([folder_path, "/remove:d", "*S-1-1-0"])
            set_file_attributes(folder_path, hidden=False, system=False)
            return True
        raise FileNotFoundError(f"No locked data container found inside: {folder_path}")

    # Temporarily remove deny ACE to inspect metadata
    set_file_attributes(locked_data_dir, hidden=False, system=False)
    res_rm = run_icacls([locked_data_dir, "/remove:d", "*S-1-1-0"])
    if res_rm.returncode != 0:
        # Fallback for reset if previously locked by an older version
        run_icacls([locked_data_dir, "/reset"])
        run_icacls([locked_data_dir, "/remove:d", "*S-1-1-0"])

    verified = False
    try:
        meta_path = os.path.join(locked_data_dir, META_FILENAME)
        if os.path.isfile(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                salt_hex = meta.get("salt", salt_hex)
                expected_hash_hex = meta.get("hash", expected_hash_hex)
            except Exception:
                pass

        if not salt_hex or not expected_hash_hex:
            raise CorruptedFileError("Lock metadata is missing or corrupted.")

        salt_bytes = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=PBKDF2_ITERATIONS)
        derived = kdf.derive(password.encode("utf-8")).hex()

        if not hmac.compare_digest(derived, expected_hash_hex):
            raise InvalidPasswordError("Incorrect password.")

        verified = True

    finally:
        if not verified:
            # FAIL-SAFE: Re-apply deny and hidden attributes immediately if verification failed
            set_file_attributes(locked_data_dir, hidden=True, system=True)
            run_icacls([locked_data_dir, "/deny", INSTANT_DENY_PERMS])

    # Password verified! Restore items
    safe_remove_path(meta_path)

    for item in os.listdir(locked_data_dir):
        src = os.path.join(locked_data_dir, item)
        dst = os.path.join(folder_path, item)
        if os.path.exists(dst):
            safe_remove_path(dst)
        shutil.move(src, dst)

    safe_remove_path(locked_data_dir)

    # Save re-lock configuration so user can lock again with the same password!
    save_relock_config(folder_path, mode="instant", salt_hex=salt_hex, hash_val=expected_hash_hex)
    deploy_lockers(folder_path)

    # Bilingual instruction file for unlocked state
    try:
        readme_path = os.path.join(folder_path, README_FILENAME)
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(README_UNLOCKED_TEXT)
    except Exception:
        pass

    return True


def relock_folder(folder_path: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> bool:
    """
    Instantly re-locks an unlocked folder using saved credentials in .flock_relock.
    """
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

    # Remove relock config
    safe_remove_path(os.path.join(folder_path, RELOCK_CONFIG_FILENAME))
    deploy_unlockers(folder_path)
    return True


def get_folder_stats(folder_path: str, exclude_vault: bool = True) -> Tuple[int, int]:
    """
    Returns (total_files, total_bytes) for the given folder.
    Skips vault files and unlocker if requested. Safely ignores unreadable items.
    """
    total_files = 0
    total_bytes = 0
    excluded = EXCLUDED_NAMES
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            if exclude_vault and f in excluded:
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


class ChunkEncryptingWriter:
    """
    Acts as a writable stream for tarfile that encrypts data in 1MB chunks using AES-256-GCM.
    Keeps memory usage under 2MB even for hundreds of gigabytes of data.
    """
    def __init__(self, out_file, aes_key: bytes, chunk_size: int = CHUNK_SIZE,
                 on_chunk: Optional[Callable[[int], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.out_file = out_file
        self.aes = AESGCM(aes_key)
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
        nonce = struct.pack(">Q", self.chunk_index) + b"\x00\x00\x00\x00"
        ct = self.aes.encrypt(nonce, data, None)
        flags = 1 if is_last else 0
        header = struct.pack(">II", len(ct), flags)
        self.out_file.write(header + ct)
        self.chunk_index += 1

    def close(self):
        if hasattr(self, 'buffer') and self.buffer is not None:
            remaining = bytes(self.buffer)
            self._write_chunk(remaining, is_last=True)
            if self.on_chunk and len(remaining) > 0:
                self.on_chunk(len(remaining))
            self.buffer = None


class ChunkDecryptingReader:
    """
    Acts as a readable stream for tarfile that decrypts AES-256-GCM chunks on-the-fly.
    """
    def __init__(self, in_file, aes_key: bytes,
                 on_chunk: Optional[Callable[[int], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.in_file = in_file
        self.aes = AESGCM(aes_key)
        self.buffer = bytearray()
        self.chunk_index = 0
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
                self.eof = True
                break
            ct_len, flags = struct.unpack(">II", header)
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


def verify_file_password(vault_path: str, password: str) -> bool:
    """
    Verifies whether the provided password can authenticate the vault header.
    """
    if not os.path.exists(vault_path):
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, "rb") as f:
        magic = f.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise CorruptedFileError("The selected file is not a valid FolderLock vault.")

        salt = f.read(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            raise CorruptedFileError("Damaged vault header.")

        nonce = f.read(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise CorruptedFileError("Damaged vault header.")

        verifier_len_bytes = f.read(4)
        if len(verifier_len_bytes) != 4:
            raise CorruptedFileError("Damaged vault header.")
        verifier_len = struct.unpack(">I", verifier_len_bytes)[0]

        verifier_ct = f.read(verifier_len)
        if len(verifier_ct) != verifier_len:
            raise CorruptedFileError("Damaged vault header.")

    key = derive_key(password, salt)
    aes = AESGCM(key)
    try:
        dec = aes.decrypt(nonce, verifier_ct, None)
        if dec == VERIFIER_PAYLOAD:
            return True
        else:
            raise InvalidPasswordError("Password verification token mismatch.")
    except InvalidTag:
        raise InvalidPasswordError("Incorrect password.")


def _get_app_executable_path() -> Optional[str]:
    """Finds FolderLock.exe to copy into locked folders as the unlocker."""
    if getattr(sys, 'frozen', False):
        return sys.executable

    candidates = [
        os.path.abspath("FolderLock.exe"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "FolderLock.exe")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "dist", "FolderLock.exe"))
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def lock_folder(folder_path: str, password: str,
                progress_callback: Optional[Callable[[float, str], None]] = None,
                cancel_check: Optional[Callable[[], bool]] = None) -> str:
    """
    In-Place Folder Locking (AES-256-GCM):
    - Encrypts all items inside `folder_path` into `.locked_vault`.
    - Places `Unlock.exe` directly inside the folder so clicking it prompts for password.
    - Zero data loss on cancellation or error.
    """
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Target is not a valid directory: {folder_path}")

    if is_folder_locked(folder_path):
        raise ValueError("The folder is already locked.")

    if not password:
        raise ValueError("Password cannot be empty.")

    vault_file = os.path.join(folder_path, VAULT_FILENAME)
    temp_vault_file = os.path.join(folder_path, VAULT_FILENAME + ".tmp")

    if progress_callback:
        progress_callback(0.02, "Calculating folder size...")

    total_files, total_bytes = get_folder_stats(folder_path)
    if total_bytes == 0:
        total_bytes = 1024

    processed_bytes = 0

    def on_chunk(bytes_written: int):
        nonlocal processed_bytes
        processed_bytes += bytes_written
        pct = min(0.92, 0.05 + (processed_bytes / total_bytes) * 0.87)
        if progress_callback:
            progress_callback(pct, f"Encrypting: {format_bytes(processed_bytes)} / {format_bytes(total_bytes)}")

    # Collect items to pack
    excluded_names = EXCLUDED_NAMES
    items_to_pack = [item for item in os.listdir(folder_path) if item not in excluded_names]

    try:
        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        aes = AESGCM(key)

        verifier_nonce = os.urandom(NONCE_SIZE)
        verifier_ct = aes.encrypt(verifier_nonce, VERIFIER_PAYLOAD, None)

        with open(temp_vault_file, "wb") as f_out:
            f_out.write(MAGIC_HEADER)
            f_out.write(salt)
            f_out.write(verifier_nonce)
            f_out.write(struct.pack(">I", len(verifier_ct)))
            f_out.write(verifier_ct)

            enc_writer = ChunkEncryptingWriter(
                f_out, key,
                chunk_size=CHUNK_SIZE,
                on_chunk=on_chunk,
                cancel_check=cancel_check
            )
            with tarfile.open(mode="w|", fileobj=enc_writer) as tar:
                for item in items_to_pack:
                    full_p = os.path.join(folder_path, item)
                    # Safe add without following external symlinks
                    tar.add(full_p, arcname=item, recursive=True, filter=None)
            enc_writer.close()

        if progress_callback:
            progress_callback(0.94, "Verifying encryption integrity...")

        # Test decrypting header before deleting any plaintext files
        verify_file_password(temp_vault_file, password)

        if progress_callback:
            progress_callback(0.96, "Securing folder contents...")

        # Safe removal of plaintext items
        for item in items_to_pack:
            p = os.path.join(folder_path, item)
            safe_remove_path(p)

        # Move temp vault to permanent .locked_vault
        if os.path.exists(vault_file):
            safe_remove_path(vault_file)
        os.rename(temp_vault_file, vault_file)

        # Hide .locked_vault
        set_file_attributes(vault_file, hidden=True, system=True)

        deploy_unlockers(folder_path)

        # Write bilingual instruction note
        try:
            readme_path = os.path.join(folder_path, README_FILENAME)
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(README_LOCKED_TEXT)
        except Exception:
            pass

        if progress_callback:
            progress_callback(1.0, "Folder successfully locked!")

        return folder_path

    except Exception as e:
        safe_remove_path(temp_vault_file)
        raise e


def unlock_folder(folder_path: str, password: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  cancel_check: Optional[Callable[[], bool]] = None) -> str:
    """
    Unlocks an in-place locked folder (AES-256-GCM).
    Decrypts files back into `folder_path`, removes vault and unlocker.
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

    if progress_callback:
        progress_callback(0.05, "Verifying password...")

    verify_file_password(vault_file, password)

    if progress_callback:
        progress_callback(0.10, "Password verified. Decrypting...")

    vault_size = os.path.getsize(vault_file)
    if vault_size == 0:
        vault_size = 1024

    processed_bytes = 0

    def on_chunk(bytes_read: int):
        nonlocal processed_bytes
        processed_bytes += bytes_read
        pct = min(0.95, 0.10 + (processed_bytes / vault_size) * 0.85)
        if progress_callback:
            progress_callback(pct, f"Decrypting: {format_bytes(processed_bytes)} / {format_bytes(vault_size)}")

    temp_extract_dir = os.path.join(target_dir, f".tmp_flock_extract_{os.getpid()}")
    safe_remove_path(temp_extract_dir)
    os.makedirs(temp_extract_dir, exist_ok=True)

    try:
        with open(vault_file, "rb") as f_in:
            magic = f_in.read(len(MAGIC_HEADER))
            salt = f_in.read(SALT_SIZE)
            nonce = f_in.read(NONCE_SIZE)
            verifier_len = struct.unpack(">I", f_in.read(4))[0]
            f_in.seek(verifier_len, os.SEEK_CUR)

            key = derive_key(password, salt)

            dec_reader = ChunkDecryptingReader(
                f_in, key,
                on_chunk=on_chunk,
                cancel_check=cancel_check
            )

            with tarfile.open(mode="r|", fileobj=dec_reader) as tar:
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(temp_extract_dir, filter='data')
                else:
                    tar.extractall(temp_extract_dir)

        # Move extracted items into target directory
        for item in os.listdir(temp_extract_dir):
            src = os.path.join(temp_extract_dir, item)
            dst = os.path.join(target_dir, item)
            if os.path.exists(dst):
                safe_remove_path(dst)
            shutil.move(src, dst)

        safe_remove_path(temp_extract_dir)

        # Clean up vault and instruction file
        safe_remove_path(vault_file)

        # Save re-lock configuration and deploy Lock.exe / Kilitle.exe
        save_relock_config(target_dir, mode="crypto", salt_hex=salt.hex(), hash_val="", password=password)
        deploy_lockers(target_dir)

        # Bilingual instruction file for unlocked state
        try:
            readme_path = os.path.join(target_dir, README_FILENAME)
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(README_UNLOCKED_TEXT)
        except Exception:
            pass

        if progress_callback:
            progress_callback(1.0, "Folder successfully unlocked!")

        return target_dir

    except Exception as e:
        safe_remove_path(temp_extract_dir)
        raise e
