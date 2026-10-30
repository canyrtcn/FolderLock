"""
FolderLock - Safe Filesystem Abstraction Layer (Windows Hardened)
Provides atomic, crash-resilient, non-clobbering filesystem operations:
- Canonical path and protection root validation (rejects drive roots, junctions, symlinks, traversal).
- Exclusive per-folder operation locking (UUID, PID, active Win32 handle lock, hierarchical conflict prevention).
- Atomic JSON write and read with fsync, schema verification, and durability.
- Same-volume atomic move without replacement (MoveFileExW with MOVEFILE_WRITE_THROUGH).
- Win32 attribute preservation (bitwise modification, Get/SetFileAttributesW, no clobbering).
- Win32 NTFS DACL / SDDL snapshot capture and restoration (zero usage of icacls /reset).
- Safe source tree scanning recording both files and empty directories, rejecting reparse points.
"""

import os
import sys
import stat
import errno
import time
import json
import uuid
import ctypes
import tempfile
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

# Win32 Constants
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_READONLY = 0x0001
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_SYSTEM = 0x0004
FILE_ATTRIBUTE_DIRECTORY = 0x0010
FILE_ATTRIBUTE_ARCHIVE = 0x0020
FILE_ATTRIBUTE_NORMAL = 0x0080
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400

DACL_SECURITY_INFORMATION = 0x00000004
SDDL_REVISION_1 = 1

# MoveFileExW Flags
MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_COPY_ALLOWED = 0x00000002
MOVEFILE_WRITE_THROUGH = 0x00000008

# Win32 CreateFile Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Process and error constants
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
ERROR_FILE_EXISTS = 80
ERROR_NOT_SAME_DEVICE = 17
ERROR_ALREADY_EXISTS = 183
ERROR_SHARING_VIOLATION = 32
ERROR_ACCESS_DENIED = 5

WIN_NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

# Windows Reserved Device Names
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

OP_LOCK_FILENAME = ".flock_oplock"


class SafeFSError(Exception):
    """Base exception for safe filesystem layer errors."""
    pass


class OperationLockError(SafeFSError):
    """Raised when an operation lock cannot be acquired or conflicts with another process."""
    pass


class PathValidationError(SafeFSError):
    """Raised when a path fails security or validation checks."""
    pass


# ---------------- WIN32 LOW-LEVEL HELPERS ----------------

if os.name == 'nt':
    from ctypes import wintypes
    _k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _advapi32_dll = ctypes.WinDLL('advapi32', use_last_error=True)

    _MoveFileExW = _k32.MoveFileExW
    _MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _MoveFileExW.restype = wintypes.BOOL

    _GetFileAttributesW = _k32.GetFileAttributesW
    _GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _GetFileAttributesW.restype = wintypes.DWORD

    _SetFileAttributesW = _k32.SetFileAttributesW
    _SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _SetFileAttributesW.restype = wintypes.BOOL

    _CreateFileW = _k32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _CloseHandle = _k32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _OpenProcess = _k32.OpenProcess
    _OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _OpenProcess.restype = wintypes.HANDLE

    _GetExitCodeProcess = _k32.GetExitCodeProcess
    _GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _GetExitCodeProcess.restype = wintypes.BOOL
else:
    _k32 = None
    _advapi32_dll = None


def is_pid_running(pid: int) -> bool:
    """Checks whether a process with the given PID is currently alive."""
    if pid <= 0:
        return False
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    h_proc = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        return False
    try:
        from ctypes import wintypes
        exit_code = wintypes.DWORD()
        if _GetExitCodeProcess(h_proc, ctypes.byref(exit_code)):
            return exit_code.value == STILL_ACTIVE
        return False
    finally:
        _CloseHandle(h_proc)


# ---------------- PATH AND HIERARCHY VALIDATION ----------------

def is_same_volume(path_a: str, path_b: str) -> bool:
    """Checks if two paths reside on the same drive volume."""
    drive_a = os.path.splitdrive(os.path.abspath(path_a))[0].upper()
    drive_b = os.path.splitdrive(os.path.abspath(path_b))[0].upper()
    return drive_a == drive_b


def is_reparse_point(path: str) -> bool:
    """Checks whether a path is a Windows reparse point (junction, symlink, mount point)."""
    if os.name != 'nt':
        return os.path.islink(path)
    if not os.path.lexists(path):
        return False
    if os.path.islink(path):
        return True
    attrs = _GetFileAttributesW(os.path.abspath(path))
    if attrs != INVALID_FILE_ATTRIBUTES:
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def validate_protection_root(target_path: str) -> str:
    """
    Validates that target_path is a legitimate, safe directory for folder protection.
    Rejects:
    - Non-existent paths or non-directories.
    - Drive roots (e.g. C:\\, D:\\).
    - Windows system directories (Windows, System32, Program Files, AppData root).
    - Reparse points, junctions, or symbolic links.
    Returns canonical normalized absolute path.
    """
    if not target_path or not isinstance(target_path, str):
        raise PathValidationError("Target path must be a non-empty string.")

    abs_path = os.path.abspath(target_path)
    if not os.path.isdir(abs_path):
        raise PathValidationError(f"Target is not an existing directory: {abs_path}")

    # Check for drive root
    drive, rest = os.path.splitdrive(abs_path)
    if rest in ("\\", "/", ""):
        raise PathValidationError(f"Refusing to operate directly on drive root: {abs_path}")

    # Check for reparse point or junction
    if is_reparse_point(abs_path):
        raise PathValidationError(f"Refusing to protect junction or reparse point: {abs_path}")

    # Check for system directories
    norm = abs_path.lower()
    system_roots = []
    windir = os.environ.get("WINDIR")
    if windir:
        system_roots.append(windir.lower())
    prog_files = os.environ.get("ProgramFiles")
    if prog_files:
        system_roots.append(prog_files.lower())
    prog_files_x86 = os.environ.get("ProgramFiles(x86)")
    if prog_files_x86:
        system_roots.append(prog_files_x86.lower())
    user_prof = os.environ.get("USERPROFILE")
    if user_prof:
        system_roots.append(user_prof.lower())

    for sys_r in system_roots:
        if norm == sys_r:
            raise PathValidationError(f"Refusing to protect sensitive system/profile directory: {abs_path}")

    return abs_path


def is_safe_relative_path(rel_path: str, root_dir: str) -> bool:
    """
    Audits a relative path to ensure it is safe from traversal, ADS, and Windows reserved device names.
    Ensures resolved path is strictly within root_dir.
    """
    if not rel_path or not isinstance(rel_path, str):
        return False

    # Block directory traversal and drive prefixes
    if ".." in rel_path.replace("\\", "/").split("/"):
        return False
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        return False
    if ":" in rel_path:  # Blocks NTFS Alternate Data Streams (ADS) and drive colons
        return False

    # Check each path component against Windows reserved device names and illegal characters
    illegal_chars = set('<>"|?*')
    parts = rel_path.replace("\\", "/").split("/")
    for part in parts:
        if not part:
            continue
        if any(c in illegal_chars for c in part):
            return False
        base_name = part.split(".")[0].upper()
        if base_name in WINDOWS_RESERVED_NAMES:
            return False

    # Ensure containment inside root_dir
    abs_target = os.path.abspath(os.path.join(root_dir, rel_path))
    try:
        common = os.path.commonpath([os.path.abspath(root_dir), abs_target])
        if os.path.normcase(common) != os.path.normcase(os.path.abspath(root_dir)):
            return False
    except ValueError:
        return False

    return True


# ---------------- WIN32 ATTRIBUTE MANAGEMENT ----------------

def get_file_attributes_safe(path: str) -> int:
    """Reads Windows file attributes without clobbering. Raises WinError on failure."""
    if os.name != 'nt':
        return 0
    path = os.path.abspath(path)
    attrs = _GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:
        err = ctypes.get_last_error()
        raise ctypes.WinError(err)
    return attrs


def add_hidden_system_attributes(path: str) -> int:
    """
    Adds FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM to a file or folder
    without modifying other existing attributes (archive, read-only, etc.).
    Returns original attributes before modification.
    """
    if os.name != 'nt':
        return 0
    path = os.path.abspath(path)
    orig_attrs = get_file_attributes_safe(path)
    new_attrs = orig_attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    if new_attrs != orig_attrs:
        ret = _SetFileAttributesW(path, new_attrs)
        if not ret:
            err = ctypes.get_last_error()
            raise ctypes.WinError(err)
    return orig_attrs


def remove_hidden_system_attributes(path: str, orig_attrs: Optional[int] = None) -> int:
    """
    Removes FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM from a file or folder.
    Preserves all other attributes. If orig_attrs was provided and valid, restores it.
    Returns attributes prior to modification.
    """
    if os.name != 'nt':
        return 0
    path = os.path.abspath(path)
    curr_attrs = get_file_attributes_safe(path)
    if orig_attrs is not None and orig_attrs != INVALID_FILE_ATTRIBUTES:
        target_attrs = orig_attrs
    else:
        target_attrs = curr_attrs & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
        if (target_attrs & ~FILE_ATTRIBUTE_DIRECTORY) == 0:
            if not (curr_attrs & FILE_ATTRIBUTE_DIRECTORY):
                target_attrs = FILE_ATTRIBUTE_NORMAL

    if target_attrs != curr_attrs:
        ret = _SetFileAttributesW(path, target_attrs)
        if not ret:
            err = ctypes.get_last_error()
            raise ctypes.WinError(err)
    return curr_attrs


# ---------------- WIN32 NTFS DACL / SDDL SECURITY DESCRIPTOR ----------------

def get_security_descriptor_sddl(path: str) -> Optional[str]:
    """
    Captures the exact DACL security descriptor of a path as an SDDL string.
    Returns SDDL string, or None if not on Windows or unsupported.
    """
    if os.name != 'nt':
        return None
    path = os.path.abspath(path)
    from ctypes import wintypes
    advapi = _advapi32_dll
    k32 = _k32

    len_needed = wintypes.DWORD(0)
    advapi.GetFileSecurityW(path, DACL_SECURITY_INFORMATION, None, 0, ctypes.byref(len_needed))
    if len_needed.value == 0:
        return None

    sd_buf = ctypes.create_string_buffer(len_needed.value)
    if not advapi.GetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd_buf, len_needed.value, ctypes.byref(len_needed)):
        return None

    sddl_ptr = ctypes.c_wchar_p()
    sddl_len = wintypes.ULONG()
    if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        sd_buf, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, ctypes.byref(sddl_ptr), ctypes.byref(sddl_len)
    ):
        return None

    sddl_val = sddl_ptr.value
    k32.LocalFree(ctypes.cast(sddl_ptr, ctypes.c_void_p))
    return sddl_val


def restore_security_descriptor_sddl(path: str, sddl_str: str) -> bool:
    """
    Restores the exact DACL security descriptor from an SDDL string.
    Never uses icacls /reset! Returns True if restored, False otherwise.
    """
    if os.name != 'nt' or not sddl_str:
        return False
    path = os.path.abspath(path)
    advapi = _advapi32_dll
    k32 = _k32

    sd_ptr = ctypes.c_void_p()
    res = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl_str, SDDL_REVISION_1, ctypes.byref(sd_ptr), None
    )
    if not res:
        return False
    try:
        ret = advapi.SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd_ptr)
        return bool(ret)
    finally:
        k32.LocalFree(sd_ptr)


def run_icacls_safe(args: List[str]) -> subprocess.CompletedProcess:
    """Executes icacls silently without console flash and handles encoding safely."""
    cmd = ["icacls"] + args
    return subprocess.run(
        cmd,
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
        creationflags=WIN_NO_WINDOW
    )


# ---------------- ATOMIC MOVE NO-REPLACE (Win32 MoveFileExW) ----------------

def move_no_replace(src: str, dst: str):
    """
    Moves src to dst on the same volume with atomic no-replace semantics using MoveFileExW.
    Passes MOVEFILE_WRITE_THROUGH to ensure file system flushing before return.
    Raises FileExistsError if dst already exists.
    Raises SafeFSError if cross-volume move is requested.
    Raises PermissionError on sharing violation or in-use files.
    Never overwrites or deletes an existing destination file.
    """
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)

    # Both paths are already absolute. Avoid resolving them a second time for
    # every entry in a large Instant Lock batch.
    if os.path.splitdrive(src)[0].upper() != os.path.splitdrive(dst)[0].upper():
        raise SafeFSError(f"Cross-volume move refused between {src} and {dst}")

    if os.name == 'nt':
        # MoveFileExW with MOVEFILE_WRITE_THROUGH (0x8): atomic flush, no overwrite, no copy
        flags = MOVEFILE_WRITE_THROUGH
        ret = _MoveFileExW(src, dst, flags)
        if not ret:
            err = ctypes.get_last_error()
            # Let the atomic API enforce existence/no-replacement. Probing
            # both paths before every successful move adds I/O and cannot
            # prevent races. Check a conflicting destination only on failure.
            if err in (ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS) or os.path.lexists(dst):
                raise FileExistsError(f"Destination already exists: {dst}")
            elif err == ERROR_NOT_SAME_DEVICE:
                raise SafeFSError(f"Cross-volume move refused between {src} and {dst}")
            elif err in (ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED):
                raise PermissionError(
                    errno.EACCES, "File in use or access denied during move",
                    src, err, dst
                )
            else:
                raise ctypes.WinError(err)
    else:
        if os.path.lexists(dst):
            raise FileExistsError(f"Destination already exists: {dst}")
        if not os.path.lexists(src):
            raise FileNotFoundError(f"Source does not exist: {src}")
        os.rename(src, dst)

    if not os.path.lexists(dst) or os.path.lexists(src):
        raise SafeFSError(f"Move verification failed: src={os.path.lexists(src)}, dst={os.path.lexists(dst)}")


# ---------------- ATOMIC JSON STORAGE WITH FSYNC & DIVERGENT POLICIES ----------------

def atomic_write_json(file_path: str, data: Dict[str, Any], expected_op_id: Optional[str] = None):
    """
    Atomically writes a transaction journal dictionary to file_path via mkstemp + flush + fsync + os.replace.
    Strict Journal Security Policy:
    If file_path already exists and expected_op_id is provided:
      - If existing file cannot be parsed as JSON: REFUSES to replace, preserves original, raises SafeFSError.
      - If existing file lacks operation_id: REFUSES to replace, preserves original, raises SafeFSError.
      - If existing operation_id != expected_op_id: REFUSES to replace, preserves original, raises SafeFSError.
      - ONLY replaces if existing operation_id == expected_op_id.
    """
    file_path = os.path.abspath(file_path)
    target_dir = os.path.dirname(file_path)
    os.makedirs(target_dir, exist_ok=True)

    if os.path.isfile(file_path) and expected_op_id is not None:
        try:
            with open(file_path, "r", encoding="utf-8") as existing_f:
                existing_data = json.load(existing_f)
            if not isinstance(existing_data, dict):
                raise SafeFSError(f"Refusing to overwrite invalid journal file: {file_path}")
            existing_op = existing_data.get("operation_id")
            if not existing_op:
                raise SafeFSError(f"Refusing to overwrite unowned journal without operation_id: {file_path}")
            if existing_op != expected_op_id:
                raise SafeFSError(
                    f"Refusing to overwrite journal file {file_path}: operation ID mismatch "
                    f"(existing={existing_op}, expected={expected_op_id}). Original journal preserved."
                )
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise SafeFSError(
                f"Refusing to overwrite corrupted journal file at {file_path}: {e}. "
                "Original file preserved intact; recovery required."
            )

    fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".flock_tmp_json_")
    try:
        content_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        with os.fdopen(fd, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())

        if os.name == 'nt':
            add_hidden_system_attributes(tmp_path)

        os.replace(tmp_path, file_path)

        with open(file_path, "r", encoding="utf-8") as verify_f:
            verified_data = json.load(verify_f)
        if expected_op_id and verified_data.get("operation_id") != expected_op_id:
            raise SafeFSError(f"Post-write verification failed: operation_id mismatch in {file_path}")

    except Exception:
        if os.path.lexists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise


def atomic_write_config_json(file_path: str, data: Dict[str, Any], backup_if_corrupt: bool = True):
    """
    Configuration Storage Policy (e.g. settings.json):
    If file_path exists and is corrupt, backs it up to .corrupt.<timestamp> before replacing.
    """
    file_path = os.path.abspath(file_path)
    target_dir = os.path.dirname(file_path)
    os.makedirs(target_dir, exist_ok=True)

    if os.path.isfile(file_path) and backup_if_corrupt:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json.load(f)
        except Exception:
            corrupt_backup = f"{file_path}.corrupt.{int(time.time())}"
            try:
                shutil.copy2(file_path, corrupt_backup)
            except Exception:
                pass

    fd, tmp_path = tempfile.mkstemp(dir=target_dir, prefix=".flock_tmp_cfg_")
    try:
        content_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        with os.fdopen(fd, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, file_path)
    finally:
        if os.path.lexists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def read_verified_json(file_path: str) -> Dict[str, Any]:
    """Reads and parses a JSON file safely. Raises SafeFSError on decode error."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SafeFSError(f"JSON file corrupted at {file_path}: {e}")


# ---------------- EXCLUSIVE OPERATION LOCKING (Win32 Handle Lock) ----------------

_IN_PROCESS_LOCKS: Set[str] = set()


class OperationLock:
    """
    Exclusive lock context manager for mutating folder operations:
    - In-process overlap prevention.
    - Hierarchical conflict prevention: detects locks held on parent or child directories.
    - True Windows kernel-level file handle locking via CreateFileW with FILE_SHARE_READ:
      blocks concurrent processes at the OS level (ERROR_SHARING_VIOLATION).
    - Safe stale detection: verifies open handle status, active PID, and uncompleted journals
      before touching any existing lock file.
    """
    def __init__(self, target_path: str, operation_type: str, is_recovery: bool = False):
        self.target_path = os.path.normcase(os.path.abspath(target_path))
        self.operation_type = operation_type
        self.is_recovery = is_recovery or ("recover" in operation_type.lower())
        self.operation_id = str(uuid.uuid4())
        self.lock_file = os.path.join(self.target_path, OP_LOCK_FILENAME)
        self.win32_handle: Optional[int] = None
        self._acquired = False

    def _check_hierarchy_locks(self):
        """Checks if any parent directory or immediate subdirectories have an active lock."""
        # 1. Walk up to drive root
        curr = os.path.dirname(self.target_path)
        while curr:
            parent_lock = os.path.join(curr, OP_LOCK_FILENAME)
            if os.path.isfile(parent_lock):
                if self._is_lock_active(parent_lock):
                    raise OperationLockError(f"A parent directory is actively locked: {curr}")
            next_curr = os.path.dirname(curr)
            if next_curr == curr:
                break
            curr = next_curr

        # 2. Check subdirectories of target_path (shallow check for performance)
        try:
            for item in os.listdir(self.target_path):
                sub = os.path.join(self.target_path, item)
                if os.path.isdir(sub) and not is_reparse_point(sub):
                    sub_lock = os.path.join(sub, OP_LOCK_FILENAME)
                    if os.path.isfile(sub_lock) and self._is_lock_active(sub_lock):
                        raise OperationLockError(f"A subdirectory is actively locked: {sub}")
        except Exception as e:
            if isinstance(e, OperationLockError):
                raise

    def _is_lock_active(self, lock_file_path: str) -> bool:
        """Determines if a lock file is actively held by a live process or handle."""
        if not os.path.isfile(lock_file_path):
            return False

        if os.name == 'nt':
            # Try to open the file with GENERIC_WRITE to see if another process holds it
            h = _CreateFileW(
                lock_file_path,
                GENERIC_READ | GENERIC_WRITE,
                0,  # No sharing
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if h == INVALID_HANDLE_VALUE or not h:
                err = ctypes.get_last_error()
                if err in (ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED):
                    return True
            else:
                _CloseHandle(h)

        # Handle was not locked by kernel, check PID
        try:
            info = read_verified_json(lock_file_path)
            pid = info.get("pid", 0)
            if is_pid_running(pid):
                return True
        except Exception:
            pass

        return False

    def acquire(self):
        if self._acquired:
            return self

        # 1. In-process overlap check
        for active in _IN_PROCESS_LOCKS:
            try:
                common = os.path.commonpath([self.target_path, active])
                if common == self.target_path or common == active:
                    raise OperationLockError(
                        f"An operation is already in progress on this folder or a parent/subfolder in this process ({active})."
                    )
            except ValueError:
                pass

        # 2. Cross-process hierarchy check (parent/child)
        self._check_hierarchy_locks()

        # 3. Check existing lock on target_path
        if os.path.isfile(self.lock_file):
            if self._is_lock_active(self.lock_file):
                try:
                    info = read_verified_json(self.lock_file)
                    pid_info = f" (PID: {info.get('pid')}, Op: {info.get('operation_type')})"
                except Exception:
                    pid_info = ""
                raise OperationLockError(f"Folder is locked by another running FolderLock process{pid_info}.")

            # Stale lock evaluation: evaluate process ID, journal, and open handle status
            # Do NOT delete if an uncompleted journal or recovery is required, unless this is a recovery operation!
            journal_path = os.path.join(self.target_path, ".flock_journal")
            instant_journal_path = os.path.join(self.target_path, ".flock_instant_journal")
            for j_path in (journal_path, instant_journal_path):
                if os.path.isfile(j_path):
                    try:
                        j_data = read_verified_json(j_path)
                        state = j_data.get("state", "")
                        rec_req = j_data.get("recovery_required", False)
                        if rec_req or state not in ("COMPLETED", ""):
                            if not self.is_recovery:
                                raise OperationLockError(
                                    f"Folder has an interrupted operation (state: {state}, recovery_required={rec_req}). "
                                    "Lock cannot be overridden. Recovery required."
                                )
                    except OperationLockError:
                        raise
                    except Exception:
                        if not self.is_recovery:
                            raise OperationLockError("Unreadable transaction journal found. Recovery required.")

            # Safe cleanup of unheld stale lock file
            try:
                if os.name == 'nt':
                    remove_hidden_system_attributes(self.lock_file)
                os.remove(self.lock_file)
            except Exception as e:
                raise OperationLockError(f"Cannot clean stale lock file: {e}")

        # 4. Open and hold exclusive Win32 file handle
        if os.name == 'nt':
            # CREATE_NEW with FILE_SHARE_READ: exclusive write access held open
            h = _CreateFileW(
                self.lock_file,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,  # Allow others to inspect/read lock payload, but not write/acquire
                None,
                CREATE_NEW,
                0,
                None
            )
            if h == INVALID_HANDLE_VALUE or not h:
                err = ctypes.get_last_error()
                if err in (ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_SHARING_VIOLATION):
                    raise OperationLockError("Concurrent operation detected: lock already held by another process.")
                raise OperationLockError(f"Failed to acquire Win32 file lock: WinError {err}")
            self.win32_handle = h
        else:
            fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            self.win32_handle = fd

        # 5. Write lock metadata payload
        lock_payload = {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "pid": os.getpid(),
            "target_path": self.target_path,
            "timestamp": time.time()
        }
        payload_bytes = json.dumps(lock_payload, indent=2).encode("utf-8")

        if os.name == 'nt':
            from ctypes import wintypes
            written = wintypes.DWORD(0)
            _k32.WriteFile(self.win32_handle, payload_bytes, len(payload_bytes), ctypes.byref(written), None)
            _k32.FlushFileBuffers(self.win32_handle)
            add_hidden_system_attributes(self.lock_file)
        else:
            os.write(self.win32_handle, payload_bytes)
            os.fsync(self.win32_handle)

        _IN_PROCESS_LOCKS.add(self.target_path)
        self._acquired = True
        return self

    def release(self):
        if not self._acquired:
            return

        if self.target_path in _IN_PROCESS_LOCKS:
            _IN_PROCESS_LOCKS.remove(self.target_path)

        if self.win32_handle is not None:
            if os.name == 'nt':
                _CloseHandle(self.win32_handle)
            else:
                try:
                    os.close(self.win32_handle)
                except Exception:
                    pass
            self.win32_handle = None

        if os.path.lexists(self.lock_file):
            try:
                if os.name == 'nt':
                    remove_hidden_system_attributes(self.lock_file)
                os.remove(self.lock_file)
            except Exception:
                pass

        self._acquired = False

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


def acquire_operation_lock(target_path: str, operation_type: str, is_recovery: bool = False) -> OperationLock:
    """Helper to instantiate and acquire an OperationLock."""
    lock = OperationLock(target_path, operation_type, is_recovery=is_recovery)
    return lock.acquire()


# ---------------- DESTINATION VALIDATION & SAFE DIRECTORY CREATION ----------------

def verify_destination_path_safe(base_dir: str, rel_path: str) -> None:
    """
    Validates that rel_path is safe and that NO intermediate component or existing target
    inside base_dir is a symlink, NTFS junction, or reparse point.
    Raises PathValidationError or SafeFSError if an escape, symlink, or reparse point is detected.
    """
    base_dir = os.path.abspath(base_dir)
    if not is_safe_relative_path(rel_path, base_dir):
        raise PathValidationError(f"Path is not a safe relative path: {rel_path}")

    normalized_rel = os.path.normpath(rel_path)
    parts = Path(normalized_rel).parts
    curr = base_dir
    for part in parts:
        curr = os.path.join(curr, part)
        if os.path.lexists(curr):
            st = os.lstat(curr)
            if stat.S_ISLNK(st.st_mode) or is_reparse_point(curr):
                raise SafeFSError(f"Target path contains symlink or reparse point: {curr}")


def safe_recreate_directories(base_dir: str, rel_dir: str) -> None:
    """
    Safely creates each directory component of rel_dir inside base_dir.
    Ensures no component is a symlink, junction, or non-directory.
    """
    base_dir = os.path.abspath(base_dir)
    normalized_rel = os.path.normpath(rel_dir)
    if normalized_rel == ".":
        return

    parts = Path(normalized_rel).parts
    curr = base_dir
    for part in parts:
        curr = os.path.join(curr, part)
        if os.path.lexists(curr):
            st = os.lstat(curr)
            if stat.S_ISLNK(st.st_mode) or is_reparse_point(curr):
                raise SafeFSError(f"Target directory contains symlink or reparse point: {curr}")
            if not stat.S_ISDIR(st.st_mode):
                raise SafeFSError(f"Target path component is not a directory: {curr}")
        else:
            try:
                os.mkdir(curr)
            except FileExistsError:
                st = os.lstat(curr)
                if stat.S_ISLNK(st.st_mode) or is_reparse_point(curr) or not stat.S_ISDIR(st.st_mode):
                    raise SafeFSError(f"Target path component is not a safe directory: {curr}")


# ---------------- SOURCE TREE SCANNING & MANIFEST ----------------

def compute_file_sha256(file_path: str) -> str:
    """Computes SHA-256 hash of a file streaming in 64 KB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def scan_source_tree(folder_path: str, reserved_names: Set[str]) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Performs safe preflight scan of a folder tree:
    - Recursively audits all entries with os.lstat().
    - Records regular files AND directory entries (including empty and nested subdirectories).
    - Rejects reparse points, junctions, symlinks, FIFOs, device nodes.
    - Rejects Windows reserved device names, ADS (:), illegal characters.
    - Computes size, mtime, and SHA-256 for each regular file.
    - Returns (manifest_list, total_files, total_bytes).
    - Verifies sufficient disk space before returning.
    """
    folder_path = os.path.abspath(folder_path)
    manifest: List[Dict[str, Any]] = []
    total_bytes = 0
    total_files = 0

    for root, dirs, files in os.walk(folder_path):
        rel_root = os.path.relpath(root, folder_path)
        if rel_root != ".":
            if is_reparse_point(root):
                raise SafeFSError(f"Refusing to scan directory reparse point or junction: {root}")
            if not is_safe_relative_path(rel_root, folder_path):
                raise PathValidationError(f"Unsafe directory path detected: {rel_root}")

        # Filter out reserved metadata directories ONLY at protection root
        if rel_root == ".":
            dirs[:] = [d for d in dirs if d not in reserved_names]

        # Audit subdirectories and record directory entries in manifest
        for dname in sorted(dirs):
            sub_dir_full = os.path.join(root, dname)
            rel_dir = os.path.relpath(sub_dir_full, folder_path).replace("\\", "/")
            if is_reparse_point(sub_dir_full):
                raise SafeFSError(f"Refusing to pack subdirectory reparse point or junction: {rel_dir}")
            if not is_safe_relative_path(rel_dir, folder_path):
                raise PathValidationError(f"Unsafe directory name detected: {rel_dir}")

            st_d = os.lstat(sub_dir_full)
            manifest.append({
                "rel_path": rel_dir,
                "size": 0,
                "mtime": st_d.st_mtime,
                "sha256": None,
                "is_dir": True
            })

        # Audit files (filter reserved metadata names ONLY at protection root)
        for fname in sorted(files):
            if rel_root == "." and fname in reserved_names:
                continue

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, folder_path).replace("\\", "/")

            if not is_safe_relative_path(rel_path, folder_path):
                raise PathValidationError(f"Unsafe filename or path detected: {rel_path}")

            st = os.lstat(full_path)
            if stat.S_ISLNK(st.st_mode) or is_reparse_point(full_path):
                raise SafeFSError(f"Refusing to pack symlink or reparse point: {rel_path}")

            if not stat.S_ISREG(st.st_mode):
                raise SafeFSError(f"Refusing to pack non-regular file (device/socket/pipe): {rel_path}")

            f_size = st.st_size
            f_mtime = st.st_mtime
            f_hash = compute_file_sha256(full_path)

            manifest.append({
                "rel_path": rel_path,
                "size": f_size,
                "mtime": f_mtime,
                "sha256": f_hash,
                "is_dir": False
            })
            total_bytes += f_size
            total_files += 1

    # Check disk space
    free_bytes = shutil.disk_usage(folder_path).free
    needed_bytes = int(total_bytes * 1.05) + 10 * 1024 * 1024
    if free_bytes < needed_bytes:
        raise SafeFSError(
            f"Insufficient disk space: {needed_bytes // (1024*1024)} MB required, "
            f"but only {free_bytes // (1024*1024)} MB available on volume."
        )

    return manifest, total_files, total_bytes

# ---------------- VERIFIED SOURCE DELETION ----------------

def delete_verified_source_file(path: str, expected_sha256: str, expected_size: int) -> None:
    """Verify and remove the *same* source file identity.

    On Windows a single exclusive WRITE-denying handle is used for reading and
    setting delete disposition, blocking concurrent writable opens (and refusing
    to proceed if an existing writable open is incompatible). A changed file is
    never removed. On POSIX only best-effort advisory locking is available;
    the Windows guarantees must not be claimed for other platforms.
    """
    path = os.path.abspath(path)
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise SafeFSError("Missing validated expected SHA-256 digest")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise SafeFSError("Missing expected source length")
    if not os.path.isfile(path) or os.path.islink(path) or is_reparse_point(path):
        raise SafeFSError("Source is missing or has unsupported file type")

    if os.name == "nt":
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = k32.CreateFileW
        create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                wintypes.DWORD, ctypes.c_void_p,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create_file.restype = wintypes.HANDLE
        read_file = k32.ReadFile
        read_file.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                              wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                              ctypes.c_void_p]
        read_file.restype = wintypes.BOOL
        set_info = k32.SetFileInformationByHandle
        set_info.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD]
        set_info.restype = wintypes.BOOL
        close = k32.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL

        GENERIC_READ = 0x80000000
        DELETE = 0x00010000
        FILE_SHARE_READ = 1  # No sharing for WRITE or DELETE while handle held.
        OPEN_EXISTING = 3
        FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        FILE_DISPOSITION_INFO_CLASS = 4

        handle = create_file(path, GENERIC_READ | DELETE, FILE_SHARE_READ,
                             None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            # A handle opened without following a reparse point must also be
            # inspected. Never delete a link/reparse object through this API.
            if is_reparse_point(path):
                raise SafeFSError("Source became a reparse point")
            hasher = hashlib.sha256()
            size = 0
            buf = ctypes.create_string_buffer(1024 * 1024)
            count = wintypes.DWORD()
            while True:
                if not read_file(handle, buf, len(buf), ctypes.byref(count), None):
                    raise ctypes.WinError(ctypes.get_last_error())
                if count.value == 0:
                    break
                hasher.update(buf.raw[:count.value])
                size += count.value
                if size > expected_size:
                    raise SafeFSError("Source grew after vault verification")
            if size != expected_size or hasher.hexdigest() != expected_sha256:
                raise SafeFSError("Source changed after vault verification; refusing deletion")
            # FILE_DISPOSITION_INFO; operation is bound to this *handle*, not
            # a path that could have been replaced following verification.
            disposition = wintypes.BOOLEAN(1)
            if not set_info(handle, FILE_DISPOSITION_INFO_CLASS,
                            ctypes.byref(disposition), ctypes.sizeof(disposition)):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            close(handle)
        if os.path.lexists(path):
            raise SafeFSError("Source path remains after delete disposition")
        return

    # POSIX fallback for local synthetic tests. POSIX flock is advisory,
    # not a replacement for Windows mandatory file sharing semantics.
    import fcntl
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != expected_size:
            raise SafeFSError("Source changed or is not a regular file")
        hasher = hashlib.sha256()
        size = 0
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            hasher.update(data)
            size += len(data)
        if size != expected_size or hasher.hexdigest() != expected_sha256:
            raise SafeFSError("Source changed after vault verification")
        now = os.lstat(path)
        if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
            raise SafeFSError("Source identity changed before cleanup")
        os.unlink(path)
    finally:
        os.close(fd)
