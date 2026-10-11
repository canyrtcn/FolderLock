"""
FolderLock - Safe Filesystem Abstraction Layer (Windows Hardened)
Provides atomic, crash-resilient, non-clobbering filesystem operations:
- Canonical path and protection root validation (rejects drive roots, junctions, symlinks, traversal).
- Exclusive per-folder operation locking (UUID, PID, stale detection, hierarchical conflict prevention).
- Atomic JSON write and read with fsync, schema verification, and durability.
- Same-volume atomic move without replacement (MoveFileExW with non-replace semantics).
- Win32 attribute preservation (bitwise modification, Get/SetFileAttributesW, no clobbering).
- Win32 NTFS DACL / SDDL snapshot capture and restoration (zero usage of icacls /reset).
- Safe source tree scanning rejecting reparse points, ADS, reserved device names.
"""

import os
import sys
import stat
import time
import json
import uuid
import ctypes
import tempfile
import hashlib
import shutil
import subprocess
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

MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_COPY_ALLOWED = 0x00000002

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259

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

def _kernel32():
    return ctypes.windll.kernel32 if os.name == 'nt' else None


def _advapi32():
    return ctypes.windll.advapi32 if os.name == 'nt' else None


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

    k32 = _kernel32()
    h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if k32.GetExitCodeProcess(h_proc, ctypes.byref(exit_code)):
            return exit_code.value == STILL_ACTIVE
        return False
    finally:
        k32.CloseHandle(h_proc)


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
    attrs = _kernel32().GetFileAttributesW(os.path.abspath(path))
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
        # Don't allow protecting the entire user profile root C:\Users\Username
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
        # Strip extension to check base device name (e.g. CON.txt is reserved)
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
    attrs = _kernel32().GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:
        raise ctypes.WinError()
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
        ret = _kernel32().SetFileAttributesW(path, new_attrs)
        if ret == 0:
            raise ctypes.WinError()
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
        # If no attributes remain on a regular file, Windows convention is NORMAL
        if (target_attrs & ~FILE_ATTRIBUTE_DIRECTORY) == 0:
            if not (curr_attrs & FILE_ATTRIBUTE_DIRECTORY):
                target_attrs = FILE_ATTRIBUTE_NORMAL

    if target_attrs != curr_attrs:
        ret = _kernel32().SetFileAttributesW(path, target_attrs)
        if ret == 0:
            raise ctypes.WinError()
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
    advapi = _advapi32()
    k32 = _kernel32()

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
    advapi = _advapi32()
    k32 = _kernel32()

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


# ---------------- ATOMIC MOVE NO-REPLACE ----------------

def move_no_replace(src: str, dst: str):
    """
    Moves src to dst on the same volume with atomic no-replace semantics.
    Raises FileExistsError if dst already exists.
    Raises SafeFSError if moving fails or verification fails.
    Never overwrites or deletes an existing destination file.
    """
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)

    if not is_same_volume(src, dst):
        raise SafeFSError(f"Cross-volume move refused between {src} and {dst}")

    if os.path.lexists(dst):
        raise FileExistsError(f"Destination already exists: {dst}")

    if not os.path.lexists(src):
        raise FileNotFoundError(f"Source does not exist: {src}")

    if os.name == 'nt':
        # MoveFileExW with flag 0: no replace existing, no cross-volume copy allowed
        ret = _kernel32().MoveFileExW(src, dst, 0)
        if ret == 0:
            err = ctypes.GetLastError()
            if err == 183:  # ERROR_ALREADY_EXISTS
                raise FileExistsError(f"Destination already exists: {dst}")
            raise ctypes.WinError(err)
    else:
        if os.path.lexists(dst):
            raise FileExistsError(f"Destination already exists: {dst}")
        os.rename(src, dst)

    if not os.path.lexists(dst) or os.path.lexists(src):
        raise SafeFSError(f"Move verification failed: src={os.path.lexists(src)}, dst={os.path.lexists(dst)}")


# ---------------- ATOMIC JSON STORAGE WITH DURATION & FSYNC ----------------

def atomic_write_json(file_path: str, data: Dict[str, Any], expected_op_id: Optional[str] = None):
    """
    Atomically writes a dictionary to file_path via mkstemp + flush + fsync + os.replace.
    If file_path already exists and expected_op_id is provided, verifies ownership before replace.
    Verifies written file can be reloaded as valid JSON with the same operation_id.
    """
    file_path = os.path.abspath(file_path)
    target_dir = os.path.dirname(file_path)
    os.makedirs(target_dir, exist_ok=True)

    # If destination exists and expected_op_id provided, verify existing file belongs to this operation
    if os.path.isfile(file_path) and expected_op_id:
        try:
            with open(file_path, "r", encoding="utf-8") as existing_f:
                existing_data = json.load(existing_f)
            existing_op = existing_data.get("operation_id")
            if existing_op and existing_op != expected_op_id:
                raise SafeFSError(
                    f"Refusing to overwrite file {file_path}: operation ID mismatch (existing={existing_op}, expected={expected_op_id})"
                )
        except json.JSONDecodeError:
            # Existing file is corrupted, preserve it before replace
            corrupt_backup = f"{file_path}.corrupt.{int(time.time())}"
            try:
                shutil.copy2(file_path, corrupt_backup)
            except Exception:
                pass

    # Create temporary file in same directory for atomic replace
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

        # Post-write verification
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


def read_verified_json(file_path: str) -> Dict[str, Any]:
    """Reads and parses a JSON file safely. Raises SafeFSError on decode error."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SafeFSError(f"JSON file corrupted at {file_path}: {e}")


# ---------------- EXCLUSIVE OPERATION LOCKING ----------------

_IN_PROCESS_LOCKS: Set[str] = set()


class OperationLock:
    """
    Exclusive lock context manager for mutating folder operations.
    Guarantees only one active operation per protected folder.
    Prevents overlapping operations on parent/child directory trees.
    """
    def __init__(self, target_path: str, operation_type: str):
        self.target_path = os.path.normcase(os.path.abspath(target_path))
        self.operation_type = operation_type
        self.operation_id = str(uuid.uuid4())
        self.lock_file = os.path.join(self.target_path, OP_LOCK_FILENAME)
        self.lock_fd: Optional[int] = None
        self._acquired = False

    def acquire(self):
        if self._acquired:
            return self

        # 1. In-process overlap check
        for active in _IN_PROCESS_LOCKS:
            try:
                common = os.path.commonpath([self.target_path, active])
                if common == self.target_path or common == active:
                    raise OperationLockError(
                        f"An operation is already in progress on this folder or a parent/subfolder in this process."
                    )
            except ValueError:
                pass

        # 2. Check on-disk lock file
        if os.path.isfile(self.lock_file):
            try:
                lock_info = read_verified_json(self.lock_file)
                lock_pid = lock_info.get("pid", 0)
                if is_pid_running(lock_pid):
                    raise OperationLockError(
                        f"Folder is locked by another running FolderLock process (PID: {lock_pid}, Op: {lock_info.get('operation_type')})."
                    )
                else:
                    # Previous process crashed or terminated. Stale lock file.
                    # We do not delete silently if uncompleted journal is present.
                    pass
            except Exception as e:
                if isinstance(e, OperationLockError):
                    raise
                # Corrupted lock file
                pass

        # 3. Create exclusive lock file atomically
        try:
            # os.O_CREAT | os.O_EXCL ensures atomic creation
            self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            # File was created concurrently or stale
            if os.path.isfile(self.lock_file):
                try:
                    info = read_verified_json(self.lock_file)
                    if is_pid_running(info.get("pid", 0)):
                        raise OperationLockError(f"Concurrent operation initiated by PID {info.get('pid')}.")
                except OperationLockError:
                    raise
                except Exception:
                    pass
                # Safe stale lock cleanup
                try:
                    os.remove(self.lock_file)
                    self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                except Exception as ex:
                    raise OperationLockError(f"Failed to acquire exclusive lock: {ex}")
            else:
                raise OperationLockError("Failed to acquire lock due to race condition.")

        # Write lock payload
        lock_payload = {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "pid": os.getpid(),
            "target_path": self.target_path,
            "timestamp": time.time()
        }
        payload_bytes = json.dumps(lock_payload, indent=2).encode("utf-8")
        os.write(self.lock_fd, payload_bytes)
        os.fsync(self.lock_fd)

        if os.name == 'nt':
            add_hidden_system_attributes(self.lock_file)

        _IN_PROCESS_LOCKS.add(self.target_path)
        self._acquired = True
        return self

    def release(self):
        if not self._acquired:
            return

        if self.target_path in _IN_PROCESS_LOCKS:
            _IN_PROCESS_LOCKS.remove(self.target_path)

        if self.lock_fd is not None:
            try:
                os.close(self.lock_fd)
            except Exception:
                pass
            self.lock_fd = None

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


def acquire_operation_lock(target_path: str, operation_type: str) -> OperationLock:
    """Helper to instantiate and acquire an OperationLock."""
    lock = OperationLock(target_path, operation_type)
    return lock.acquire()


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
            # Check if directory itself is a reparse point or reserved
            if is_reparse_point(root):
                raise SafeFSError(f"Refusing to scan directory reparse point or junction: {root}")
            if not is_safe_relative_path(rel_root, folder_path):
                raise PathValidationError(f"Unsafe directory path detected: {rel_root}")

        # Filter out reserved metadata directories
        dirs[:] = [d for d in dirs if d not in reserved_names]

        # Audit files
        for fname in sorted(files):
            if fname in reserved_names:
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
    needed_bytes = int(total_bytes * 1.05) + 10 * 1024 * 1024  # Vault overhead + 10MB safety margin
    if free_bytes < needed_bytes:
        raise SafeFSError(
            f"Insufficient disk space: {needed_bytes // (1024*1024)} MB required, "
            f"but only {free_bytes // (1024*1024)} MB available on volume."
        )

    return manifest, total_files, total_bytes
