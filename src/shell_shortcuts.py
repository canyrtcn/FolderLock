"""Native Windows Shell Links for FolderLock's in-folder lock/unlock actions.

Uses Windows COM, central executable references, and ownership validation.
"""

import ctypes
import os
import shlex
import stat
import subprocess
import sys
import uuid
from ctypes import wintypes
from typing import Optional, Set, Tuple

import safe_fs
from shell_integration import get_app_exe_path


class ShortcutError(RuntimeError):
    pass


class ShortcutConflictError(RuntimeError):
    pass


SHORTCUT_LOCK_NAME = 'FolderLock - Lock.lnk'
SHORTCUT_UNLOCK_NAME = 'FolderLock - Unlock.lnk'
SHORTCUT_NAMES = (SHORTCUT_LOCK_NAME, SHORTCUT_UNLOCK_NAME)


class GUID(ctypes.Structure):
    _fields_ = [('Data1', ctypes.c_uint32), ('Data2', ctypes.c_uint16),
                ('Data3', ctypes.c_uint16), ('Data4', ctypes.c_ubyte * 8)]


def _guid(value):
    return GUID.from_buffer_copy(uuid.UUID(value).bytes_le)


CLSID_SHELL_LINK = _guid('00021401-0000-0000-c000-000000000046')
IID_ISHELL_LINK_W = _guid('000214f9-0000-0000-c000-000000000046')
IID_IPERSIST_FILE = _guid('0000010b-0000-0000-c000-000000000046')


class _ShellLink:
    """Small Windows COM wrapper; balance COM interfaces/initialization strictly."""

    def __enter__(self):
        if os.name != 'nt':
            raise OSError('Windows Shell Link COM is only available on Windows.')
        self._initialized = False
        self._link = ctypes.c_void_p()
        self._persist = ctypes.c_void_p()
        ole32 = ctypes.OleDLL('ole32')
        ole32.CoInitializeEx.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        ole32.CoInitializeEx.restype = ctypes.c_long
        hr = ole32.CoInitializeEx(None, 0x2)  # COINIT_APARTMENTTHREADED
        if hr in (0, 1):
            self._initialized = True
        elif hr != -2147417850:  # RPC_E_CHANGED_MODE: already initialized differently
            raise ShortcutError(f'CoInitializeEx failed: 0x{hr & 0xffffffff:08x}')
        try:
            ole32.CoCreateInstance.argtypes = (
                ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_uint32,
                ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p))
            ole32.CoCreateInstance.restype = ctypes.c_long
            hr = ole32.CoCreateInstance(ctypes.byref(CLSID_SHELL_LINK), None, 1,
                                        ctypes.byref(IID_ISHELL_LINK_W),
                                        ctypes.byref(self._link))
            self._check(hr, 'CoCreateInstance')
            self._call(self._link, 0, (ctypes.POINTER(GUID),
                                      ctypes.POINTER(ctypes.c_void_p)),
                       ctypes.byref(IID_IPERSIST_FILE), ctypes.byref(self._persist))
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    @staticmethod
    def _check(hr, operation):
        if hr < 0:
            raise ShortcutError(f'{operation} failed: 0x{hr & 0xffffffff:08x}')

    @staticmethod
    def _call(obj, index, params, *args):
        vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        func = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *params)(vtbl[index])
        hr = func(obj, *args)
        _ShellLink._check(hr, f'COM method #{index}')
        return hr

    def make(self, link_path, executable, args, working_directory):
        self._call(self._link, 20, (wintypes.LPCWSTR,), executable)  # SetPath
        self._call(self._link, 11, (wintypes.LPCWSTR,), args)  # SetArguments
        self._call(self._link, 9, (wintypes.LPCWSTR,), working_directory)
        self._call(self._link, 7, (wintypes.LPCWSTR,), 'FolderLock local folder action')
        self._call(self._link, 17, (wintypes.LPCWSTR, ctypes.c_int), executable, 0)
        self._call(self._persist, 6, (wintypes.LPCWSTR, wintypes.BOOL), link_path, True)

    def read(self, path):
        self._call(self._persist, 5, (wintypes.LPCWSTR, ctypes.c_uint32), path, 0)
        target = ctypes.create_unicode_buffer(32768)
        args = ctypes.create_unicode_buffer(32768)
        wd = ctypes.create_unicode_buffer(32768)
        self._call(self._link, 3, (wintypes.LPWSTR, ctypes.c_int,
                                   ctypes.c_void_p, ctypes.c_uint32), target,
                   len(target), None, 4)  # SLGP_RAWPATH
        self._call(self._link, 10, (wintypes.LPWSTR, ctypes.c_int), args, len(args))
        self._call(self._link, 8, (wintypes.LPWSTR, ctypes.c_int), wd, len(wd))
        return target.value, args.value, wd.value

    def __exit__(self, *_):
        for obj in (self._persist, self._link):
            if obj and obj.value:
                vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[2])
                release(obj)
        self._persist = ctypes.c_void_p()
        self._link = ctypes.c_void_p()
        if self._initialized:
            ctypes.OleDLL('ole32').CoUninitialize()
            self._initialized = False


def create_prototype(folder, executable, action):
    """Create a *new* .lnk atomically. Existing user files are never overwritten.

    IMPORTANT: Proves only Windows Shell Link creation. Never call from a lock
    transaction before the separate ownership/recovery design is validated.
    """
    if os.name != 'nt':
        raise OSError('Windows required')
    if action not in ('lock', 'unlock'):
        raise ValueError('Invalid action')
    folder = os.path.abspath(folder)
    executable = os.path.abspath(executable)
    if not os.path.isdir(folder) or not os.path.isfile(executable):
        raise FileNotFoundError('Target folder and FolderLock EXE must exist')
    name = f'FolderLock - {action.title()}.lnk'
    output = os.path.join(folder, name)
    if os.path.lexists(output):
        return False
    argument = subprocess.list2cmdline([f'--{action}', folder])
    temp_path = os.path.join(folder, f'.folderlock_shortcut_{uuid.uuid4().hex}.lnk')
    try:
        with _ShellLink() as link:
            link.make(temp_path, executable, argument, folder)
        # Windows os.rename does not overwrite existing destination paths.
        os.rename(temp_path, output)
        return True
    except BaseException:
        if os.path.isfile(temp_path) and not os.path.islink(temp_path):
            os.unlink(temp_path)
        raise


def inspect_prototype(path):
    with _ShellLink() as link:
        return link.read(os.path.abspath(path))


def is_authentic_folderlock_shortcut(shortcut_path: str, expected_folder: str,
                                     expected_action: Optional[str] = None,
                                     expected_exe: Optional[str] = None) -> bool:
    """
    Validates that a .lnk file is genuine FolderLock infrastructure and NOT user data.
    Verifies:
    1. Running on Windows NT.
    2. Regular file (strictly not symlink, not junction, not reparse point).
    3. Correct naming (FolderLock - Lock.lnk or FolderLock - Unlock.lnk).
    4. Valid Windows Shell Link COM parse.
    5. Target points to trusted FolderLock executable.
    6. Arguments strictly match action and expected folder.
    7. Working directory matches expected folder.
    """
    if os.name != 'nt':
        return False
    if not shortcut_path or not os.path.isfile(shortcut_path):
        return False
    if os.path.islink(shortcut_path) or safe_fs.is_reparse_point(shortcut_path):
        return False

    base_name = os.path.basename(shortcut_path)
    if expected_action:
        if base_name.lower() != f"folderlock - {expected_action.lower()}.lnk":
            return False
    else:
        if base_name.lower() not in (SHORTCUT_LOCK_NAME.lower(), SHORTCUT_UNLOCK_NAME.lower()):
            return False

    try:
        target, args, wd = inspect_prototype(shortcut_path)
    except Exception:
        return False

    norm_folder = os.path.normcase(os.path.abspath(expected_folder))
    norm_wd = os.path.normcase(os.path.abspath(wd)) if wd else ""
    if norm_wd != norm_folder:
        return False

    if expected_exe is None:
        expected_exe = get_app_exe_path()
    norm_target = os.path.normcase(os.path.abspath(target)) if target else ""
    norm_expected_exe = os.path.normcase(os.path.abspath(expected_exe)) if expected_exe else ""

    is_same_exe = (norm_target == norm_expected_exe)
    if not is_same_exe and os.path.isfile(norm_target) and os.path.isfile(norm_expected_exe):
        try:
            is_same_exe = os.path.samefile(norm_target, norm_expected_exe)
        except Exception:
            is_same_exe = False

    if not is_same_exe:
        target_base = os.path.basename(norm_target).lower()
        if target_base in ("folderlock.exe", "folderlock-v1.0.5-test.exe", "python.exe", "pythonw.exe"):
            expected_dir = os.path.normcase(os.path.abspath(os.path.dirname(norm_expected_exe)))
            target_dir = os.path.normcase(os.path.abspath(os.path.dirname(norm_target)))
            if target_dir == expected_dir:
                is_same_exe = True
            else:
                try:
                    if os.path.samefile(target_dir, expected_dir):
                        is_same_exe = True
                except Exception:
                    pass

    if not is_same_exe:
        return False

    # Check arguments
    try:
        tokens = shlex.split(args, posix=False)
    except Exception:
        tokens = args.split()

    if len(tokens) != 2:
        return False

    flag, folder_arg = tokens[0].lower(), tokens[1].strip('"\'')
    if expected_action:
        if flag != f"--{expected_action.lower()}":
            return False
    else:
        if flag not in ("--lock", "--unlock"):
            return False

    if os.path.normcase(os.path.abspath(folder_arg)) != norm_folder:
        return False

    return True


def _safe_remove_shortcut_file(path: str, allowed_names: Set[str]) -> None:
    if not os.path.lexists(path):
        return
    if os.path.islink(path):
        raise RuntimeError(f"Refusing to remove symlink shortcut: {path}")
    if os.path.isdir(path):
        raise RuntimeError(f"Refusing to remove directory as shortcut: {path}")
    base = os.path.basename(path)
    if base not in allowed_names:
        raise RuntimeError(f"Refusing to remove file outside allowed shortcut set: {path}")
    if os.name == 'nt':
        try:
            os.chmod(path, stat.S_IWRITE)
        except Exception:
            pass
    os.remove(path)


def audit_and_clean_authentic_shortcuts(folder_path: str, expected_exe: Optional[str] = None) -> None:
    """
    Preflight check before locking (AES and Instant).
    - If a shortcut is authentic, safely deletes it so it won't be packed into AES
      vault or moved into .locked_data container.
    - If a file of that name exists but is NOT authentic (user data / corrupted / malicious),
      RAISES CryptoError to fail closed and prevent data loss or unencrypted exclusion!
    """
    if os.name != 'nt':
        return
    folder_path = os.path.abspath(folder_path)
    try:
        from crypto_engine import CryptoError
    except ImportError:
        CryptoError = ShortcutConflictError

    for action in ('lock', 'unlock'):
        fname = f"FolderLock - {action.title()}.lnk"
        fpath = os.path.join(folder_path, fname)
        if os.path.lexists(fpath):
            if is_authentic_folderlock_shortcut(fpath, folder_path, expected_action=action, expected_exe=expected_exe):
                _safe_remove_shortcut_file(fpath, allowed_names={fname})
            else:
                raise CryptoError(
                    f"Pre-existing '{fname}' is user data and cannot be managed as a FolderLock shortcut; "
                    "please rename or back up the file before locking."
                )


def deploy_folderlock_shortcuts(folder_path: str,
                                actions: Tuple[str, ...] = ('lock', 'unlock'),
                                executable: Optional[str] = None) -> None:
    """
    Creates fresh, verified Windows Shell Link shortcuts in the target folder.
    Never overwrites existing files of the same name.
    """
    if os.name != 'nt':
        return
    folder_path = os.path.abspath(folder_path)
    if not os.path.isdir(folder_path):
        return
    if executable is None:
        executable = get_app_exe_path()
    if not executable or not os.path.isfile(executable):
        return

    for action in actions:
        fname = f"FolderLock - {action.title()}.lnk"
        fpath = os.path.join(folder_path, fname)
        if os.path.lexists(fpath):
            continue
        try:
            create_prototype(folder_path, executable, action)
        except Exception:
            pass
