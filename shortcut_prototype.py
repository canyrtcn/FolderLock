"""Windows Shell Link proof-of-concept. Not installed into FolderLock automatically.

Uses only Windows COM; no PowerShell, WScript, copied executables, or scripts.
Prototype only: not yet integrated with AES/Instant state machines.
"""

import ctypes
import os
import subprocess
import sys
import uuid
from ctypes import wintypes


class ShortcutError(RuntimeError):
    pass


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