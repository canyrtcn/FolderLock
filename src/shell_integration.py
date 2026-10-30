"""
FolderLock - Windows Shell Integration
Registers and unregisters .locked extension and context menu in HKEY_CURRENT_USER (No admin rights required).
Completely user-isolated, portable, and clean.

Version 1.0.3 Updates:
- Verifies that registered command string points to a valid, existing executable.
- Handles portable relocations (updates registration if path changed).
- Transactional registration with automatic rollback on error.
- Never clobbers or deletes unrelated foreign registry keys.
"""

import os
import sys
import ctypes
import winreg
from typing import Tuple

PROGID = "FolderLock.Vault"
MENU_KEY = r"Software\Classes\Directory\shell\FolderLock"


def _app_command(exe_path: str) -> str:
    if not getattr(sys, "frozen", False) and os.path.normcase(exe_path) == os.path.normcase(sys.executable):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
        return f'"{exe_path}" "{script}" "%1"'
    return f'"{exe_path}" "%1"'


def _notify_explorer():
    """Refresh cached associations without restarting Explorer."""
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)


def get_app_exe_path() -> str:
    """Returns absolute path to the current FolderLock executable."""
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative_path in (os.path.join("dist", "FolderLock.exe"),
                          os.path.join("dist", "FolderLock_portable", "FolderLock.exe"),
                          "FolderLock.exe"):
        dev_exe = os.path.join(project_dir, relative_path)
        if os.path.isfile(dev_exe):
            return dev_exe
    return os.path.abspath(sys.executable)


def is_shell_integration_enabled() -> bool:
    """
    True only when the folder command points to this copy of FolderLock.
    A still-existing older portable copy is a stale registration.
    """
    if os.name != 'nt':
        return False
    try:
        exe_path = get_app_exe_path()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Classes\Directory\shell\FolderLock\command"
        ) as key:
            cmd, _ = winreg.QueryValueEx(key, "")
            if not isinstance(cmd, str) or not cmd:
                return False
            return (cmd.casefold() == _app_command(exe_path).casefold()
                    and os.path.isfile(exe_path))
    except OSError:
        return False


def setup_shell_integration() -> Tuple[bool, str]:
    """Configures HKCU registry for .locked extension and explorer integration with rollback."""
    if os.name != 'nt':
        return False, "Shell integration is only supported on Windows."

    exe_path = get_app_exe_path()
    if not exe_path or not os.path.isfile(exe_path):
        return False, f"FolderLock executable not found at: {exe_path}"

    changes = []
    created_subkeys = []
    try:
        # .locked may already belong to another application. Refuse before
        # touching any registry value rather than stealing its association.
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked") as key:
                owner, _ = winreg.QueryValueEx(key, "")
                if owner and owner != PROGID:
                    return False, "The .locked extension is registered to another application."
        except FileNotFoundError:
            pass

        command = _app_command(exe_path)
        values = [
            (r"Software\Classes\.locked", "", PROGID),
            (rf"Software\Classes\{PROGID}", "", "Locked Folder (FolderLock)"),
            (rf"Software\Classes\{PROGID}\DefaultIcon", "", f'"{exe_path}",0'),
            (rf"Software\Classes\{PROGID}\shell", None, None),
            (rf"Software\Classes\{PROGID}\shell\open", "", "Unlock with FolderLock"),
            (rf"Software\Classes\{PROGID}\shell\open\command", "", command),
            (MENU_KEY, "", "FolderLock - Lock / Unlock"),
            (MENU_KEY, "Icon", f'"{exe_path}",0'),
            (MENU_KEY + r"\command", "", command),
        ]
        for path, name, value in values:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path):
                    pass
            except FileNotFoundError:
                created_subkeys.append(path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                if name is None:
                    continue
                try:
                    previous = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    previous = None
                changes.append((path, name, previous))
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

        if not is_shell_integration_enabled():
            raise RuntimeError("Verification failed: registry command does not point to current executable.")

        _notify_explorer()
        return True, "Shell integration configured successfully."

    except Exception as e:
        rollback_errors = []
        for path, name, previous in reversed(changes):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
                    if previous is None:
                        try:
                            winreg.DeleteValue(key, name)
                        except FileNotFoundError:
                            pass
                    else:
                        winreg.SetValueEx(key, name, 0, previous[1], previous[0])
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        for path in reversed(created_subkeys):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        detail = f" Rollback errors: {'; '.join(rollback_errors)}" if rollback_errors else ""
        return False, f"Failed to configure shell integration: {e}{detail}"


def refresh_shell_integration() -> Tuple[bool, str]:
    """Repair an already opted-in registration after moving/updating the EXE.

    Never enable integration for a user who has not registered it. Only a
    FolderLock command in our own menu key is eligible for automatic repair.
    """
    if os.name != "nt":
        return False, "Shell integration is only supported on Windows."
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, MENU_KEY + r"\command") as key:
            command, _ = winreg.QueryValueEx(key, "")
        if is_shell_integration_enabled():
            return True, "Shell integration is up to date."
        if not isinstance(command, str):
            return False, "Existing shell command is not a string."
        parts = command.split('"')
        if (len(parts) != 5 or parts[0] or parts[2] != " " or parts[4]
                or parts[3] != "%1"):
            return False, "Existing shell command is not a recognized FolderLock registration."
        if os.path.basename(parts[1]).lower() != "folderlock.exe":
            # A portable EXE may have been renamed. Our label and matching
            # icon also identify registrations made by setup_shell_integration.
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, MENU_KEY) as key:
                label, _ = winreg.QueryValueEx(key, "")
                icon, _ = winreg.QueryValueEx(key, "Icon")
            if label != "FolderLock - Lock / Unlock" or icon != f'"{parts[1]}",0':
                return False, "Existing shell command is not a recognized FolderLock registration."
        return setup_shell_integration()
    except OSError as e:
        return False, str(e)


def remove_shell_integration() -> Tuple[bool, str]:
    """Safely removes FolderLock shell integration from HKCU registry."""
    if os.name != 'nt':
        return False, "Shell integration is only supported on Windows."

    def _delete_key_tree(root, subkey):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                while winreg.QueryInfoKey(key)[0]:
                    child = winreg.EnumKey(key, 0)
                    _delete_key_tree(key, child)
            winreg.DeleteKey(root, subkey)
        except FileNotFoundError:
            pass

    try:
        # Verify ProgID ownership before deleting .locked extension
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked") as k:
                val, _ = winreg.QueryValueEx(k, "")
                if val == PROGID:
                    _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked")
        except FileNotFoundError:
            pass

        _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock")
        _delete_key_tree(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}")

        if is_shell_integration_enabled():
            return False, "Failed to completely remove registry keys."

        _notify_explorer()
        return True, "Shell integration removed successfully."
    except Exception as e:
        return False, f"Failed to remove shell integration: {e}"
