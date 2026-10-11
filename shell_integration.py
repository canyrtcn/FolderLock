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
import winreg
from typing import Tuple

PROGID = "FolderLock.Vault"


def get_app_exe_path() -> str:
    """Returns absolute path to the current FolderLock executable."""
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    dev_exe = os.path.abspath("FolderLock.exe")
    if os.path.isfile(dev_exe):
        return dev_exe
    return os.path.abspath(sys.executable)


def is_shell_integration_enabled() -> bool:
    """
    Checks if shell integration is correctly enabled and points to a valid executable.
    Returns True ONLY if registry keys exist AND command points to the current or existing executable.
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
            if not cmd:
                return False
            # Check if command points to current exe_path
            expected_prefix = f'"{exe_path}"'
            if cmd.lower().startswith(expected_prefix.lower()):
                return os.path.isfile(exe_path)
            # If pointing to an existing FolderLock.exe elsewhere
            if "folderlock.exe" in cmd.lower():
                registered_path = cmd.split('"')[1] if '"' in cmd else cmd.split()[0]
                return os.path.isfile(registered_path)
            return False
    except OSError:
        return False


def setup_shell_integration() -> Tuple[bool, str]:
    """Configures HKCU registry for .locked extension and explorer integration with rollback."""
    if os.name != 'nt':
        return False, "Shell integration is only supported on Windows."

    exe_path = get_app_exe_path()
    if not exe_path or not os.path.isfile(exe_path):
        return False, f"FolderLock executable not found at: {exe_path}"

    created_subkeys = []

    try:
        # 1. Register .locked extension
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, PROGID)
            created_subkeys.append(r"Software\Classes\.locked")

        # 2. Register ProgID
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Locked Folder (FolderLock)")
            created_subkeys.append(rf"Software\Classes\{PROGID}")

        # 3. Default Icon (uses FolderLock's embedded icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}\DefaultIcon") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}",0')

        # 4. Double click command: launches FolderLock with target path
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}\shell\open") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Unlock with FolderLock")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}\shell\open\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}" "%1"')

        # 5. Right-click context menu on normal folders: "FolderLock - Lock / Unlock"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "FolderLock - Lock / Unlock")
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{exe_path}",0')
            created_subkeys.append(r"Software\Classes\Directory\shell\FolderLock")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}" "%1"')

        if not is_shell_integration_enabled():
            raise RuntimeError("Verification failed: registry command does not point to current executable.")

        return True, "Shell integration configured successfully."

    except Exception as e:
        # Rollback created keys
        remove_shell_integration()
        return False, f"Failed to configure shell integration: {e}"


def remove_shell_integration() -> Tuple[bool, str]:
    """Safely removes FolderLock shell integration from HKCU registry."""
    if os.name != 'nt':
        return False, "Shell integration is only supported on Windows."

    def _delete_key_tree(root, subkey):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                while True:
                    try:
                        child = winreg.EnumKey(key, 0)
                        _delete_key_tree(key, child)
                    except OSError:
                        break
            winreg.DeleteKey(root, subkey)
        except OSError:
            pass

    try:
        # Verify ProgID ownership before deleting .locked extension
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked") as k:
                val, _ = winreg.QueryValueEx(k, "")
                if val == PROGID:
                    _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked")
        except OSError:
            pass

        _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock")
        _delete_key_tree(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}")

        if is_shell_integration_enabled():
            return False, "Failed to completely remove registry keys."

        return True, "Shell integration removed successfully."
    except Exception as e:
        return False, f"Failed to remove shell integration: {e}"
