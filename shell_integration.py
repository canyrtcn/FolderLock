"""
FolderLock - Windows Shell Integration
Registers and unregisters .locked extension and context menu in HKEY_CURRENT_USER (No admin rights required).
Completely user-isolated, portable, and clean.
"""

import os
import sys
import winreg

PROGID = "FolderLock.Vault"


def get_app_exe_path() -> str:
    if getattr(sys, 'frozen', False):
        return sys.executable
    dev_exe = os.path.abspath("FolderLock.exe")
    if os.path.isfile(dev_exe):
        return dev_exe
    return sys.executable


def setup_shell_integration():
    """Configures HKCU registry for .locked extension and explorer integration."""
    try:
        exe_path = get_app_exe_path()
        if not exe_path or not os.path.isfile(exe_path):
            return

        # 1. Register .locked extension
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, PROGID)

        # 2. Register ProgID
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "Locked Folder (FolderLock)")

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
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock\command") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, f'"{exe_path}" "%1"')

    except Exception:
        pass


def remove_shell_integration():
    """Removes FolderLock shell integration from HKCU registry."""
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

    _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock")
    _delete_key_tree(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{PROGID}")
    _delete_key_tree(winreg.HKEY_CURRENT_USER, r"Software\Classes\.locked")


def is_shell_integration_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\FolderLock") as key:
            return True
    except OSError:
        return False


if __name__ == "__main__":
    setup_shell_integration()
    print("Shell integration executed successfully.")
