"""Portable shell registration tests in an isolated temporary HKCU subtree."""

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import winreg

import shell_integration as shell


@unittest.skipUnless(os.name == "nt", "Windows registry required")
class ShellRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="flock_shell_registration_")
        self.addCleanup(self.work.cleanup)
        self.folder = Path(self.work.name)
        self.exe = self.folder / "Portable with spaces İ" / "FolderLock.exe"
        self.exe.parent.mkdir()
        self.exe.touch()
        self.registry_path = rf"Software\FolderLockTests\{uuid.uuid4().hex}"
        self.hive = winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.registry_path)
        proxy = SimpleNamespace(**{name: getattr(winreg, name) for name in dir(winreg)
                                  if not name.startswith("_")})
        proxy.HKEY_CURRENT_USER = self.hive
        self.addCleanup(self.clean_registry)
        self.addCleanup(patch.stopall)
        patch.object(shell, "winreg", proxy).start()
        patch.object(shell, "sys", SimpleNamespace(frozen=True, executable=str(self.exe))).start()
        patch.object(shell, "_notify_explorer").start()

    def clean_registry(self):
        def remove_tree(key, path):
            with winreg.OpenKey(key, path, 0, winreg.KEY_ALL_ACCESS) as child:
                while winreg.QueryInfoKey(child)[0]:
                    remove_tree(child, winreg.EnumKey(child, 0))
            winreg.DeleteKey(key, path)
        self.hive.Close()
        remove_tree(winreg.HKEY_CURRENT_USER, self.registry_path)

    def set_value(self, path, value, name=""):
        with winreg.CreateKey(self.hive, path) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def read_value(self, path, name=""):
        with winreg.OpenKey(self.hive, path) as key:
            return winreg.QueryValueEx(key, name)[0]

    def test_frozen_registration_uses_its_own_exe_and_quotes_target(self):
        ok, message = shell.setup_shell_integration()
        self.assertTrue(ok, message)
        expected = f'"{self.exe}" "%1"'
        self.assertEqual(self.read_value(shell.MENU_KEY + r"\command"), expected)
        self.assertEqual(self.read_value(rf"Software\Classes\{shell.PROGID}\shell\open\command"), expected)
        self.assertTrue(shell.is_shell_integration_enabled())
        ok, message = shell.remove_shell_integration()
        self.assertTrue(ok, message)
        self.assertFalse(shell.is_shell_integration_enabled())

    def test_other_existing_copy_is_stale_and_is_repaired(self):
        old_exe = self.folder / "old" / "FolderLock.exe"
        old_exe.parent.mkdir()
        old_exe.touch()
        self.set_value(shell.MENU_KEY + r"\command", f'"{old_exe}" "%1"')
        self.assertFalse(shell.is_shell_integration_enabled())
        ok, message = shell.refresh_shell_integration()
        self.assertTrue(ok, message)
        self.assertEqual(self.read_value(shell.MENU_KEY + r"\command"), f'"{self.exe}" "%1"')

    def test_deleted_old_exe_is_repaired(self):
        old_exe = self.folder / "deleted copy" / "FolderLock.exe"
        self.set_value(shell.MENU_KEY + r"\command", f'"{old_exe}" "%1"')
        ok, message = shell.refresh_shell_integration()
        self.assertTrue(ok, message)
        self.assertTrue(shell.is_shell_integration_enabled())

    def test_renamed_portable_exe_can_also_be_relocated(self):
        renamed_exe = self.folder / "Renamed portable tool.exe"
        renamed_exe.touch()
        with patch.object(shell, "sys", SimpleNamespace(frozen=True, executable=str(renamed_exe))):
            ok, message = shell.setup_shell_integration()
            self.assertTrue(ok, message)
        renamed_exe.unlink()
        ok, message = shell.refresh_shell_integration()
        self.assertTrue(ok, message)
        self.assertEqual(self.read_value(shell.MENU_KEY + r"\command"), f'"{self.exe}" "%1"')

    def test_removal_reports_registry_permission_failure(self):
        ok, message = shell.setup_shell_integration()
        self.assertTrue(ok, message)
        with patch.object(shell.winreg, "DeleteKey", side_effect=PermissionError("Synthetic registry denial")):
            ok, message = shell.remove_shell_integration()
        self.assertFalse(ok)
        self.assertIn("Synthetic registry denial", message)

    def test_disabled_integration_stays_disabled(self):
        ok, _ = shell.refresh_shell_integration()
        self.assertFalse(ok)
        with self.assertRaises(FileNotFoundError):
            self.read_value(shell.MENU_KEY + r"\command")

    def test_unrecognized_command_is_not_automatically_replaced(self):
        original = f'"{self.exe}" --custom-argument "%1"'
        self.set_value(shell.MENU_KEY + r"\command", original)
        ok, _ = shell.refresh_shell_integration()
        self.assertFalse(ok)
        self.assertEqual(self.read_value(shell.MENU_KEY + r"\command"), original)

    def test_foreign_extension_is_never_overwritten(self):
        extension = r"Software\Classes\.locked"
        self.set_value(extension, "AnotherApplication.Document")
        ok, _ = shell.setup_shell_integration()
        self.assertFalse(ok)
        self.assertEqual(self.read_value(extension), "AnotherApplication.Document")
        with self.assertRaises(FileNotFoundError):
            self.read_value(shell.MENU_KEY + r"\command")

    def test_failed_update_restores_previous_registration(self):
        old_exe = self.folder / "old" / "FolderLock.exe"
        self.set_value(shell.MENU_KEY + r"\command", f'"{old_exe}" "%1"')
        self.set_value(shell.MENU_KEY, "original label")
        self.set_value(shell.MENU_KEY, "unrelated user value", "CustomValue")
        real_write = shell.winreg.SetValueEx
        failed = False

        def fail_once(key, name, reserved, value_type, value):
            nonlocal failed
            if value == f'"{self.exe}" "%1"' and not failed:
                failed = True
                raise PermissionError("Synthetic registry write failure")
            return real_write(key, name, reserved, value_type, value)

        with patch.object(shell.winreg, "SetValueEx", side_effect=fail_once):
            ok, message = shell.setup_shell_integration()
        self.assertFalse(ok)
        self.assertNotIn("Rollback errors:", message)
        self.assertEqual(self.read_value(shell.MENU_KEY + r"\command"), f'"{old_exe}" "%1"')
        self.assertEqual(self.read_value(shell.MENU_KEY), "original label")
        self.assertEqual(self.read_value(shell.MENU_KEY, "CustomValue"), "unrelated user value")
        with self.assertRaises(FileNotFoundError):
            self.read_value(r"Software\Classes\.locked")

    def test_development_exe_resolution_does_not_depend_on_working_directory(self):
        project = self.folder / "project"
        (project / "dist").mkdir(parents=True)
        built_exe = project / "dist" / "FolderLock.exe"
        built_exe.touch()
        previous_cwd = os.getcwd()
        try:
            os.chdir(self.folder)
            with patch.object(shell, "__file__", str(project / "shell_integration.py")), \
                    patch.object(shell, "sys", SimpleNamespace(frozen=False, executable="python.exe")):
                self.assertEqual(shell.get_app_exe_path(), str(built_exe))
        finally:
            os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
