"""Exercise Explorer/shortcut argument routing without opening user windows."""

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import main


class EntrypointRoutingTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="flock_entrypoint_")
        self.addCleanup(self.work.cleanup)
        self.folder = str(Path(self.work.name) / "Folder with saved settings")
        os.mkdir(self.folder)
        self.config = SimpleNamespace(language="en")

    def invoke(self, args, locked=None, relock=None):
        with patch.object(main.sys, "argv", ["FolderLock.exe", *args]), \
                patch.object(main.sys, "frozen", False, create=True), \
                patch.object(main, "ConfigManager", return_value=self.config), \
                patch.object(main, "set_current_lang"), \
                patch.object(main, "is_folder_locked", return_value=locked), \
                patch.object(main, "get_relock_config", return_value=relock), \
                patch.object(main, "FolderLockApp") as full_app, \
                patch.object(main, "InFolderLockApp") as lock_app, \
                patch.object(main, "InFolderUnlockApp") as unlock_app:
            main.main()
            return full_app, lock_app, unlock_app

    def test_explorer_unlocked_folder_with_saved_settings_opens_lock_folder(self):
        for mode in ("instant", "crypto"):
            with self.subTest(mode=mode):
                full, compact_lock, compact_unlock = self.invoke([self.folder], relock={"mode": mode})
                full.assert_called_once_with(config_mgr=self.config)
                full.return_value._set_folder_for_locking.assert_called_once_with(self.folder)
                full.return_value.tabview.set.assert_called_once_with("tab_lock")
                full.return_value.mainloop.assert_called_once_with()
                compact_lock.assert_not_called()
                compact_unlock.assert_not_called()

    def test_explorer_new_unlocked_folder_opens_lock_folder(self):
        full, compact_lock, compact_unlock = self.invoke([self.folder])
        full.return_value.tabview.set.assert_called_once_with("tab_lock")
        full.return_value._set_folder_for_locking.assert_called_once_with(self.folder)
        compact_lock.assert_not_called()
        compact_unlock.assert_not_called()

    def test_explorer_locked_folder_opens_unlock_dialog(self):
        full, compact_lock, compact_unlock = self.invoke([self.folder], locked="instant")
        compact_unlock.assert_called_once_with(self.folder)
        compact_unlock.return_value.mainloop.assert_called_once_with()
        compact_lock.assert_not_called()
        full.assert_not_called()

    def test_explicit_lock_shortcut_keeps_compact_relock_dialog(self):
        full, compact_lock, compact_unlock = self.invoke(["--lock", self.folder], relock={"mode": "instant"})
        compact_lock.assert_called_once_with(self.folder)
        compact_lock.return_value.mainloop.assert_called_once_with()
        full.assert_not_called()
        compact_unlock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
