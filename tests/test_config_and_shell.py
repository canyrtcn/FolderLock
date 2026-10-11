"""
FolderLock - Tests for ConfigManager and Shell Integration
Validates atomic persistence, deep copy protection, corrupted backup creation, and shell validation.
"""

import os
import sys
import tempfile
import shutil
import unittest
import json

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config_manager
from config_manager import ConfigManager, DEFAULT_CONFIG
import shell_integration


class TestConfigAndShell(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_test_cfg_")
        self.old_config_path = config_manager.get_config_path
        # Override config path to isolated test file
        self.cfg_file = os.path.join(self.test_dir, "settings.json")
        config_manager.get_config_path = lambda: self.cfg_file

    def tearDown(self):
        config_manager.get_config_path = self.old_config_path
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_config_defaults_and_save(self):
        cm = ConfigManager()
        self.assertEqual(cm.language, "en")
        self.assertIn(cm.theme, ["dark", "light"])

        # Change settings
        cm.language = "tr"
        cm.theme = "light"
        cm.add_vault_item(
            name="MyVault",
            locked_path="C:\\test\\locked",
            original_path="C:\\test\\orig",
            size_bytes=1024,
            mode="crypto"
        )

        # Reload from disk
        cm2 = ConfigManager()
        self.assertEqual(cm2.language, "tr")
        self.assertEqual(cm2.theme, "light")
        vault = cm2.get_vault()
        self.assertEqual(len(vault), 1)
        self.assertEqual(vault[0]["name"], "MyVault")

    def test_config_corrupted_backup_preservation(self):
        # Write corrupted/invalid JSON to settings.json
        with open(self.cfg_file, "w", encoding="utf-8") as f:
            f.write("CORRUPTED_NOT_VALID_JSON{{{")

        # ConfigManager._load should detect corruption, create a backup, and load defaults
        cm = ConfigManager()
        self.assertEqual(cm.language, "en")

        # Verify corrupted backup exists in directory
        corrupted_files = [f for f in os.listdir(self.test_dir) if "corrupt" in f]
        self.assertTrue(len(corrupted_files) > 0)
        with open(os.path.join(self.test_dir, corrupted_files[0]), "r") as f:
            self.assertEqual(f.read(), "CORRUPTED_NOT_VALID_JSON{{{")

    def test_config_deepcopy_isolation(self):
        cm = ConfigManager()
        # Modifying DEFAULT_CONFIG must not leak into config instance
        DEFAULT_CONFIG["vault"].append({"test": "bad"})
        self.assertEqual(len(cm.get_vault()), 0)
        DEFAULT_CONFIG["vault"].clear()

    @unittest.skipUnless(os.name == 'nt', "Windows-specific shell integration test")
    def test_shell_integration_query(self):
        # Verification function runs without exception
        is_enabled = shell_integration.is_shell_integration_enabled()
        self.assertIsInstance(is_enabled, bool)


if __name__ == "__main__":
    unittest.main()
