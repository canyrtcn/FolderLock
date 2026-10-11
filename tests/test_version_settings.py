"""Tests for consistent installed-version display; no GUI or user folders."""
import ast
import unittest
from pathlib import Path

from translations import APP_VERSION, t, set_current_lang, get_current_lang

ROOT = Path(__file__).resolve().parent.parent


class VersionSettingsTests(unittest.TestCase):
    def test_version_is_consistent_across_locales(self):
        previous = get_current_lang()
        try:
            for lang, label in (("tr", "Sürüm:"), ("en", "Version:")):
                with self.subTest(lang=lang):
                    set_current_lang(lang)
                    self.assertEqual(t("version"), APP_VERSION)
                    self.assertEqual(t("setting_version"), label)
        finally:
            set_current_lang(previous)

    def test_version_matches_windows_executable_metadata(self):
        info = (ROOT / "version_info.txt").read_text(encoding="utf-8")
        parts = tuple(map(int, APP_VERSION.split(".")))
        self.assertEqual(len(parts), 3)
        expected_tuple = f"({parts[0]}, {parts[1]}, {parts[2]}, 0)"
        self.assertIn(f"filevers={expected_tuple}", info)
        self.assertIn(f"prodvers={expected_tuple}", info)
        self.assertIn(f"StringStruct('ProductVersion', '{APP_VERSION}')", info)

    def test_gui_settings_row_and_language_refresh_present(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn("self.lbl_s_version = ctk.CTkLabel(", source)
        self.assertIn("self.lbl_s_version_val = ctk.CTkLabel(", source)
        self.assertIn('text=f"v{APP_VERSION}"', source)
        self.assertIn('self.lbl_s_version.configure(text=t("setting_version"))', source)
        self.assertIn('description=f"FolderLock v{APP_VERSION}', source)


if __name__ == "__main__":
    unittest.main()
