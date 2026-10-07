"""
FolderLock - Configuration and Vault Registry Manager
Handles persistent settings (language, theme) and tracks locked folders.
Defaults to English ('en') unless explicitly changed by the user.
Follows Windows system theme on first launch, then preserves user preference.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

APP_DIR_NAME = "FolderLock"


def get_config_dir() -> str:
    """Returns the persistent configuration directory in AppData or home."""
    appdata = os.environ.get("APPDATA")
    if appdata and os.path.exists(appdata):
        config_dir = os.path.join(appdata, APP_DIR_NAME)
    else:
        config_dir = os.path.join(os.path.expanduser("~"), f".{APP_DIR_NAME.lower()}")
    os.makedirs(config_dir, exist_ok=True)
    return config_dir


def get_config_path() -> str:
    return os.path.join(get_config_dir(), "settings.json")


def detect_windows_theme() -> str:
    """Detects Windows system appearance mode (light or dark)."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        )
        val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return "light" if val == 1 else "dark"
    except Exception:
        pass

    try:
        import darkdetect
        sys_theme = darkdetect.theme()
        if sys_theme and sys_theme.lower() in ["light", "dark"]:
            return sys_theme.lower()
    except Exception:
        pass

    return "dark"


DEFAULT_CONFIG: Dict[str, Any] = {
    "language": "en",  # Strict default is English
    "user_selected_language": False,
    "theme": "dark",
    "user_selected_theme": False,
    "vault": []
}


class ConfigManager:
    def __init__(self):
        self.config_path = get_config_path()
        self.config = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(data)
                    # If user never explicitly clicked to choose a language, enforce English default
                    if not merged.get("user_selected_language", False):
                        merged["language"] = "en"
                    # If user never explicitly toggled theme, follow Windows theme
                    if not merged.get("user_selected_theme", False):
                        merged["theme"] = detect_windows_theme()
                    return merged
            except Exception:
                pass
        cfg = DEFAULT_CONFIG.copy()
        cfg["theme"] = detect_windows_theme()
        return cfg

    def save(self):
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")

    @property
    def language(self) -> str:
        if not self.config.get("user_selected_language", False):
            return "en"
        return self.config.get("language", "en")

    @language.setter
    def language(self, val: str):
        self.config["language"] = val
        self.config["user_selected_language"] = True
        self.save()

    @property
    def theme(self) -> str:
        if not self.config.get("user_selected_theme", False):
            return detect_windows_theme()
        return self.config.get("theme", "dark")

    @theme.setter
    def theme(self, val: str):
        self.config["theme"] = val
        self.config["user_selected_theme"] = True
        self.save()

    def set_language(self, val: str):
        self.language = val

    def set_theme(self, val: str):
        self.theme = val

    def get_vault(self) -> List[Dict[str, Any]]:
        return self.config.get("vault", [])

    def find_vault_item(self, path: str) -> Optional[Dict[str, Any]]:
        norm_path = os.path.normpath(path).lower()
        for item in self.get_vault():
            stored_p = os.path.normpath(item.get("locked_path", "")).lower()
            if stored_p == norm_path:
                return item
            if stored_p == norm_path + ".locked" or stored_p + ".locked" == norm_path:
                return item
        return None

    def add_vault_item(self, name: str, locked_path: str, original_path: str, size_bytes: int,
                       mode: str = "instant", salt: str = "", hash_val: str = ""):
        locked_path = os.path.abspath(locked_path)
        vault = self.config.get("vault", [])
        norm = os.path.normpath(locked_path).lower()
        vault = [item for item in vault if os.path.normpath(item.get("locked_path", "")).lower() != norm]

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        new_entry = {
            "name": name,
            "locked_path": locked_path,
            "original_path": os.path.abspath(original_path),
            "date": now_str,
            "size": size_bytes,
            "mode": mode,
            "salt": salt,
            "hash": hash_val
        }
        vault.insert(0, new_entry)
        self.config["vault"] = vault
        self.save()

    def remove_vault_item(self, locked_path: str):
        norm = os.path.normpath(locked_path).lower()
        vault = self.config.get("vault", [])
        self.config["vault"] = [item for item in vault if os.path.normpath(item.get("locked_path", "")).lower() != norm]
        self.save()
