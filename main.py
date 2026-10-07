"""
FolderLock - Professional, Secure Folder Locker for Windows
"""

import os
import sys
import threading
import subprocess
from typing import Optional, Dict, Any
from tkinter import filedialog, messagebox

import customtkinter as ctk

from crypto_engine import (
    lock_folder,
    unlock_folder,
    lock_folder_instant,
    unlock_folder_instant,
    relock_folder,
    get_relock_config,
    is_folder_locked,
    verify_file_password,
    get_folder_stats,
    format_bytes,
    InvalidPasswordError,
    CorruptedFileError,
    OperationCancelledError,
    VAULT_FILENAME,
    INSTANT_DATA_DIRNAME,
    UNLOCKER_FILENAME,
    UNLOCKER_TR_FILENAME,
    LOCKER_FILENAME,
    LOCKER_TR_FILENAME
)
from translations import t, set_current_lang, get_current_lang
from config_manager import ConfigManager
from ui_dialogs import ModernPasswordDialog, HelpDialog
from ui_icons import get_theme_image, get_eye_image
from shell_integration import setup_shell_integration


class InFolderUnlockApp(ctk.CTk):
    """
    Mini unlock modal launched when user runs Unlock.exe inside a locked folder
    OR when a locked folder is opened via context menu / CLI.
    """
    def __init__(self, folder_dir: str):
        super().__init__()
        self.folder_dir = os.path.abspath(folder_dir)
        self.folder_name = os.path.basename(self.folder_dir.rstrip("/\\"))
        self.is_busy = False

        self.config_mgr = ConfigManager()
        set_current_lang(self.config_mgr.language)

        ctk.set_appearance_mode(self.config_mgr.theme)
        ctk.set_default_color_theme("blue")

        self.title(f"{self.folder_name} - {t('in_folder_title')}")
        self.geometry("420x270")
        self.minsize(400, 250)
        self.resizable(False, False)

        self._set_icon()

        container = ctk.CTkFrame(self, corner_radius=10)
        container.pack(fill="both", expand=True, padx=16, pady=16)

        top_bar = ctk.CTkFrame(container, fg_color="transparent")
        top_bar.pack(fill="x", padx=12, pady=(6, 0))

        self.btn_lang = ctk.CTkButton(
            top_bar,
            text="TR" if self.config_mgr.language == "en" else "EN",
            width=38,
            height=24,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("gray85", "gray25"),
            hover_color=("gray75", "gray35"),
            text_color=("gray20", "gray80"),
            command=self._toggle_lang
        )
        self.btn_lang.pack(side="right")

        self.title_lbl = ctk.CTkLabel(
            container,
            text=self.folder_name,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.title_lbl.pack(pady=(4, 2))

        self.desc_lbl = ctk.CTkLabel(
            container,
            text=t("in_folder_desc"),
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray60")
        )
        self.desc_lbl.pack(pady=(0, 14))

        pwd_row = ctk.CTkFrame(container, fg_color="transparent")
        pwd_row.pack(fill="x", padx=16, pady=4)

        self.entry_pwd = ctk.CTkEntry(
            pwd_row,
            placeholder_text=t("unlock_password_placeholder"),
            show="*",
            height=36,
            font=ctk.CTkFont(size=13)
        )
        self.entry_pwd.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.entry_pwd.focus_set()
        self.entry_pwd.bind("<Return>", lambda e: self._do_unlock())

        self.show_pwd = False
        self.btn_eye = ctk.CTkButton(
            pwd_row,
            text="",
            image=get_eye_image(False),
            width=36,
            height=36,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            command=self._toggle_eye
        )
        self.btn_eye.pack(side="right")

        self.btn_unlock = ctk.CTkButton(
            container,
            text=t("in_folder_unlock_btn"),
            height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669",
            command=self._do_unlock
        )
        self.btn_unlock.pack(fill="x", padx=16, pady=(14, 8))

        self.lbl_status = ctk.CTkLabel(
            container,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60")
        )
        self.lbl_status.pack(pady=(0, 4))

    def _set_icon(self):
        base_dir = sys._MEIPASS if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS') else os.path.dirname(__file__)
        icon_path = os.path.join(base_dir, "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

    def _toggle_lang(self):
        new_lang = "tr" if self.config_mgr.language == "en" else "en"
        self.config_mgr.set_language(new_lang)
        set_current_lang(new_lang)
        self.btn_lang.configure(text="TR" if new_lang == "en" else "EN")
        self.title(f"{self.folder_name} - {t('in_folder_title')}")
        self.desc_lbl.configure(text=t("in_folder_desc"))
        self.entry_pwd.configure(placeholder_text=t("unlock_password_placeholder"))
        self.btn_unlock.configure(text=t("in_folder_unlock_btn"))

    def _toggle_eye(self):
        self.show_pwd = not self.show_pwd
        self.entry_pwd.configure(show="" if self.show_pwd else "*")
        self.btn_eye.configure(image=get_eye_image(self.show_pwd))

    def _do_unlock(self):
        if self.is_busy:
            return
        pwd = self.entry_pwd.get().strip()
        if not pwd:
            return

        self.is_busy = True
        self.btn_unlock.configure(state="disabled", text="...")
        self.lbl_status.configure(text=t("status_unlocking"))

        def worker():
            try:
                mode = is_folder_locked(self.folder_dir)
                if mode == "instant":
                    unlock_folder_instant(self.folder_dir, pwd)
                elif mode == "crypto":
                    unlock_folder(self.folder_dir, pwd)
                else:
                    v_item = self.config_mgr.find_vault_item(self.folder_dir)
                    if v_item and v_item.get("mode") == "instant":
                        unlock_folder_instant(self.folder_dir, pwd, v_item.get("salt"), v_item.get("hash"))
                    else:
                        unlock_folder(self.folder_dir, pwd)

                self.after(0, self._on_success)
            except InvalidPasswordError:
                self.after(0, lambda: self._on_fail(t("err_wrong_password")))
            except Exception as e:
                self.after(0, lambda: self._on_fail(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_success(self):
        self.withdraw()
        messagebox.showinfo(t("dialog_success"), t("in_folder_success"))
        # DO NOT open Explorer again! Folder is already open in user's window.

        # If running as the unlocker inside this folder, self-delete so Lock.exe remains
        exe_path = os.path.abspath(sys.argv[0])
        exe_parent = os.path.dirname(exe_path)
        if os.path.normpath(exe_parent).lower() == os.path.normpath(self.folder_dir).lower():
            if getattr(sys, 'frozen', False):
                cmd = f'cmd /c ping 127.0.0.1 -n 2 > nul & del /f /q "{exe_path}"'
                subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.destroy()

    def _on_fail(self, msg: str):
        self.is_busy = False
        self.btn_unlock.configure(state="normal", text=t("in_folder_unlock_btn"))
        self.lbl_status.configure(text="")
        messagebox.showerror(t("dialog_error"), msg)


class FolderLockApp(ctk.CTk):
    """
    Main FolderLock Desktop Application.
    Clean, elegant Windows 11 Fluent dark layout.
    """
    def __init__(self):
        super().__init__()

        self.config_mgr = ConfigManager()
        set_current_lang(self.config_mgr.language)

        ctk.set_appearance_mode(self.config_mgr.theme)
        ctk.set_default_color_theme("blue")

        self.title(f"{t('app_title')} - {t('app_subtitle')}")
        self.geometry("500x670")
        self.minsize(460, 620)

        self._set_icon()

        # State Variables
        self.selected_folder_to_lock: Optional[str] = None
        self.selected_folder_to_unlock: Optional[str] = None
        self.is_busy = False
        self.cancel_requested = False
        self.show_lock_password = False
        self.show_unlock_password = False

        self._build_ui()
        self.refresh_vault_list()
        self._check_cli_args()

    def _set_icon(self):
        base_dir = sys._MEIPASS if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS') else os.path.dirname(__file__)
        icon_path = os.path.join(base_dir, "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

    def _check_cli_args(self):
        if len(sys.argv) > 1:
            target = sys.argv[1]
            if os.path.isdir(target):
                if is_folder_locked(target):
                    self._set_folder_for_unlocking(os.path.abspath(target))
                    self.tabview.set("tab_unlock")
                else:
                    self._set_folder_for_locking(os.path.abspath(target))
                    self.tabview.set("tab_lock")

    def _build_ui(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # 1. TOP HEADER (54px)
        self.header_frame = ctk.CTkFrame(self, height=54, corner_radius=0, fg_color=("gray92", "gray14"))
        self.header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame.grid_columnconfigure(1, weight=1)

        # Title & Subtitle
        header_text_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        header_text_frame.grid(row=0, column=0, sticky="w", padx=16, pady=8)

        self.title_lbl = ctk.CTkLabel(
            header_text_frame,
            text="FolderLock",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.title_lbl.pack(anchor="w")

        self.subtitle_lbl = ctk.CTkLabel(
            header_text_frame,
            text=t("app_subtitle"),
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60")
        )
        self.subtitle_lbl.pack(anchor="w")

        # Help, Language, and Theme Controls
        ctrls = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        ctrls.grid(row=0, column=2, sticky="e", padx=16, pady=8)

        self.btn_help = ctk.CTkButton(
            ctrls,
            text="?",
            width=28,
            height=28,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=("gray80", "gray25"),
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray35"),
            command=self._show_help_dialog
        )
        self.btn_help.pack(side="left", padx=(0, 4))

        self.btn_lang = ctk.CTkButton(
            ctrls,
            text="TR" if get_current_lang() == "tr" else "EN",
            width=46,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("gray80", "gray25"),
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray35"),
            command=self._toggle_language
        )
        self.btn_lang.pack(side="left", padx=(0, 4))

        is_dark = self.config_mgr.theme == "dark"
        self.btn_theme = ctk.CTkButton(
            ctrls,
            text="",
            image=get_theme_image(is_dark),
            width=32,
            height=28,
            fg_color=("gray80", "gray25"),
            hover_color=("gray70", "gray35"),
            command=self._toggle_theme
        )
        self.btn_theme.pack(side="left")

        # 2. MAIN TABVIEW
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=16, pady=(4, 6))

        self.tab_lock = self.tabview.add("tab_lock")
        self.tab_unlock = self.tabview.add("tab_unlock")
        self.tab_vault = self.tabview.add("tab_vault")
        self.tab_settings = self.tabview.add("tab_settings")

        self.tabview._segmented_button._buttons_dict["tab_lock"].configure(text=t("tab_lock"))
        self.tabview._segmented_button._buttons_dict["tab_unlock"].configure(text=t("tab_unlock"))
        self.tabview._segmented_button._buttons_dict["tab_vault"].configure(text=t("tab_vault"))
        self.tabview._segmented_button._buttons_dict["tab_settings"].configure(text=t("tab_settings"))

        self._build_tab_lock()
        self._build_tab_unlock()
        self._build_tab_vault()
        self._build_tab_settings()

        # 3. BOTTOM PROGRESS / STATUS BAR
        self.bottom_frame = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color=("gray92", "gray14"))
        self.bottom_frame.grid(row=2, column=0, sticky="ew")
        self.bottom_frame.grid_columnconfigure(0, weight=1)

        self.status_lbl = ctk.CTkLabel(
            self.bottom_frame,
            text=t("status_ready"),
            font=ctk.CTkFont(size=11),
            text_color=("gray30", "gray70"),
            anchor="w"
        )
        self.status_lbl.grid(row=0, column=0, sticky="w", padx=16, pady=(4, 2))

        self.btn_cancel = ctk.CTkButton(
            self.bottom_frame,
            text=t("btn_cancel"),
            width=65,
            height=20,
            font=ctk.CTkFont(size=11),
            fg_color="#ef4444",
            hover_color="#dc2626",
            command=self._on_cancel_clicked
        )
        self.btn_cancel.grid(row=0, column=1, sticky="e", padx=16, pady=(4, 2))
        self.btn_cancel.grid_remove()

        self.progress_bar = ctk.CTkProgressBar(self.bottom_frame, height=4, corner_radius=2)
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 6))
        self.progress_bar.set(0)

    # ---------------- TAB 1: LOCK ----------------
    def _build_tab_lock(self):
        container = self.tab_lock
        container.grid_columnconfigure(0, weight=1)

        # Folder Selection Card
        card_folder = ctk.CTkFrame(container, corner_radius=8)
        card_folder.pack(fill="x", padx=4, pady=(4, 6))
        card_folder.grid_columnconfigure(0, weight=1)

        self.lbl_f_title = ctk.CTkLabel(card_folder, text=t("lock_title"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_f_title.grid(row=0, column=0, sticky="w", padx=12, pady=(8, 1))

        self.lbl_selected_folder = ctk.CTkLabel(
            card_folder,
            text=t("no_folder_selected"),
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
            anchor="w"
        )
        self.lbl_selected_folder.grid(row=1, column=0, sticky="w", padx=12, pady=1)

        self.lbl_folder_stats = ctk.CTkLabel(
            card_folder,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#0284c7",
            anchor="w"
        )
        self.lbl_folder_stats.grid(row=2, column=0, sticky="w", padx=12, pady=(1, 8))

        self.btn_browse_folder = ctk.CTkButton(
            card_folder,
            text=t("select_folder_btn"),
            width=105,
            height=28,
            font=ctk.CTkFont(size=11),
            command=self._choose_folder_to_lock
        )
        self.btn_browse_folder.grid(row=0, column=1, rowspan=3, padx=12, pady=8, sticky="e")

        # Mode Selection Card
        card_mode = ctk.CTkFrame(container, corner_radius=8)
        card_mode.pack(fill="x", padx=4, pady=(0, 6))

        self.lbl_m = ctk.CTkLabel(card_mode, text=t("lock_mode_label"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_m.pack(anchor="w", padx=12, pady=(6, 2))

        self.seg_lock_mode = ctk.CTkSegmentedButton(
            card_mode,
            values=[t("mode_instant"), t("mode_crypto")],
            height=26,
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_lock_mode_changed
        )
        self.seg_lock_mode.pack(fill="x", padx=12, pady=2)
        self.seg_lock_mode.set(t("mode_instant"))

        self.lbl_mode_desc = ctk.CTkLabel(
            card_mode,
            text=t("mode_instant_desc"),
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
            anchor="w"
        )
        self.lbl_mode_desc.pack(anchor="w", padx=12, pady=(2, 6))

        # Password Card
        card_pwd = ctk.CTkFrame(container, corner_radius=8)
        card_pwd.pack(fill="x", padx=4, pady=(0, 8))

        self.lbl_p = ctk.CTkLabel(card_pwd, text=t("enter_password"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_p.pack(anchor="w", padx=12, pady=(6, 2))

        pwd_row = ctk.CTkFrame(card_pwd, fg_color="transparent")
        pwd_row.pack(fill="x", padx=12, pady=2)

        self.entry_lock_pwd = ctk.CTkEntry(
            pwd_row,
            placeholder_text=t("password_placeholder"),
            show="*",
            height=32,
            font=ctk.CTkFont(size=12)
        )
        self.entry_lock_pwd.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.entry_lock_pwd.bind("<KeyRelease>", self._on_password_input_change)

        self.btn_eye_lock = ctk.CTkButton(
            pwd_row,
            text="",
            image=get_eye_image(False),
            width=32,
            height=32,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            command=self._toggle_eye_lock
        )
        self.btn_eye_lock.pack(side="right")

        # Strength Bar
        strength_row = ctk.CTkFrame(card_pwd, fg_color="transparent")
        strength_row.pack(fill="x", padx=12, pady=(2, 4))

        self.lbl_strength = ctk.CTkLabel(
            strength_row,
            text=f"{t('strength_label')} -",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60")
        )
        self.lbl_strength.pack(side="left")

        self.progress_strength = ctk.CTkProgressBar(strength_row, height=5, width=110)
        self.progress_strength.pack(side="right")
        self.progress_strength.set(0)

        # Confirm Password
        self.lbl_c = ctk.CTkLabel(card_pwd, text=t("confirm_password"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_c.pack(anchor="w", padx=12, pady=(2, 2))

        self.entry_lock_confirm = ctk.CTkEntry(
            card_pwd,
            placeholder_text=t("confirm_placeholder"),
            show="*",
            height=32,
            font=ctk.CTkFont(size=12)
        )
        self.entry_lock_confirm.pack(fill="x", padx=12, pady=(0, 8))

        # Big Lock Button - High Contrast, Full Visibility, Never Squeezed
        self.btn_do_lock = ctk.CTkButton(
            container,
            text=t("btn_lock_now"),
            height=42,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            corner_radius=8,
            command=self._start_locking
        )
        self.btn_do_lock.pack(fill="x", padx=4, pady=(4, 10))

    # ---------------- TAB 2: UNLOCK ----------------
    def _build_tab_unlock(self):
        container = self.tab_unlock
        container.grid_columnconfigure(0, weight=1)

        card_folder = ctk.CTkFrame(container, corner_radius=8)
        card_folder.pack(fill="x", padx=4, pady=(4, 6))
        card_folder.grid_columnconfigure(0, weight=1)

        self.lbl_u_title = ctk.CTkLabel(card_folder, text=t("unlock_title"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_u_title.grid(row=0, column=0, sticky="w", padx=12, pady=(8, 1))

        self.lbl_selected_file = ctk.CTkLabel(
            card_folder,
            text=t("no_file_selected"),
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
            anchor="w"
        )
        self.lbl_selected_file.grid(row=1, column=0, sticky="w", padx=12, pady=1)

        self.lbl_file_stats = ctk.CTkLabel(
            card_folder,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#10b981",
            anchor="w"
        )
        self.lbl_file_stats.grid(row=2, column=0, sticky="w", padx=12, pady=(1, 8))

        self.btn_browse_file = ctk.CTkButton(
            card_folder,
            text=t("select_folder_btn"),
            width=105,
            height=28,
            font=ctk.CTkFont(size=11),
            command=self._choose_folder_to_unlock
        )
        self.btn_browse_file.grid(row=0, column=1, rowspan=3, padx=12, pady=8, sticky="e")

        # Password Card
        card_pwd = ctk.CTkFrame(container, corner_radius=8)
        card_pwd.pack(fill="x", padx=4, pady=(0, 8))

        self.lbl_u_pwd = ctk.CTkLabel(card_pwd, text=t("enter_unlock_password"), font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_u_pwd.pack(anchor="w", padx=12, pady=(8, 2))

        pwd_row = ctk.CTkFrame(card_pwd, fg_color="transparent")
        pwd_row.pack(fill="x", padx=12, pady=(2, 10))

        self.entry_unlock_pwd = ctk.CTkEntry(
            pwd_row,
            placeholder_text=t("unlock_password_placeholder"),
            show="*",
            height=32,
            font=ctk.CTkFont(size=12)
        )
        self.entry_unlock_pwd.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.entry_unlock_pwd.bind("<Return>", lambda e: self._start_unlocking())

        self.btn_eye_unlock = ctk.CTkButton(
            pwd_row,
            text="",
            image=get_eye_image(False),
            width=32,
            height=32,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            command=self._toggle_eye_unlock
        )
        self.btn_eye_unlock.pack(side="right")

        self.btn_do_unlock = ctk.CTkButton(
            container,
            text=t("btn_unlock_now"),
            height=42,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669",
            corner_radius=8,
            command=self._start_unlocking
        )
        self.btn_do_unlock.pack(fill="x", padx=4, pady=(4, 10))

    # ---------------- TAB 3: VAULT ----------------
    def _build_tab_vault(self):
        container = self.tab_vault
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self.scroll_vault = ctk.CTkScrollableFrame(container, corner_radius=8)
        self.scroll_vault.grid(row=0, column=0, sticky="nsew", padx=2, pady=4)
        self.scroll_vault.grid_columnconfigure(0, weight=1)

    # ---------------- TAB 4: SETTINGS ----------------
    def _build_tab_settings(self):
        container = self.tab_settings

        card_opts = ctk.CTkFrame(container, corner_radius=8)
        card_opts.pack(fill="x", padx=4, pady=(6, 8))

        self.lbl_s_title = ctk.CTkLabel(card_opts, text=t("settings_title"), font=ctk.CTkFont(size=13, weight="bold"))
        self.lbl_s_title.pack(anchor="w", padx=12, pady=(10, 6))

        # Language row
        row_lang = ctk.CTkFrame(card_opts, fg_color="transparent")
        row_lang.pack(fill="x", padx=12, pady=4)

        self.lbl_s_lang = ctk.CTkLabel(row_lang, text=t("setting_lang"), font=ctk.CTkFont(size=12))
        self.lbl_s_lang.pack(side="left")

        self.seg_lang = ctk.CTkSegmentedButton(
            row_lang,
            values=["English", "Türkçe"],
            height=28,
            command=self._on_segmented_lang_change
        )
        self.seg_lang.set("English" if get_current_lang() == "en" else "Türkçe")
        self.seg_lang.pack(side="right")

        # Theme row
        row_theme = ctk.CTkFrame(card_opts, fg_color="transparent")
        row_theme.pack(fill="x", padx=12, pady=(4, 8))

        self.lbl_s_theme = ctk.CTkLabel(row_theme, text=t("setting_theme"), font=ctk.CTkFont(size=12))
        self.lbl_s_theme.pack(side="left")

        self.seg_theme = ctk.CTkSegmentedButton(
            row_theme,
            values=[t("theme_dark"), t("theme_light")],
            height=28,
            command=self._on_segmented_theme_change
        )
        self.seg_theme.set(t("theme_dark") if self.config_mgr.theme == "dark" else t("theme_light"))
        self.seg_theme.pack(side="right")

        # Guide / Help row
        row_help = ctk.CTkFrame(card_opts, fg_color="transparent")
        row_help.pack(fill="x", padx=12, pady=(4, 12))

        self.lbl_s_help = ctk.CTkLabel(row_help, text=t("help_btn_tooltip"), font=ctk.CTkFont(size=12))
        self.lbl_s_help.pack(side="left")

        self.btn_open_help = ctk.CTkButton(
            row_help,
            text=t("help_btn_tooltip"),
            height=28,
            width=110,
            command=self._show_help_dialog
        )
        self.btn_open_help.pack(side="right")

        # Security Info
        card_sec = ctk.CTkFrame(container, corner_radius=8)
        card_sec.pack(fill="both", expand=True, padx=4, pady=4)

        self.lbl_sec_t = ctk.CTkLabel(card_sec, text=t("security_note_title"), font=ctk.CTkFont(size=13, weight="bold"), text_color="#0284c7")
        self.lbl_sec_t.pack(anchor="w", padx=12, pady=(10, 4))

        self.lbl_sec_b = ctk.CTkLabel(
            card_sec,
            text=t("security_note_text"),
            font=ctk.CTkFont(size=11),
            justify="left",
            anchor="w"
        )
        self.lbl_sec_b.pack(anchor="w", padx=12, pady=(0, 10))

    # ---------------- HANDLERS ----------------
    def _toggle_language(self):
        new_lang = "tr" if get_current_lang() == "en" else "en"
        self._apply_language(new_lang)

    def _on_segmented_lang_change(self, val: str):
        new_lang = "en" if val == "English" else "tr"
        self._apply_language(new_lang)

    def _apply_language(self, new_lang: str):
        set_current_lang(new_lang)
        self.config_mgr.language = new_lang
        self.btn_lang.configure(text="TR" if new_lang == "tr" else "EN")
        self.seg_lang.set("English" if new_lang == "en" else "Türkçe")
        self._refresh_all_texts()

    def _toggle_theme(self):
        new_theme = "light" if self.config_mgr.theme == "dark" else "dark"
        self._apply_theme(new_theme)

    def _on_segmented_theme_change(self, val: str):
        new_theme = "dark" if val == t("theme_dark") else "light"
        self._apply_theme(new_theme)

    def _apply_theme(self, new_theme: str):
        self.config_mgr.theme = new_theme
        ctk.set_appearance_mode(new_theme)
        is_dark = new_theme == "dark"
        self.btn_theme.configure(image=get_theme_image(is_dark), text="")
        self.seg_theme.set(t("theme_dark") if is_dark else t("theme_light"))
        if hasattr(self, 'btn_eye_lock'):
            self.btn_eye_lock.configure(image=get_eye_image(self.show_lock_password))
        if hasattr(self, 'btn_eye_unlock'):
            self.btn_eye_unlock.configure(image=get_eye_image(self.show_unlock_password))

    def _show_help_dialog(self):
        HelpDialog(self)

    def _refresh_all_texts(self):
        self.title(f"{t('app_title')} - {t('app_subtitle')}")
        self.subtitle_lbl.configure(text=t("app_subtitle"))
        self.status_lbl.configure(text=t("status_ready"))
        self.btn_cancel.configure(text=t("btn_cancel"))

        # Invariant tab button texts
        self.tabview._segmented_button._buttons_dict["tab_lock"].configure(text=t("tab_lock"))
        self.tabview._segmented_button._buttons_dict["tab_unlock"].configure(text=t("tab_unlock"))
        self.tabview._segmented_button._buttons_dict["tab_vault"].configure(text=t("tab_vault"))
        self.tabview._segmented_button._buttons_dict["tab_settings"].configure(text=t("tab_settings"))

        # Lock Tab
        self.lbl_f_title.configure(text=t("lock_title"))
        if not self.selected_folder_to_lock:
            self.lbl_selected_folder.configure(text=t("no_folder_selected"))
        self.btn_browse_folder.configure(text=t("select_folder_btn"))
        self.lbl_m.configure(text=t("lock_mode_label"))
        cur_mode = self.seg_lock_mode.get()
        self.seg_lock_mode.configure(values=[t("mode_instant"), t("mode_crypto")])
        if cur_mode in ["Instant Lock (SSD Safe)", "Hızlı Kilit (SSD Dostu)"]:
            self.seg_lock_mode.set(t("mode_instant"))
            self.lbl_mode_desc.configure(text=t("mode_instant_desc"))
        else:
            self.seg_lock_mode.set(t("mode_crypto"))
            self.lbl_mode_desc.configure(text=t("mode_crypto_desc"))

        self.lbl_p.configure(text=t("enter_password"))
        self.entry_lock_pwd.configure(placeholder_text=t("password_placeholder"))
        self._on_password_input_change()
        self.lbl_c.configure(text=t("confirm_password"))
        self.entry_lock_confirm.configure(placeholder_text=t("confirm_placeholder"))
        self.btn_do_lock.configure(text=t("btn_lock_now"))

        # Unlock Tab
        self.lbl_u_title.configure(text=t("unlock_title"))
        if not self.selected_folder_to_unlock:
            self.lbl_selected_file.configure(text=t("no_file_selected"))
        self.btn_browse_file.configure(text=t("select_folder_btn"))
        self.lbl_u_pwd.configure(text=t("enter_unlock_password"))
        self.entry_unlock_pwd.configure(placeholder_text=t("unlock_password_placeholder"))
        self.btn_do_unlock.configure(text=t("btn_unlock_now"))

        # Settings Tab
        self.lbl_s_title.configure(text=t("settings_title"))
        self.lbl_s_lang.configure(text=t("setting_lang"))
        self.lbl_s_theme.configure(text=t("setting_theme"))
        self.seg_theme.configure(values=[t("theme_dark"), t("theme_light")])
        self.seg_theme.set(t("theme_dark") if self.config_mgr.theme == "dark" else t("theme_light"))
        if hasattr(self, 'lbl_s_help'):
            self.lbl_s_help.configure(text=t("help_btn_tooltip"))
        if hasattr(self, 'btn_open_help'):
            self.btn_open_help.configure(text=t("help_btn_tooltip"))
        self.lbl_sec_t.configure(text=t("security_note_title"))
        self.lbl_sec_b.configure(text=t("security_note_text"))

        self.refresh_vault_list()

    def _toggle_eye_lock(self):
        self.show_lock_password = not self.show_lock_password
        self.entry_lock_pwd.configure(show="" if self.show_lock_password else "*")
        self.entry_lock_confirm.configure(show="" if self.show_lock_password else "*")
        self.btn_eye_lock.configure(image=get_eye_image(self.show_lock_password))

    def _toggle_eye_unlock(self):
        self.show_unlock_password = not self.show_unlock_password
        self.entry_unlock_pwd.configure(show="" if self.show_unlock_password else "*")
        self.btn_eye_unlock.configure(image=get_eye_image(self.show_unlock_password))

    def _on_password_input_change(self, event=None):
        pwd = self.entry_lock_pwd.get()
        if not pwd:
            self.progress_strength.set(0)
            self.lbl_strength.configure(text=f"{t('strength_label')} -", text_color=("gray40", "gray60"))
            return

        score = 0
        if len(pwd) >= 6:
            score += 0.25
        if len(pwd) >= 10:
            score += 0.25
        if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd):
            score += 0.25
        if any(c.isdigit() for c in pwd) or any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd):
            score += 0.25

        self.progress_strength.set(score)
        if score < 0.5:
            self.lbl_strength.configure(text=f"{t('strength_label')} {t('strength_weak')}", text_color="#ef4444")
            self.progress_strength.configure(progress_color="#ef4444")
        elif score < 0.8:
            self.lbl_strength.configure(text=f"{t('strength_label')} {t('strength_medium')}", text_color="#f59e0b")
            self.progress_strength.configure(progress_color="#f59e0b")
        else:
            self.lbl_strength.configure(text=f"{t('strength_label')} {t('strength_strong')}", text_color="#10b981")
            self.progress_strength.configure(progress_color="#10b981")

    # ---------------- SELECTION ----------------
    def _choose_folder_to_lock(self):
        if self.is_busy:
            return
        folder = filedialog.askdirectory(title=t("lock_title"))
        if folder:
            self._set_folder_for_locking(folder)

    def _set_folder_for_locking(self, folder: str):
        self.selected_folder_to_lock = folder
        fname = os.path.basename(folder.rstrip("/\\"))
        self.lbl_selected_folder.configure(text=f"{fname} ({folder})")
        self.lbl_folder_stats.configure(text=t("status_calculating"))

        def calc():
            files, sz = get_folder_stats(folder)
            self.after(0, lambda: self.lbl_folder_stats.configure(
                text=t("folder_info_fmt", files=files, size=format_bytes(sz))
            ))
        threading.Thread(target=calc, daemon=True).start()

    def _choose_folder_to_unlock(self):
        if self.is_busy:
            return
        folder = filedialog.askdirectory(title=t("unlock_title"))
        if folder:
            self._set_folder_for_unlocking(folder)

    def _set_folder_for_unlocking(self, folder: str):
        self.selected_folder_to_unlock = folder
        fname = os.path.basename(folder.rstrip("/\\"))
        self.lbl_selected_file.configure(text=f"{fname} ({folder})")
        vault_p = os.path.join(folder, VAULT_FILENAME)
        if os.path.isfile(vault_p):
            sz = os.path.getsize(vault_p)
            self.lbl_file_stats.configure(text=t("file_info_fmt", size=format_bytes(sz)))
        else:
            self.lbl_file_stats.configure(text=folder)

    # ---------------- VAULT ----------------
    def refresh_vault_list(self):
        for w in self.scroll_vault.winfo_children():
            w.destroy()

        vault_items = self.config_mgr.get_vault()
        if not vault_items:
            empty_lbl = ctk.CTkLabel(
                self.scroll_vault,
                text=t("vault_empty"),
                font=ctk.CTkFont(size=12),
                text_color=("gray40", "gray60")
            )
            empty_lbl.pack(pady=30)
            return

        for item in vault_items:
            name = item.get("name", "Unknown")
            path = item.get("locked_path", "")
            sz = item.get("size", 0)
            exists = os.path.exists(path)

            card = ctk.CTkFrame(self.scroll_vault, corner_radius=6, fg_color=("gray85", "gray18"))
            card.pack(fill="x", pady=3, padx=2)
            card.grid_columnconfigure(0, weight=1)

            lock_state = is_folder_locked(path) if exists else None

            if not exists:
                badge_text = t("file_missing")
            elif lock_state:
                mode_str = "Instant" if lock_state == "instant" else "AES-256"
                badge_text = f"{t('vault_status_locked')} • {mode_str}"
            else:
                badge_text = t("vault_status_unlocked")

            t_text = f"{name}  [{badge_text}]"
            title_lbl = ctk.CTkLabel(card, text=t_text, font=ctk.CTkFont(size=12, weight="bold"), anchor="w")
            title_lbl.grid(row=0, column=0, sticky="w", padx=10, pady=(6, 0))

            size_str = format_bytes(sz) if (exists and lock_state != "instant" and sz > 0) else "Instant"
            detail_lbl = ctk.CTkLabel(
                card,
                text=f"{size_str} • {path}",
                font=ctk.CTkFont(size=10),
                text_color=("gray40", "gray60"),
                anchor="w"
            )
            detail_lbl.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 6))

            btn_box = ctk.CTkFrame(card, fg_color="transparent")
            btn_box.grid(row=0, column=1, rowspan=2, padx=8, pady=6, sticky="e")

            if exists:
                if lock_state:
                    # Folder is currently LOCKED -> Show green UNLOCK button!
                    btn_act = ctk.CTkButton(
                        btn_box,
                        text=t("btn_quick_unlock"),
                        width=65,
                        height=26,
                        font=ctk.CTkFont(size=11, weight="bold"),
                        fg_color="#10b981",
                        hover_color="#059669",
                        command=lambda p=path, n=name: self._on_quick_unlock(p, n)
                    )
                    btn_act.pack(side="left", padx=2)
                else:
                    # Folder is currently UNLOCKED -> Show blue LOCK button!
                    btn_act = ctk.CTkButton(
                        btn_box,
                        text=t("btn_quick_lock"),
                        width=65,
                        height=26,
                        font=ctk.CTkFont(size=11, weight="bold"),
                        fg_color="#2563eb",
                        hover_color="#1d4ed8",
                        command=lambda p=path, n=name, it=item: self._on_quick_relock(p, n, it)
                    )
                    btn_act.pack(side="left", padx=2)

                btn_exp = ctk.CTkButton(
                    btn_box,
                    text=t("btn_show_explorer"),
                    width=45,
                    height=26,
                    font=ctk.CTkFont(size=11),
                    fg_color=("gray75", "gray30"),
                    hover_color=("gray65", "gray40"),
                    command=lambda p=path: self._open_explorer(p)
                )
                btn_exp.pack(side="left", padx=2)

            btn_d = ctk.CTkButton(
                btn_box,
                text="✕",
                width=26,
                height=26,
                fg_color=("gray75", "gray30"),
                hover_color="#ef4444",
                command=lambda p=path: self._remove_from_vault(p)
            )
            btn_d.pack(side="left", padx=2)

    def _open_explorer(self, p: str):
        if os.path.exists(p):
            try:
                subprocess.run(["explorer", os.path.normpath(p)], check=False)
            except Exception as e:
                messagebox.showerror(t("dialog_error"), str(e))

    def _remove_from_vault(self, p: str):
        if messagebox.askyesno(t("dialog_confirm"), t("confirm_remove_vault")):
            self.config_mgr.remove_vault_item(p)
            self.refresh_vault_list()

    def _on_quick_unlock(self, path: str, name: str):
        if self.is_busy:
            return
        dialog = ModernPasswordDialog(self, t("quick_unlock_dialog_title"), t("quick_unlock_prompt", name=name))
        password = dialog.get_input()
        if password:
            self._execute_unlock(path, password)

    def _on_quick_relock(self, path: str, name: str, item: Dict[str, Any]):
        if self.is_busy:
            return
        if not os.path.exists(path):
            messagebox.showerror(t("dialog_error"), t("err_no_folder"))
            return

        # 1. Fast re-lock via .flock_relock if present
        cfg = get_relock_config(path)
        if cfg:
            try:
                relock_folder(path)
                self.refresh_vault_list()
                messagebox.showinfo(t("dialog_success"), f"'{name}' {t('status_success_lock')}")
                return
            except Exception as e:
                messagebox.showerror(t("dialog_error"), str(e))
                return

        # 2. Re-lock via saved vault salt/hash (fast, without rewriting protected file contents)
        salt = item.get("salt")
        pwd_hash = item.get("hash")
        mode = item.get("mode", "instant")
        if mode == "instant" and salt and pwd_hash:
            try:
                lock_folder_instant(path, salt_hex=salt, hash_val=pwd_hash)
                self.refresh_vault_list()
                messagebox.showinfo(t("dialog_success"), f"'{name}' {t('status_success_lock')}")
                return
            except Exception as e:
                messagebox.showerror(t("dialog_error"), str(e))
                return

        # 3. Prompt user for password if no saved credentials exist
        dialog = ModernPasswordDialog(self, t("quick_lock_dialog_title"), t("quick_lock_prompt", name=name), btn_text=t("btn_quick_lock"))
        pwd = dialog.get_input()
        if not pwd:
            return
        if len(pwd) < 4:
            messagebox.showwarning(t("dialog_warning"), t("err_password_short"))
            return

        try:
            salt_h, hash_h = lock_folder_instant(path, password=pwd)
            self.config_mgr.add_vault_item(name, path, path, 0, mode="instant", salt=salt_h, hash_val=hash_h)
            self.refresh_vault_list()
            messagebox.showinfo(t("dialog_success"), f"'{name}' {t('status_success_lock')}")
        except Exception as e:
            messagebox.showerror(t("dialog_error"), str(e))

    def _on_lock_mode_changed(self, val: str):
        if val == t("mode_instant"):
            self.lbl_mode_desc.configure(text=t("mode_instant_desc"))
        else:
            self.lbl_mode_desc.configure(text=t("mode_crypto_desc"))

    # ---------------- LOCK OPERATION ----------------
    def _start_locking(self):
        if self.is_busy:
            return

        if not self.selected_folder_to_lock or not os.path.isdir(self.selected_folder_to_lock):
            messagebox.showerror(t("dialog_error"), t("err_no_folder"))
            return

        pwd = self.entry_lock_pwd.get()
        confirm_pwd = self.entry_lock_confirm.get()

        if not pwd:
            messagebox.showerror(t("dialog_error"), t("err_empty_password"))
            return

        if len(pwd) < 4:
            messagebox.showwarning(t("dialog_warning"), t("err_password_short"))
            return

        if pwd != confirm_pwd:
            messagebox.showerror(t("dialog_error"), t("err_password_mismatch"))
            return

        folder_name = os.path.basename(self.selected_folder_to_lock.rstrip("/\\"))
        is_instant = self.seg_lock_mode.get() == t("mode_instant")

        confirm_msg = t("confirm_lock_msg_instant", name=folder_name) if is_instant else t("confirm_lock_msg_crypto", name=folder_name)
        if not messagebox.askyesno(t("dialog_confirm"), confirm_msg):
            return

        target_folder = self.selected_folder_to_lock
        self._set_busy(True)

        def worker():
            try:
                def prog(pct, msg):
                    self.after(0, lambda: self._update_progress(pct, msg))

                def cancel_chk():
                    return self.cancel_requested

                if is_instant:
                    prog(0.5, t("status_locking"))
                    salt, hash_val = lock_folder_instant(target_folder, pwd, prog)
                    self.config_mgr.add_vault_item(
                        name=folder_name,
                        locked_path=target_folder,
                        original_path=target_folder,
                        size_bytes=0,
                        mode="instant",
                        salt=salt,
                        hash_val=hash_val
                    )
                    prog(1.0, t("status_success_lock"))
                    locked_path = target_folder
                else:
                    locked_path = lock_folder(
                        folder_path=target_folder,
                        password=pwd,
                        progress_callback=prog,
                        cancel_check=cancel_chk
                    )
                    vault_file = os.path.join(locked_path, VAULT_FILENAME)
                    sz = os.path.getsize(vault_file) if os.path.isfile(vault_file) else 0
                    self.config_mgr.add_vault_item(
                        name=folder_name,
                        locked_path=locked_path,
                        original_path=locked_path,
                        size_bytes=sz,
                        mode="aes256"
                    )

                self.after(0, lambda: self._on_lock_finished_success(locked_path))

            except OperationCancelledError:
                self.after(0, self._on_cancelled)
            except Exception as e:
                self.after(0, lambda: self._on_operation_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_lock_finished_success(self, locked_path: str):
        self._set_busy(False)
        self.entry_lock_pwd.delete(0, "end")
        self.entry_lock_confirm.delete(0, "end")
        self.selected_folder_to_lock = None
        self.lbl_selected_folder.configure(text=t("no_folder_selected"))
        self.lbl_folder_stats.configure(text="")
        self.progress_strength.set(0)
        self.lbl_strength.configure(text=f"{t('strength_label')} -", text_color=("gray40", "gray60"))

        self.refresh_vault_list()
        fname = os.path.basename(locked_path.rstrip("/\\"))
        messagebox.showinfo(
            t("dialog_success"),
            f"'{fname}' {t('status_success_lock')}"
        )

    # ---------------- UNLOCK OPERATION ----------------
    def _start_unlocking(self):
        if self.is_busy:
            return

        if not self.selected_folder_to_unlock:
            messagebox.showerror(t("dialog_error"), t("err_no_file"))
            return

        pwd = self.entry_unlock_pwd.get()
        if not pwd:
            messagebox.showerror(t("dialog_error"), t("err_empty_password"))
            return

        self._execute_unlock(self.selected_folder_to_unlock, pwd)

    def _execute_unlock(self, path: str, password: str):
        self._set_busy(True)
        vault_item = self.config_mgr.find_vault_item(path)
        mode = is_folder_locked(path)
        is_instant = (mode == "instant") or (vault_item and vault_item.get("mode") == "instant")

        def worker():
            try:
                def prog(pct, msg):
                    self.after(0, lambda: self._update_progress(pct, msg))

                def cancel_chk():
                    return self.cancel_requested

                if is_instant:
                    prog(0.5, t("status_unlocking"))
                    salt = vault_item.get("salt", "") if vault_item else None
                    expected_hash = vault_item.get("hash", "") if vault_item else None
                    unlock_folder_instant(path, password, salt, expected_hash)
                    unlocked_path = path
                    prog(1.0, t("status_success_unlock"))
                else:
                    unlocked_path = unlock_folder(
                        folder_path=path,
                        password=password,
                        progress_callback=prog,
                        cancel_check=cancel_chk
                    )

                self.after(0, lambda: self._on_unlock_finished_success(unlocked_path))

            except InvalidPasswordError:
                self.after(0, self._on_invalid_password)
            except CorruptedFileError:
                self.after(0, self._on_corrupted_file)
            except OperationCancelledError:
                self.after(0, self._on_cancelled)
            except Exception as e:
                self.after(0, lambda: self._on_operation_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_unlock_finished_success(self, unlocked_dir: str):
        self._set_busy(False)
        self.entry_unlock_pwd.delete(0, "end")
        self.selected_folder_to_unlock = None
        self.lbl_selected_file.configure(text=t("no_file_selected"))
        self.lbl_file_stats.configure(text="")

        self.refresh_vault_list()
        fname = os.path.basename(unlocked_dir.rstrip("/\\"))
        messagebox.showinfo(t("dialog_success"), f"'{fname}' {t('status_success_unlock')}")

    def _on_invalid_password(self):
        self._set_busy(False)
        messagebox.showerror(t("dialog_error"), t("err_wrong_password"))

    def _on_corrupted_file(self):
        self._set_busy(False)
        messagebox.showerror(t("dialog_error"), t("err_corrupted"))

    def _on_cancelled(self):
        self._set_busy(False)
        messagebox.showinfo(t("dialog_warning"), t("cancelled_msg"))

    def _on_operation_error(self, err: str):
        self._set_busy(False)
        messagebox.showerror(t("dialog_error"), err)

    # ---------------- STATUS & PROGRESS ----------------
    def _set_busy(self, busy: bool):
        self.is_busy = busy
        self.cancel_requested = False

        if busy:
            self.btn_cancel.grid()
            self.btn_do_lock.configure(state="disabled")
            self.btn_do_unlock.configure(state="disabled")
            self.btn_browse_folder.configure(state="disabled")
            self.btn_browse_file.configure(state="disabled")
        else:
            self.btn_cancel.grid_remove()
            self.progress_bar.set(0)
            self.status_lbl.configure(text=t("status_ready"))
            self.btn_do_lock.configure(state="normal")
            self.btn_do_unlock.configure(state="normal")
            self.btn_browse_folder.configure(state="normal")
            self.btn_browse_file.configure(state="normal")

    def _update_progress(self, pct: float, msg: str):
        self.progress_bar.set(pct)
        self.status_lbl.configure(text=f"{int(pct * 100)}% - {msg}")

    def _on_cancel_clicked(self):
        self.cancel_requested = True
        self.status_lbl.configure(text=t("cancelled_msg"))


def _show_quick_dialog(title: str, msg: str, is_error: bool = False):
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if is_error:
            messagebox.showerror(title, msg, parent=root)
        else:
            messagebox.showinfo(title, msg, parent=root)
        root.destroy()
    except Exception:
        if is_error:
            messagebox.showerror(title, msg)
        else:
            messagebox.showinfo(title, msg)


def main():
    try:
        cfg = ConfigManager()
        set_current_lang(cfg.language)
    except Exception:
        pass

    try:
        setup_shell_integration()
    except Exception:
        pass

    exe_name = os.path.basename(sys.argv[0]).lower()
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

    # 1. Fast Re-Lock: If user clicked Lock.exe / Kilitle.exe or inside unlocked folder with saved config
    if exe_name in ["lock.exe", "kilitle.exe"] or (len(sys.argv) == 1 and get_relock_config(exe_dir) and not is_folder_locked(exe_dir)):
        try:
            relock_folder(exe_dir)
            if getattr(sys, 'frozen', False):
                cmd = f'cmd /c ping 127.0.0.1 -n 2 > nul & del /f /q "{os.path.abspath(sys.argv[0])}"'
                subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            _show_quick_dialog(t("dialog_success"), t("status_success_lock"))
            return
        except InvalidPasswordError:
            dialog = ModernPasswordDialog(None, t("quick_lock_dialog_title"), t("quick_lock_prompt", name=os.path.basename(exe_dir)), btn_text=t("btn_quick_lock"))
            pwd = dialog.get_input()
            if pwd and len(pwd) >= 4:
                try:
                    lock_folder(exe_dir, password=pwd)
                    if getattr(sys, 'frozen', False):
                        cmd = f'cmd /c ping 127.0.0.1 -n 2 > nul & del /f /q "{os.path.abspath(sys.argv[0])}"'
                        subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                    _show_quick_dialog(t("dialog_success"), t("status_success_lock"))
                    return
                except Exception as e:
                    _show_quick_dialog(t("dialog_error"), str(e), is_error=True)
                    return
            return
        except Exception as e:
            _show_quick_dialog(t("dialog_error"), str(e), is_error=True)
            return

    # 2. CLI target check (Explorer context menu, drag & drop, file association)
    if len(sys.argv) > 1:
        target = os.path.abspath(sys.argv[1])
        if os.path.isdir(target):
            if is_folder_locked(target):
                app = InFolderUnlockApp(target)
                app.mainloop()
                return
            elif get_relock_config(target):
                try:
                    relock_folder(target)
                    _show_quick_dialog(t("dialog_success"), t("status_success_lock"))
                except Exception as e:
                    _show_quick_dialog(t("dialog_error"), str(e), is_error=True)
                return
            else:
                app = FolderLockApp()
                app._set_folder_for_locking(target)
                app.tabview.set("tab_lock")
                app.mainloop()
                return
        elif os.path.isfile(target):
            parent_dir = os.path.dirname(target)
            if is_folder_locked(parent_dir):
                app = InFolderUnlockApp(parent_dir)
                app.mainloop()
                return

    # 3. Running as Unlock.exe / Kilidi Ac.exe inside a locked folder
    if is_folder_locked(exe_dir) or exe_name in ["unlock.exe", "kilidi ac.exe"]:
        app = InFolderUnlockApp(exe_dir)
        app.mainloop()
        return

    # 4. Default app launch
    app = FolderLockApp()
    app.mainloop()


if __name__ == "__main__":
    main()
