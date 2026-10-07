"""
Modern CTk Dialogs and Popups for FolderLock
Includes ModernPasswordDialog and interactive HelpDialog.
"""

import customtkinter as ctk
from typing import Optional, Callable
from translations import t
from ui_icons import get_eye_image


class ModernPasswordDialog(ctk.CTkToplevel):
    """
    Modern modal dialog to enter a password for quick unlock or quick lock.
    """
    def __init__(self, parent, title: str, prompt: str, btn_text: Optional[str] = None):
        super().__init__(parent)
        self.title(title)
        self.geometry("420x220")
        self.result: Optional[str] = None
        self.show_password = False

        if parent is not None:
            self.transient(parent)
            self.grab_set()
            try:
                parent.update_idletasks()
                px = parent.winfo_x() + (parent.winfo_width() // 2) - 210
                py = parent.winfo_y() + (parent.winfo_height() // 2) - 110
                self.geometry(f"420x220+{max(0, px)}+{max(0, py)}")
            except Exception:
                pass
        else:
            self.attributes("-topmost", True)
            try:
                sw = self.winfo_screenwidth()
                sh = self.winfo_screenheight()
                self.geometry(f"420x220+{(sw - 420) // 2}+{(sh - 220) // 2}")
            except Exception:
                pass

        self.container = ctk.CTkFrame(self, corner_radius=12)
        self.container.pack(fill="both", expand=True, padx=16, pady=16)

        self.label_prompt = ctk.CTkLabel(
            self.container,
            text=prompt,
            font=ctk.CTkFont(size=13, weight="bold"),
            wraplength=380
        )
        self.label_prompt.pack(pady=(12, 10), padx=16)

        # Entry row with vector eye icon
        self.entry_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.entry_frame.pack(fill="x", padx=16, pady=4)

        self.entry = ctk.CTkEntry(
            self.entry_frame,
            placeholder_text=t("unlock_password_placeholder"),
            show="*",
            height=36,
            font=ctk.CTkFont(size=13)
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self._on_ok())

        self.btn_eye = ctk.CTkButton(
            self.entry_frame,
            text="",
            image=get_eye_image(False),
            width=36,
            height=36,
            fg_color=("gray75", "gray30"),
            hover_color=("gray65", "gray40"),
            command=self._toggle_eye
        )
        self.btn_eye.pack(side="right")

        # Buttons row
        self.btn_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.btn_frame.pack(fill="x", padx=16, pady=(14, 8))

        self.btn_cancel = ctk.CTkButton(
            self.btn_frame,
            text=t("btn_cancel"),
            fg_color=("gray70", "gray35"),
            hover_color=("gray60", "gray45"),
            width=110,
            height=34,
            command=self._on_cancel
        )
        self.btn_cancel.pack(side="left")

        ok_text = btn_text or t("btn_quick_unlock")
        self.btn_ok = ctk.CTkButton(
            self.btn_frame,
            text=ok_text,
            width=130,
            height=34,
            command=self._on_ok
        )
        self.btn_ok.pack(side="right")

    def _toggle_eye(self):
        self.show_password = not self.show_password
        self.entry.configure(show="" if self.show_password else "*")
        self.btn_eye.configure(image=get_eye_image(self.show_password))

    def _on_ok(self):
        val = self.entry.get().strip()
        if val:
            self.result = val
            self.grab_release()
            self.destroy()

    def _on_cancel(self):
        self.result = None
        self.grab_release()
        self.destroy()

    def get_input(self) -> Optional[str]:
        self.wait_window()
        return self.result


class HelpDialog(ctk.CTkToplevel):
    """
    Modern scrollable Help / User Guide dialog.
    Presents clear, simple instructions in the active language.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title(t("help_modal_title"))
        self.geometry("470x560")
        self.minsize(440, 480)
        self.transient(parent)
        self.grab_set()

        # Center on parent
        parent.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() // 2) - 235
        py = parent.winfo_y() + (parent.winfo_height() // 2) - 280
        self.geometry(f"470x560+{max(0, px)}+{max(0, py)}")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(self, corner_radius=12)
        scroll.grid(row=0, column=0, sticky="nsew", padx=16, pady=(16, 8))
        scroll.grid_columnconfigure(0, weight=1)

        # Header Title
        lbl_head = ctk.CTkLabel(
            scroll,
            text=t("help_modal_title"),
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#2563eb"
        )
        lbl_head.pack(anchor="w", padx=8, pady=(4, 12))

        # Section 1: How to Lock
        self._add_help_card(
            scroll,
            title=t("help_sec1_title"),
            body=t("help_sec1_body"),
            accent="#2563eb"
        )

        # Section 2: How to Unlock
        self._add_help_card(
            scroll,
            title=t("help_sec2_title"),
            body=t("help_sec2_body"),
            accent="#10b981"
        )

        # Section 3: 1-Click Re-lock
        self._add_help_card(
            scroll,
            title=t("help_sec3_title"),
            body=t("help_sec3_body"),
            accent="#f59e0b"
        )

        # Section 4: Performance & Safety
        self._add_help_card(
            scroll,
            title=t("help_sec4_title"),
            body=t("help_sec4_body"),
            accent="#8b5cf6"
        )

        # Bottom Close Button
        btn_close = ctk.CTkButton(
            self,
            text=t("help_close_btn"),
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.destroy
        )
        btn_close.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))

    def _add_help_card(self, parent, title: str, body: str, accent: str):
        card = ctk.CTkFrame(parent, corner_radius=8, fg_color=("gray90", "gray18"))
        card.pack(fill="x", pady=6, padx=4)

        lbl_t = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=accent
        )
        lbl_t.pack(anchor="w", padx=12, pady=(10, 4))

        lbl_b = ctk.CTkLabel(
            card,
            text=body,
            font=ctk.CTkFont(size=11),
            justify="left",
            wraplength=400,
            anchor="w"
        )
        lbl_b.pack(anchor="w", padx=12, pady=(0, 10))
