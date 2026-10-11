"""
FolderLock - Localized Translations (i18n)
Supports English (default) and Turkish.
"""

from typing import Dict, Any

# One source for displayed application version across GUI and CLI.
APP_VERSION = "1.0.4"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        # App Info
        "app_title": "FolderLock",
        "app_subtitle": "Smart Folder Protection",
        "version": APP_VERSION,

        # Tabs
        "tab_lock": "Lock Folder",
        "tab_unlock": "Unlock Folder",
        "tab_vault": "Locked Vault",
        "tab_settings": "Settings",

        # Lock Tab
        "lock_title": "Select Folder to Lock",
        "select_folder_btn": "Browse Folder...",
        "selected_folder_label": "Selected Folder:",
        "no_folder_selected": "No folder selected",
        "folder_info_fmt": "{files} files • {size}",

        # Modes
        "lock_mode_label": "Lock Mode:",
        "mode_instant": "Instant Lock (SSD Safe)",
        "mode_crypto": "Deep AES-256",
        "mode_instant_desc": "⚡ Fast • No protected-file rewrites • NTFS access control",
        "mode_crypto_desc": "🛡️ Maximum security • Bit-by-bit AES-256 • Full encryption (rewrites files)",

        "enter_password": "Password",
        "confirm_password": "Confirm Password",
        "password_placeholder": "Enter password",
        "confirm_placeholder": "Confirm password",
        "btn_lock_now": "Lock Folder",
        "show_password": "Show",
        "strength_weak": "Weak",
        "strength_medium": "Medium",
        "strength_strong": "Strong",
        "strength_label": "Strength:",

        # Unlock Tab
        "unlock_title": "Select Folder to Unlock",
        "select_file_btn": "Browse Folder...",
        "selected_file_label": "Selected Item:",
        "no_file_selected": "No folder selected",
        "file_info_fmt": "Size: {size}",
        "enter_unlock_password": "Password",
        "unlock_password_placeholder": "Enter folder password",
        "btn_unlock_now": "Unlock Folder",

        # Vault Tab
        "vault_title": "Registered Locked Folders",
        "vault_desc": "Easily access, lock, and unlock your protected folders.",
        "vault_empty": "No folders currently recorded in vault.",
        "vault_status_locked": "🔒 Locked",
        "vault_status_unlocked": "🔓 Unlocked",
        "btn_quick_lock": "Lock",
        "btn_quick_unlock": "Unlock",
        "btn_show_explorer": "Open",
        "btn_remove_entry": "Remove",
        "file_missing": "(Not found)",
        "col_mode": "Mode:",

        # Status
        "status_ready": "Ready",
        "status_locking": "Locking folder...",
        "status_unlocking": "Unlocking folder...",
        "status_calculating": "Scanning files...",
        "status_verifying": "Verifying...",
        "status_success_lock": "Folder locked successfully.",
        "status_success_unlock": "Folder unlocked successfully.",
        "btn_cancel": "Cancel",
        "cancelled_msg": "Operation cancelled.",

        # Dialogs
        "dialog_success": "Success",
        "dialog_error": "Error",
        "dialog_warning": "Warning",
        "dialog_confirm": "Confirmation",
        "err_no_folder": "Please select a folder first.",
        "err_no_file": "Please select a folder to unlock.",
        "err_empty_password": "Password cannot be empty.",
        "err_password_mismatch": "Passwords do not match.",
        "err_password_short": "Password must be at least 4 characters.",
        "err_wrong_password": "Incorrect password.",
        "err_corrupted": "Data is corrupted or invalid.",
        "confirm_lock_msg_instant": "Folder '{name}' will be locked using Instant Lock.\n\nMode: NTFS access control without rewriting protected file contents\nDo you want to proceed?",
        "confirm_lock_msg_crypto": "Folder '{name}' will be encrypted with AES-256.\n\nMode: Deep AES-256 (Full Encryption)\nDo you want to proceed?",
        "confirm_remove_vault": "Remove this entry from the list?",
        "quick_unlock_dialog_title": "Unlock Folder",
        "quick_unlock_prompt": "Enter password for '{name}':",
        "quick_lock_dialog_title": "Lock Folder",
        "quick_lock_prompt": "Enter password to lock '{name}':",

        # Settings Tab
        "settings_title": "Settings",
        "setting_lang": "Language:",
        "setting_theme": "Theme:",
        "setting_developer": "Developer:",
        "setting_version": "Version:",
        "setting_shell_integration": "Explorer Context Menu:",
        "shell_status_enabled": "Enabled",
        "shell_status_disabled": "Disabled",
        "btn_shell_enable": "Enable",
        "btn_shell_disable": "Remove",
        "shell_success_enabled": "Windows Explorer context menu added successfully.",
        "shell_success_disabled": "Windows Explorer context menu removed successfully.",
        "theme_dark": "Dark",
        "theme_light": "Light",
        "security_note_title": "Locking Modes Explained",
        "security_note_text": "• Instant Lock (SSD Safe): Restricts folder access using NTFS Access Control (ACL) without rewriting file contents. Fast and lightweight, but note that it is file system permission control, not cryptographic encryption.\n• Deep AES-256: Authenticated AES-256-GCM encryption with PBKDF2-HMAC-SHA256. Fully rewrites and encrypts file contents for confidential data.",

        # Direct In-Folder Unlock Dialog
        "in_folder_title": "Locked Folder",
        "in_folder_desc": "Enter your password to unlock this folder.",
        "in_folder_unlock_btn": "Unlock Folder",
        "in_folder_success": "Folder successfully unlocked.",

        # Help / User Guide Modal
        "help_btn_tooltip": "How to Use",
        "help_modal_title": "FolderLock - User Guide",
        "help_sec1_title": "1. How to Lock a Folder",
        "help_sec1_body": "• Click 'Browse Folder' or drag & drop any folder into the app.\n• Choose 'Instant Lock' (fast NTFS access control) or 'Deep AES-256' (AES-256-GCM authenticated encryption).\n• Enter a password and click 'Lock Folder'.",
        "help_sec2_title": "2. How to Unlock",
        "help_sec2_body": "• In-App: Open FolderLock, go to 'Unlock Folder' (or drag & drop the folder into the app window), enter your password to restore files.\n• Explorer Context Menu: If enabled in Settings, right-click any locked folder and select 'FolderLock - Lock / Unlock'.\n• Locked Vault: You can also unlock directly from the 'Locked Vault' tab.",
        "help_sec3_title": "3. 1-Click Instant Re-Locking",
        "help_sec3_body": "• In the 'Locked Vault' tab, unlocked folders can be instantly re-locked with the SAME password without retyping!\n• No dangerous helper executables are dropped into your folders, keeping your system safe and antivirus-friendly.",
        "help_sec4_title": "4. Performance & Portability",
        "help_sec4_body": "• No background service is required after the application is closed.\n• Portable use is supported on compatible Windows drives and removable storage, subject to filesystem permissions and device behavior.",
        "help_close_btn": "Got It",
    },

    "tr": {
        # App Info
        "app_title": "FolderLock",
        "app_subtitle": "Akıllı Klasör Kilitleyici",
        "version": APP_VERSION,

        # Tabs
        "tab_lock": "Klasör Kilitle",
        "tab_unlock": "Kilit Aç",
        "tab_vault": "Kilitli Kasam",
        "tab_settings": "Ayarlar",

        # Lock Tab
        "lock_title": "Kilitlenecek Klasörü Seçin",
        "select_folder_btn": "Klasör Seç...",
        "selected_folder_label": "Seçilen Klasör:",
        "no_folder_selected": "Henüz klasör seçilmedi",
        "folder_info_fmt": "{files} dosya • {size}",

        # Modes
        "lock_mode_label": "Kilitleme Modu:",
        "mode_instant": "Hızlı Kilit (SSD Dostu)",
        "mode_crypto": "Tam AES-256",
        "mode_instant_desc": "⚡ Hızlı • Korunan dosyaları yeniden yazmaz • NTFS erişim kilidi",
        "mode_crypto_desc": "🛡️ Maksimum güvenlik • Bayt bayt AES-256 • Tam şifreleme (diske yazar)",

        "enter_password": "Şifre",
        "confirm_password": "Şifre Tekrar",
        "password_placeholder": "Şifrenizi belirleyin",
        "confirm_placeholder": "Şifrenizi tekrar girin",
        "btn_lock_now": "Klasörü Kilitle",
        "show_password": "Göster",
        "strength_weak": "Zayıf",
        "strength_medium": "Orta",
        "strength_strong": "Güçlü",
        "strength_label": "Güç:",

        # Unlock Tab
        "unlock_title": "Açılacak Klasörü Seçin",
        "select_file_btn": "Klasör Seç...",
        "selected_file_label": "Seçilen Öğe:",
        "no_file_selected": "Henüz klasör seçilmedi",
        "file_info_fmt": "Boyut: {size}",
        "enter_unlock_password": "Şifre",
        "unlock_password_placeholder": "Klasör şifresini girin",
        "btn_unlock_now": "Kilidi Aç",

        # Vault Tab
        "vault_title": "Kayıtlı Kilitli Klasörler",
        "vault_desc": "Korumalı klasörlerinizi kolayca kilitleyin ve açın.",
        "vault_empty": "Henüz kasaya kayıtlı klasör bulunmuyor.",
        "vault_status_locked": "🔒 Kilitli",
        "vault_status_unlocked": "🔓 Açık",
        "btn_quick_lock": "Kilitle",
        "btn_quick_unlock": "Kilidi Aç",
        "btn_show_explorer": "Aç",
        "btn_remove_entry": "Kaldır",
        "file_missing": "(Bulunamadı)",
        "col_mode": "Mod:",

        # Status
        "status_ready": "Hazır",
        "status_locking": "Klasör kilitleniyor...",
        "status_unlocking": "Kilit açılıyor...",
        "status_calculating": "Dosyalar taranıyor...",
        "status_verifying": "Doğrulanıyor...",
        "status_success_lock": "Klasör başarıyla kilitlendi.",
        "status_success_unlock": "Klasör kilidi başarıyla açıldı.",
        "btn_cancel": "İptal",
        "cancelled_msg": "İşlem iptal edildi.",

        # Dialogs
        "dialog_success": "Başarılı",
        "dialog_error": "Hata",
        "dialog_warning": "Uyarı",
        "dialog_confirm": "Onay",
        "err_no_folder": "Lütfen önce bir klasör seçin.",
        "err_no_file": "Lütfen kilitli klasörü seçin.",
        "err_empty_password": "Şifre boş bırakılamaz.",
        "err_password_mismatch": "Girdiğiniz şifreler eşleşmiyor.",
        "err_password_short": "Şifre en az 4 karakter olmalıdır.",
        "err_wrong_password": "Hatalı şifre.",
        "err_corrupted": "Veri bozulmuş veya geçersiz.",
        "confirm_lock_msg_instant": "'{name}' klasörü Hızlı Kilit ile korunacaktır.\n\nMod: Korunan dosya içeriklerini yeniden yazmadan NTFS erişim kontrolü\nDevam etmek istiyor musunuz?",
        "confirm_lock_msg_crypto": "'{name}' klasörü AES-256 ile şifrelenecektir.\n\nMod: Tam Şifreleme (Diske Yazar)\nDevam etmek istiyor musunuz?",
        "confirm_remove_vault": "Bu kaydı listeden kaldırmak istiyor musunuz?",
        "quick_unlock_dialog_title": "Klasör Kilidini Aç",
        "quick_unlock_prompt": "'{name}' klasörünün şifresini girin:",
        "quick_lock_dialog_title": "Klasörü Kilitle",
        "quick_lock_prompt": "'{name}' klasörünü kilitlemek için şifre girin:",

        # Settings Tab
        "settings_title": "Ayarlar",
        "setting_lang": "Dil (Language):",
        "setting_theme": "Tema:",
        "setting_developer": "Geliştirici:",
        "setting_version": "Sürüm:",
        "setting_shell_integration": "Gezgin Sağ Tık Menüsü:",
        "shell_status_enabled": "Etkin",
        "shell_status_disabled": "Devre Dışı",
        "btn_shell_enable": "Etkinleştir",
        "btn_shell_disable": "Kaldır",
        "shell_success_enabled": "Windows Gezgini sağ tık menüsü başarıyla eklendi.",
        "shell_success_disabled": "Windows Gezgini sağ tık menüsü başarıyla kaldırıldı.",
        "theme_dark": "Koyu",
        "theme_light": "Açık",
        "security_note_title": "Kilitleme Modları Hakkında",
        "security_note_text": "• Hızlı Kilit (SSD Dostu): Dosya içeriklerini diske yeniden yazmadan NTFS Erişim Denetimi (ACL) ile erişimi engeller. Hızlı ve hafiftir; ancak şifreleme değil dosya sistemi izin kontrolüdür.\n• Tam AES-256: PBKDF2-HMAC-SHA256 ile doğrulamalı AES-256-GCM şifreleme uygular. Gizli ve hassas veriler için dosya içeriklerini bayt bayt tam olarak şifreler.",

        # Direct In-Folder Unlock Dialog
        "in_folder_title": "Kilitli Klasör",
        "in_folder_desc": "Bu klasörün kilidini açmak için şifrenizi girin.",
        "in_folder_unlock_btn": "Klasörün Kilidini Aç",
        "in_folder_success": "Klasör kilidi başarıyla açıldı.",

        # Help / User Guide Modal
        "help_btn_tooltip": "Nasıl Kullanılır?",
        "help_modal_title": "FolderLock - Kullanım Kılavuzu",
        "help_sec1_title": "1. Klasör Nasıl Kilitlenir?",
        "help_sec1_body": "• 'Klasör Seç' düğmesine basarak veya klasörü sürükleyip bırakarak seçin.\n• 'Hızlı Kilit' (hızlı NTFS erişim kontrolü) veya 'Tam AES-256' (AES-256-GCM doğrulamalı şifreleme) modunu seçin.\n• Şifrenizi belirleyin ve 'Klasörü Kilitle' düğmesine tıklayın.",
        "help_sec2_title": "2. Kilit Nasıl Açılır?",
        "help_sec2_body": "• Uygulamadan: FolderLock uygulamasını açın, 'Kilit Aç' sekmesine gelin (veya klasörü pencereye sürükleyip bırakın), şifrenizi girerek dosyaları geri yükleyin.\n• Gezgin Sağ Tık Menüsü: Ayarlar'dan etkinleştirdiyseniz, kilitli klasöre sağ tıklayıp 'FolderLock - Lock / Unlock' seçeneğini kullanabilirsiniz.\n• Kilitli Kasam: Kasadaki listeden de tek tıkla kilidi açabilirsiniz.",
        "help_sec3_title": "3. Tek Tıkla Yeniden Kilitleme",
        "help_sec3_body": "• 'Kilitli Kasam' sekmesinde açılmış klasörleri şifreyi tekrar yazmadan AYNI şifreyle anında yeniden kilitleyebilirsiniz!\n• Klasörlerinizin içine şüpheli yardımcı çalıştırılabilir dosyalar (EXE) kopyalanmaz, sisteminiz ve antivirüslerinizle tam uyumludur.",
        "help_sec4_title": "4. Performans ve Taşınabilirlik",
        "help_sec4_body": "• Uygulama kapatıldığında arka planda servis çalıştırması gerekmez.\n• Uyumlu Windows sürücülerinde ve çıkarılabilir depolamada taşınabilir kullanım desteklenir; davranış dosya sistemi izinlerine ve cihaza bağlıdır.",
        "help_close_btn": "Anladım",
    }
}

_current_lang = "en"  # Default is English


def get_current_lang() -> str:
    global _current_lang
    return _current_lang


def set_current_lang(lang: str):
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang


def t(key: str, **kwargs) -> str:
    lang_dict = TRANSLATIONS.get(_current_lang, TRANSLATIONS["en"])
    text = lang_dict.get(key, TRANSLATIONS["en"].get(key, key))
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text
