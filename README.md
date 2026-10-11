# FolderLock 🔒

> A lightweight Windows desktop utility for locking folders quickly or protecting them with AES-256-GCM encryption.

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-red.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

<p align="center">
  <img src="assets/FolderLock_ui.png" alt="FolderLock application interface" width="520">
</p>

## Highlights

- **Instant Lock (SSD-friendly):** restricts folder access without rewriting protected file contents. Moves entries into an internal container and applies Windows hidden/system attributes plus an NTFS deny ACE.
- **Deep AES-256-GCM (FLCK03):** streams the folder into an authenticated encrypted vault using AES-256-GCM with PBKDF2-HMAC-SHA256 (300,000 iterations). Each chunk binds sequence index, length, and termination flags in Associated Authenticated Data (AAD).
- **Transactional State Machine:** persistent journal (`.flock_journal`) tracks encryption and commit states. Source files are safely removed only after complete end-to-end archive and authentication tag verification.
- **Authenticated Recovery:** recovery requires proper password verification against container metadata. No automated passwordless bypass.
- **Zero In-Folder Binary Replication:** eliminates dropping `Unlock.exe` or `Lock.exe` binaries into protected folders, ensuring clean antivirus compatibility.
- **Preservation of User Files:** user files (including user `Readme.txt` and user executables) are treated as regular protected files and never overwritten or deleted.
- **Non-Destructive File Safety:** safe collision resolution guarantees that existing user files are never overwritten or deleted during unlock.
- **Central & CLI Access:** unlock and lock folders directly via GUI, Windows Explorer context menu, or command line (`--unlock <path>`, `--lock <path>`, `--recover <path>`).
- **English + Turkish UI:** runtime language switching with persistent preferences.
- **Light + dark themes:** follows Windows appearance on first launch and remembers user preferences.
- **Windows Explorer Integration:** user-controlled context menu integration via Settings.

## Protection Modes

| Feature | Instant Lock | Deep AES-256-GCM (FLCK03) |
| --- | --- | --- |
| Main goal | Fast local access restriction | Cryptographic confidentiality + integrity |
| Protected file contents rewritten? | No | Yes, into an encrypted vault |
| Mechanism | Hidden/system attributes + NTFS deny ACE | PBKDF2-HMAC-SHA256 + AES-256-GCM with chunk AAD |
| Best for | Large folders, games, media, everyday local privacy | Sensitive documents and data requiring encryption |
| Unlock cost | Very fast; filesystem metadata operations | Depends on data size and storage/CPU performance |

> **Important:** Instant Lock is **NTFS Access Control**, not cryptographic encryption. A Windows administrator, a user taking ownership, or offline storage access may bypass permission-based protection. Use **Deep AES-256-GCM** when cryptographic confidentiality is required.

## How It Works

### Instant Lock

FolderLock creates an internal `.locked_data` container, stores verification metadata in `.flock_meta`, moves the folder contents into that container transactionally, then applies hidden/system attributes and an NTFS deny ACE using universal SID `*S-1-1-0` (`Everyone`). If any step fails, the operation rolls back cleanly with zero data loss.

#### Administrator Manual Recovery Procedure (If Metadata Lost)
If `.flock_meta` is permanently corrupted or deleted by external utilities:
1. Open PowerShell or Command Prompt as Administrator.
2. Remove the NTFS deny permission:
   ```cmd
   icacls "C:\Path\To\Folder\.locked_data" /remove:d *S-1-1-0
   ```
3. Remove hidden and system attributes:
   ```cmd
   attrib -h -s "C:\Path\To\Folder\.locked_data"
   ```
4. Move your files from `.locked_data` back to the parent folder.

### Deep AES-256-GCM (FLCK03 Format)

FolderLock packages folder contents into a streaming tar archive encrypted in 1 MB chunks using AES-256-GCM.
- Each chunk contains a 16-byte header authenticated in AES-GCM Associated Data (AAD), binding chunk index, payload length, and flags.
- Rejects truncated streams, out-of-order chunks, tampered flags, and unexpected trailing data.
- The encryption key is derived via PBKDF2-HMAC-SHA256 using a random 32-byte salt and 300,000 iterations.
- Full verification of every chunk, authentication tag, and tar structure is performed before source files are committed for cleanup.
- Full backward compatibility: older vaults created in v1.0.0 and v1.0.1 (`FLCK02`) can be unlocked directly.

## Password & Re-lock Behavior

- Folder passwords are not hard-coded in the repository.
- Instant Lock stores a salted password-derived verifier, not the plaintext password.
- For one-click re-lock in **Deep AES mode**, FolderLock may store the password in `.flock_relock` protected with the current Windows user's DPAPI credentials while the folder is unlocked.
- DPAPI-protected re-lock data is tied to the Windows security context that created it; it should be treated as a convenience feature rather than a portable secret store.

## CLI Usage

```text
Usage:
  FolderLock.exe [options] [folder_path]

Options:
  --unlock <path>     Unlock the specified locked folder
  --lock <path>       Lock the specified folder (opens lock tab)
  --relock <path>     Re-lock folder using saved credentials
  --recover <path>    Recover files from an interrupted Instant Lock folder (password required)
  --password, -p <pw> Optional password for CLI actions
  --password-stdin    Read password securely from standard input
  --quiet, -q         Suppress message dialogs (exit code 0 on success, 1 on error)
  --help, -h, /?      Show this help message
```

## Security Scope

FolderLock uses standard Windows access-control mechanisms and the `cryptography` package's AES-GCM implementation. The project has **not been presented as independently security-audited**, so highly sensitive or regulated data should still be backed up and handled with an established, audited encryption solution where appropriate.

## Building from Source

### Requirements

- Windows 10 or Windows 11
- Python 3.10+
- `pip`

### Install

```bash
git clone https://github.com/canyrtcn/FolderLock.git
cd FolderLock
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

### Build a Windows executable

```bash
pyinstaller FolderLock.spec --clean
```

The executable is generated under `dist/`.

## Kullanım Kılavuzu (Türkçe)

1. **Klasör kilitleme**
   - **Klasör Seç** ile klasörü belirleyin.
   - Bir şifre oluşturun.
   - **Hızlı Kilit (SSD Dostu)** veya **Tam AES-256** modunu seçin.
   - **Klasörü Kilitle** düğmesine basın.

2. **Kilit açma**
   - Ana uygulamadaki **Kilit Aç** sekmesinden klasörü seçerek veya sürükleyip bırakarak şifrenizi girin.
   - Ayarlar'dan Gezgin entegrasyonunu açtıysanız, klasöre sağ tıklayıp **FolderLock - Lock / Unlock** seçeneğini kullanabilirsiniz.
   - Komut satırından `FolderLock.exe --unlock "<klasör_yolu>"` komutunu çalıştırabilirsiniz.

3. **Tek tıkla tekrar kilitleme**
   - **Kilitli Kasam** sekmesindeki **Kilitle** düğmesine basarak aynı şifreyle anında yeniden kilitleyebilirsiniz.
   - Klasör içine yardımcı çalıştırılabilir dosyalar kopyalanmaz; antivirüs false-positive riskleri tamamen giderilmiştir.

### Mod seçimi

- **Hızlı Kilit:** Dosya içeriklerini yeniden yazmadan NTFS erişim kısıtlaması uygular. **Şifreleme değildir.**
- **Tam AES-256:** Dosya içeriğini AES-256-GCM ile şifreli kasaya dönüştürür. Hassas veri için tercih edilmesi gereken mod budur.

## Project Structure

```text
main.py                # Main CustomTkinter application and CLI entrypoint
crypto_engine.py       # Instant-lock and AES-GCM (FLCK03) protection logic
safe_fs.py             # Hardened Windows filesystem abstraction & locking
config_manager.py      # User settings and local vault registry
shell_integration.py   # Windows Explorer integration
translations.py        # English/Turkish localized strings
ui_dialogs.py          # Modern password dialogs
ui_icons.py            # Runtime-generated UI icons
FolderLock.spec        # PyInstaller build configuration
```

## License

Licensed under the [MIT License](LICENSE).
