# Usage and troubleshooting

## Lock a folder

Select **Lock Folder**, choose your folder, select **Instant Lock** or **Deep AES-256**, and enter and confirm your password. Click **Lock Folder** to apply protection.

Instant Lock is Windows NTFS access control; it does not encrypt file contents. Deep AES-256 encrypts the contents into an authenticated vault. Keep independent backups of important files.

## Unlock or re-lock

Use **Unlock Folder** in the app or double-click **FolderLock - Unlock** inside a protected folder. Enter the folder password to restore its contents.

Double-click **FolderLock - Lock** to open the compact lock dialog. For previously protected folders, **Re-Lock Now** uses the saved settings. You can also change the settings or password in that dialog.

Folder passwords are not hard-coded. Instant Lock stores a salted password verifier. For convenient re-lock in Deep AES mode, the unlocked folder may contain a password protected with the current Windows user's DPAPI credentials. This convenience data is tied to that Windows security context.

## Explorer integration and portable copies

Enable Explorer integration in **Settings** to add **FolderLock - Lock / Unlock** to a folder's right-click menu. An unlocked folder opens **Lock Folder**; a locked folder opens the unlock dialog.

Extract the portable package to its intended location before enabling integration. Explorer stores the executable's path. After moving or updating the app, run the new executable once to refresh an existing registration, or enable integration in Settings. Integration remains disabled for users who have not enabled it. No administrator rights are required for registration.

In-folder shortcuts reference their original central executable. Keep that executable path available; moving or deleting it can invalidate those shortcuts.

## File-in-use errors and speed

Windows may refuse to move a whole directory when a child file is open. FolderLock first attempts the fast directory move, then uses reversible individual entry moves when appropriate. Thumbnail readers that permit `FILE_SHARE_DELETE` can remain open. If another application genuinely blocks rename sharing, close that application and retry.

v1.0.8 records a recursive move plan before the operation instead of repeatedly rewriting a growing journal per file. File contents are not copied in Instant Lock. Very large folders still require filesystem work when Windows blocks the whole-directory move; timings depend on storage, caches and background processes.

## Interrupted operations

If an operation is interrupted or rollback cannot restore all entries, keep the `.locked_data` container, vault and journal intact. Use password-authenticated recovery. Existing destination files are preserved through collision resolution.

```text
FolderLock.exe --recover "<folder_path>" --password-stdin --quiet
```

### Administrator recovery when Instant Lock metadata is lost

Instant Lock can be bypassed by a Windows administrator, by taking ownership, or through offline storage access. If its metadata is permanently lost or corrupted, the original manual recovery procedure is:

1. Open PowerShell or Command Prompt as Administrator.
2. Remove the targeted deny permission:

   ```cmd
   icacls "C:\Path\To\Folder\.locked_data" /remove:d *S-1-1-0
   ```

3. Remove the hidden/system attributes:

   ```cmd
   attrib -h -s "C:\Path\To\Folder\.locked_data"
   ```

4. Move files from `.locked_data` back to the parent folder, preserving any name collisions.

This procedure applies to Instant Lock. It does not decrypt an AES vault.

## Command-line options

```text
FolderLock.exe [options] [folder_path]

--unlock <path>     Unlock a protected folder
--lock <path>       Lock a folder
--mode <mode>       crypto (AES-256-GCM) or instant (NTFS)
--relock <path>     Re-lock with saved credentials
--recover <path>    Password-authenticated recovery
--password, -p     Password argument
--password-stdin   Read the password from standard input
--quiet, -q        Suppress dialogs; exit 0 for success, 1 for an error
--help, -h, /?     Show help
```

Prefer `--password-stdin` for scripts so the password is not included in the process command line.

## Türkçe kullanım

- **Kilitleme:** **Klasör Seç** ile klasörü belirleyin, mod seçip parolanızı girin ve **Klasörü Kilitle** düğmesine basın.
- **Kilit açma:** **Kilit Aç** sekmesini veya klasördeki **FolderLock - Unlock** kısayolunu kullanın.
- **Tekrar kilitleme:** **FolderLock - Lock** kısayolunda **Re-Lock Now** ile kayıtlı ayarları kullanın.
- **Sağ tık:** Ayarlar'dan Gezgin entegrasyonunu etkinleştirin. Kilidi açık klasör **Lock Folder** ekranını açar.
- **Mod seçimi:** **Hızlı Kilit** erişim izinleri uygular; dosya içeriğini şifrelemez. **Tam AES-256** dosya içeriğini şifreler.
- **Kesinti:** Kurtarma tamamlanmadan kasa, `.locked_data` veya günlük dosyalarını silmeyin. Kurtarma parolayı doğrular; önemli verilerin bağımsız yedeğini tutun.
