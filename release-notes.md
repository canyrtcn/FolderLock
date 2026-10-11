# FolderLock v1.0.1 — Security Hardening, Antivirus Compatibility & Integrity Safeguards

## English

### 🛡️ Security & Antivirus False-Positive Remediation
- **Eliminated In-Folder Binaries**: FolderLock no longer drops `Unlock.exe` or `Lock.exe` into locked folders. All operations are handled centrally by the main application or through Windows Explorer shell integration, completely eliminating suspicious binary replication flags (e.g. Kaspersky `PDM:Trojan.Win32.Generic`).
- **Removed Self-Deletion Subprocesses**: Removed delayed `cmd.exe /c ping ... & del ...` loops previously used for cleanup.
- **UPX Compression Removed**: Disabled UPX executable packing in PyInstaller builds to eliminate heuristic packer detections.
- **Legacy Cleanup**: Automatically and safely removes orphaned `Unlock.exe` / `Lock.exe` files created by older versions upon unlocking, without touching user data.

### 🔒 Data Integrity & Zero Data Loss Architecture
- **Transactional Instant Lock**: File relocations are strictly transactional; if any step fails, changes automatically roll back to their original state.
- **Streaming Vault Verification**: AES-256-GCM vaults now undergo full multi-chunk authentication tag validation and tar stream parsing *before* source files are removed.
- **Collision Preservation**: Destination collisions during unlock or recovery are preserved using non-destructive rename schemes (`<filename>_restored_1.<ext>`) rather than overwriting or deleting user files.
- **Antivirus Recovery Mechanism (`--recover`)**: Built-in CLI recovery tool safely resets ACLs, unhides protected containers, and restores user files if an antivirus terminates an active lock/unlock operation.

### 💻 Windows Shell & CLI Integration
- **Clean Explorer Context Menu**: Optional Windows Explorer integration accessible via Settings (HKEY_CURRENT_USER, no admin privileges required).
- **Command-Line Interface**:
  - `--lock <folder>`: Opens FolderLock with folder pre-selected for locking
  - `--unlock <folder>`: Unlocks protected folder via lightweight interface
  - `--relock <folder>`: Re-locks folder using saved DPAPI credentials
  - `--recover <folder>`: Recovers interrupted or quarantined Instant Lock folders
  - `--quiet`, `-q`: Headless mode for scripting and automation (exit code 0 on success, 1 on error)

---

## Türkçe

### 🛡️ Güvenlik ve Antivirüs Uyumluluğu İyileştirmeleri
- **Klasör İçi EXE Kopyalama Kaldırıldı**: Artık korunan klasörlerin içerisine `Unlock.exe` veya `Lock.exe` kopyalanmaz. Tüm kilit açma ve kilitleme işlemleri merkezi ana uygulama ve Windows Explorer entegrasyonu üzerinden yürütülür; böylece Kaspersky (`PDM:Trojan.Win32.Generic`) ve diğer güvenlik yazılımlarının şüpheli dosya çoğaltma uyarıları giderilmiştir.
- **Kendi Kendini Silen CMD Komutları Kaldırıldı**: Temizlik amacıyla arka planda çalıştırılan gecikmeli `ping ... & del` komutları kaldırılmıştır.
- **UPX Sıkıştırması Kaldırıldı**: Hevristik antivirüs tarayıcılarının paketleyici şüphelerini önlemek için UPX sıkıştırması iptal edilmiştir.
- **Eski Sürüm Temizliği**: Önceki v1.0.0 sürümünden kalan `Unlock.exe` ve `Lock.exe` kalıntıları, kilit açma sırasında kullanıcı dosyalarına dokunulmadan güvenle temizlenir.

### 🔒 Veri Bütünlüğü ve Sıfır Veri Kaybı Mimarisi
- **İşlemsel (Transactional) Instant Lock**: Taşıma işlemleri atomik ve işlemseldir; herhangi bir adımda hata olursa tüm değişiklikler orijinal durumuna geri alınır.
- **Akış Seviyesinde Kasa Doğrulaması**: AES-256-GCM modunda şifrelenen kasalar, kaynak dosyalar silinmeden önce 1MB'lık parçalar halinde kimlik doğrulama etiketleri (GCM tag) ve tar arşivi test edilerek baştan sona teyit edilir.
- **Çakışma Koruması**: Kilit açma veya kurtarma sırasında hedef dizinde aynı isimde dosya varsa üzerine yazılmaz; `_restored_1` formatında yeni bir isim verilerek her iki dosya da korunur.
- **Antivirüs Müdahalesi Kurtarma Aracı (`--recover`)**: Güvenlik yazılımının işlemi yarıda kesmesi veya karantinaya alması durumunda `--recover` komutu ACL izinlerini sıfırlar ve dosyaları güvenle dışarı aktarır.

### 💻 Komut Satırı ve Kabuk Entegrasyonu
- **Windows Explorer Sağ Tık Menüsü**: Ayarlar sekmesinden tek tıkla açılıp kapatılabilen, yönetici yetkisi gerektirmeyen (HKCU) kabuk entegrasyonu.
- **Gelişmiş CLI**:
  - `--lock <klasör>`: Belirtilen klasörü kilitleme arayüzünde açar
  - `--unlock <klasör>`: Kilitli klasörü açma arayüzünde açar
  - `--relock <klasör>`: Kayıtlı kimlik bilgileriyle doğrudan yeniden kilitler
  - `--recover <klasör>`: Yarıda kesilmiş klasörü kurtarır
  - `--quiet`, `-q`: Otomasyon için sessiz mod (0 = başarılı, 1 = hata)

---

## 📦 Hashes & Verification / Doğrulama

| File / Dosya | Size / Boyut | SHA-256 Checksum |
| :--- | :--- | :--- |
| **FolderLock.exe** | 24,537,291 bytes (~23.4 MB) | `F4E29965CB8B606532C0807FEB006295C95F73C2A9919A40583B8515B53B38C3` |
| **FolderLock-v1.0.1-portable.zip** | 24,572,187 bytes (~23.4 MB) | `8817EDCB6AFCC98A7EBA170F480B3D649F4200DF47B07086545C6C6ABCDAECD3` |
