# FolderLock v1.0.2

**Security & Reliability Update**

FolderLock v1.0.2 focuses on safer file operations, stronger integrity validation, improved recovery behavior, and compatibility with folders protected by earlier versions.

This release addresses issues identified during the security review, with particular attention to preventing unintended file changes and improving failure handling.

### What's Changed

**File Safety & Recovery**
- Improved recovery validation for Instant Lock containers: recovery now strictly requires password authentication to prevent unauthorized container extraction.
- Strengthened safeguards against unintended file replacement and deletion: user files (including user `Readme.txt` and user executables) are treated as regular protected files and are never automatically deleted or overwritten.
- Replaced broad recursive cleanup utilities with narrow, verified file removal functions.
- Improved handling of interrupted operations and partial failures with transactional state journaling.
- Refined Windows file permission management and recovery procedures with non-destructive collision resolution.

**Encryption & Data Integrity**
- Introduced the FLCK03 authenticated vault format with chunk-level Associated Authenticated Data (AAD), binding chunk index, payload length, and termination flags.
- Strengthened encrypted archive validation: bounded chunk sizes (max 2 MB), explicit authenticated EOF markers, and rejection of trailing data.
- Enhanced validation before protected source files are removed: plaintext source files are committed for removal only after complete stream and tag verification.
- Maintained backward compatibility: full support for reading and decrypting legacy FLCK02 vaults created by earlier versions.

**Windows Integration & Usability**
- Added `--password-stdin` support for secure headless scripted execution.
- Fixed password handling in direct unlock dialogs to preserve exact entered characters without stripping leading/trailing whitespace.
- Refined Windows Explorer integration error reporting and configuration verification.
- Deferred background vault list inspection on startup for responsive initial window rendering.
- Continued use of the central FolderLock application without copying helper executables into protected folders.

**Packaging & Performance**
- Continued distribution without UPX executable compression to minimize heuristic packer flags.
- Provided both standalone executable and portable directory distribution bundles.
- Updated Windows version resource metadata to 1.0.2.0.

### Compatibility

| Component | Support |
|---|---|
| Operating systems | Windows 10 / Windows 11 |
| Instant Lock | Supported |
| AES-256-GCM protection (FLCK03) | Supported |
| Existing v1.0.0/v1.0.1 protected folders | Supported (FLCK02 backward-compatibility verified) |
| English / Turkish interface | Supported |
| Windows Explorer integration | Optional |

### Downloads & Checksums

| File | Size | SHA-256 Checksum |
|---|---|---|
| **FolderLock.exe** | 24,544,489 bytes (~23.4 MB) | `27c267888edb6057c6b28a1c93a6f9a73e23b3d60fec125f2d3990ae7ecc6fca` |
| **FolderLock-v1.0.2-portable.zip** | 24,580,936 bytes (~23.4 MB) | `a8c860d9bde8a7ec680270612c7e215f957ca87cac58c6a9c11ba2940c5e4232` |
| **SHA256SUMS.txt** | 185 bytes | `4fba85180bf9185ac1202efa540f9d1d089fef5608af4140c95abc6b622f41ae` |

### Upgrading

Existing protected folders remain accessible through the updated application.
For important data, maintain independent backups before modifying protected folders.

### Security Notes

Instant Lock uses Windows NTFS access controls and does not provide cryptographic confidentiality. A Windows administrator may manage file permissions independently.
AES-256-GCM mode provides authenticated encryption for protected file contents.
Antivirus compatibility improvements are intended to reduce heuristic detections. They do not guarantee that every security product will classify the application identically.
