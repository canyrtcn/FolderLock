# FolderLock v1.0.6 — Windows Locking & Portable Integration Fixes

## Fixed

- Fixed Instant Lock failing with `WinError 5` when Windows holds a metadata-only handle on a file inside a folder. Keep the atomic directory rename when it succeeds; otherwise use journaled same-volume entry moves without copying file contents.
- Apply the same fallback when unlocking, re-locking, rolling back, and recovering. Preserve nested and empty directories, directory streams, timestamps, attributes, and effective access permissions.
- Track attempted moves before saving completion so a journal write failure after a successful move cannot skip rollback. Keep password-verification metadata and the journal if rollback cannot restore all entries.
- Keep actual data-sharing violations as failures and restore moved entries. No automatic process termination, permission bypass, or destination overwrite is used.
- Fixed Explorer integration reporting a stale, still-existing portable EXE as the current installation. Registration uses the running EXE on every machine, including paths with spaces and Unicode characters.
- Refresh previously enabled Explorer registration after a portable EXE is moved or updated. Do not enable integration automatically when it was disabled.
- Restore prior registry values if registration fails, preserve unrelated values, and refuse to overwrite another application's `.locked` association.
- Resolve development builds relative to the source directory rather than Explorer's working directory.
- Report invalid CLI recovery paths as normal errors instead of an uncaught traceback.

## Updating

Extract the portable archive to a permanent location and run the new `FolderLock.exe` once. An existing FolderLock right-click registration will follow that EXE. To register for the first time, enable Explorer integration in Settings. Existing locked folders and passwords remain compatible.

## Validation

Validated on Windows with Python 3.13:

- All 109 unittest cases passed.
- Both the single-file EXE and portable EXE passed Instant Lock/AES round trips, password-stdin, metadata-handle lock/unlock, active-reader refusal, and invalid-recovery checks.
- A synthetic 1,036-file folder completed lock/unlock with a metadata handle held open; every file's bytes were preserved.
- Additional native-handle tests cover nested directories, directory streams, rollback failures, journal failures, authenticated recovery, and collision preservation. Registry tests use an isolated HKCU subtree. User folders are not used as test fixtures.
- Source and compiled package contents were checked for local private paths and credential patterns. Local logs, configuration, screenshots from the reported error, and validation archives are excluded from the release.
