# FolderLock v1.0.7 — Explorer Re-lock and Lock Folder Fixes

## Fixed

- Fixed a v1.0.6 regression that rejected files opened by Explorer's COM thumbnail reader even when Windows permitted renaming them. Removed the exclusive-read probe and let native no-replace moves enforce the actual sharing contract.
- Shared readers that permit `FILE_SHARE_DELETE` now work during Instant Lock, unlock, re-lock, rollback, and recovery. Applications that genuinely prohibit renaming still cause a safe failure; existing destinations remain protected from overwrite.
- Fixed Explorer launches opening **Locked Vault** for unlocked folders with saved settings. They now open **Lock Folder** with the chosen folder selected. Locked folders continue to open the unlock dialog, and explicit in-folder Lock shortcuts retain the compact re-lock dialog.

## Updating

Close older FolderLock windows and run the v1.0.7 executable. Previously enabled Explorer integration follows the new executable's location. Existing protected folders and passwords remain compatible.

## Validation

All 114 Windows unittest cases passed. Regression tests reproduce the v1.0.6 false sharing violation and incorrect Explorer tab before the fix. Coverage includes shared-reader lock/unlock/re-lock, genuine rename-sharing violations, rollback, authenticated recovery, and Explorer/shortcut entrypoint routing without desktop interaction. Both EXE builds passed shared-reader lock/unlock/re-lock checks with a reader held open from a separate process. Test data is synthetic; private files, local diagnostics, and screenshots are excluded from the release.
