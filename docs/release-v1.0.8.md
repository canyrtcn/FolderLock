# FolderLock v1.0.8 — Faster Instant Lock

## Improved

- Removed the main cause of slow Instant Lock and re-lock: an expanding JSON journal was rewritten before and after individual file moves. Instant Lock now persists one recursive move plan before the first move, keeps bounded progress records in memory, and writes its final checkpoint after protection is applied.
- Reduced redundant path and attribute queries during native moves. Destination collisions are still rejected by the atomic Windows no-replace operation, and successful moves are still checked afterward.
- Removed a redundant directory permission update after children had moved. Original permissions are applied when the destination directory is created; applying them again could trigger another inheritance walk through the files.
- Retained support for Explorer thumbnail readers that permit rename sharing. Real sharing violations still fail safely, and existing destination files are preserved.

## Measured performance

Representative synthetic Windows NTFS tests held a shared reader open to exercise the directory fallback:

| Measurement | v1.0.7 | v1.0.8 |
| --- | ---: | ---: |
| Lock time, 1,036 files | 12.2 s | 0.8 s |
| Journal writes in that lock operation | 2,081 | 3 |
| Cumulative JSON payload written | 332.7 MiB | 2.3 KiB |

In that test, the new journal's largest JSON file was about 1.1 KiB. The old 332.7 MiB figure was cumulative repeated writes, not a single retained file. Successful operations remove the journal.

A built portable EXE re-locked a separate 3,278-file synthetic fixture in about 1.4 seconds including process startup; 1,036 files were in the branch containing the open reader. Timings depend on storage, caches, open handles, and background activity.

## Reliability checks

All 123 Windows unittest cases passed. New coverage checks that the move intent is durable before any file moves, journal writes stay small for nested and top-level files, an initial storage failure moves no user data, and failed final checkpoints preserve authenticated recovery. A separate-process crash test verifies every synthetic file survives an interruption and recovery still requires the correct password. Native move tests cover read-only destination collisions, missing sources, cross-volume refusal, and post-move verification.

Both EXE builds passed Instant Lock and AES round trips, shared-reader lock/unlock/re-lock, genuine sharing-violation refusal, and invalid-recovery checks. AES verification and deletion journaling behavior is unchanged.

## Updating

Close older FolderLock windows and launch the v1.0.8 executable. Previously enabled Explorer integration follows the executable's location. Existing protected folders and passwords remain compatible.
