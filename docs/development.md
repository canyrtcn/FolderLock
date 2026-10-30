# Development

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer and pip.
- Run the commands below from the repository root unless stated otherwise.

## Run from source

```powershell
git clone https://github.com/canyrtcn/FolderLock.git
cd FolderLock
python -m pip install -r requirements.txt
python src/main.py
```

The source directory contains the app's modules. `src/main.py` is the entrypoint; its folder is added to Python's import path automatically when run as a script. The source app resolves its icon from `assets/`. Frozen builds use their bundled resources.

## Build for Windows

Install the runtime and build dependencies:

```powershell
python -m pip install -r packaging/requirements.txt
```

Build the single-file EXE and portable directory:

```powershell
python -m PyInstaller --noconfirm --clean packaging/FolderLock.spec
python -m PyInstaller --noconfirm --clean packaging/FolderLock_onedir.spec
```

Outputs remain `dist/FolderLock.exe` and `dist/FolderLock_portable/FolderLock.exe`. Intermediate files stay under `build/`; both output folders are ignored by Git. The spec files resolve source, icon and version paths relative to their own location.

Windows version resources live in `packaging/version_info.txt`. The displayed version comes from `src/translations.py`; tests check that both agree.

## Run tests

```powershell
python -m unittest discover -s tests -t . -v
python tests/test_e2e_binaries.py
```

The first command imports the test package, which adds `src/` to the test process's import path. The binary checks require both builds above. Filesystem tests use synthetic temporary folders; registry tests use an isolated temporary subtree. Never use personal data as a test fixture.

The suite covers authenticated encryption and legacy vault compatibility, Instant Lock and re-lock, open Windows handles, bounded journal writes, interrupted operations, authenticated recovery, collision preservation, native Shell Links and Explorer registration.

## Source map

| File | Responsibility |
| --- | --- |
| `src/main.py` | CustomTkinter UI and command-line entrypoint |
| `src/crypto_engine.py` | Instant Lock, AES-GCM, journals and recovery |
| `src/safe_fs.py` | Native moves, attributes, permissions and operation locks |
| `src/shell_integration.py` | Per-user Explorer registration |
| `src/shell_shortcuts.py` | Native in-folder Shell Links and ownership validation |
| `src/config_manager.py` | User settings and local vault registry |
| `src/translations.py` | English/Turkish strings and app version |
| `src/ui_dialogs.py`, `src/ui_icons.py` | Dialogs and generated UI icons |

Explorer registration in a released app uses the running executable. In source mode, it looks for an existing build under the repository's `dist/`, then falls back to launching Python with `src/main.py`. This lookup does not depend on the current working directory.

## Local files and release files

Keep personal data, settings, logs, environment files, credentials and generated release archives out of Git. Tests, source and build configuration belong in the repository; executables and portable archives belong in GitHub Releases. Previous public version notes are under [releases/](releases/).
