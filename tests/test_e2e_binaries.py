import os
import sys
import tempfile
import subprocess
import shutil
import ctypes

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
import safe_fs
from translations import APP_VERSION

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ONEFILE_EXE = os.path.join(PROJECT_ROOT, "dist", "FolderLock.exe")
PORTABLE_EXE = os.path.join(PROJECT_ROOT, "dist", "FolderLock_portable", "FolderLock.exe")

def run_exe(exe_path, args, stdin_text=None):
    cmd = [exe_path] + args
    result = subprocess.run(
        cmd,
        input=stdin_text,
        text=True,
        capture_output=True,
        timeout=60
    )
    return result

def test_binary(exe_path, name):
    print(f"Testing {name}: {exe_path}")
    assert os.path.isfile(exe_path), f"File not found: {exe_path}"
    
    # Test --help
    res = run_exe(exe_path, ["--help"])
    print(f"[{name}] --help exit code: {res.returncode}")
    assert res.returncode == 0
    assert "FolderLock" in res.stdout
    assert f"v{APP_VERSION}" in res.stdout
    assert "--password-stdin" in res.stdout
    
    # Test Instant Lock & Unlock
    temp_dir = tempfile.mkdtemp(prefix="folderlock_e2e_")
    try:
        sample_file = os.path.join(temp_dir, "test.txt")
        with open(sample_file, "w", encoding="utf-8") as f:
            f.write("E2E instant test data")
            
        # Lock Instant
        res = run_exe(exe_path, ["--lock", temp_dir, "--mode", "instant", "--password", "TestPass123!", "--quiet"])
        assert res.returncode == 0, f"Lock failed: {res.stderr}"
        assert not os.path.exists(sample_file), "Sample file should be locked"
        
        # Unlock Instant
        res = run_exe(exe_path, ["--unlock", temp_dir, "--password", "TestPass123!", "--quiet"])
        assert res.returncode == 0, f"Unlock failed: {res.stderr}"
        assert os.path.isfile(sample_file), "Sample file should be restored"
        with open(sample_file, "r", encoding="utf-8") as f:
            assert f.read() == "E2E instant test data"
            
        # Lock AES
        res = run_exe(exe_path, ["--lock", temp_dir, "--mode", "aes256", "--password-stdin", "--quiet"], stdin_text="TestPass123!\n")
        assert res.returncode == 0, f"AES Lock failed (code {res.returncode}):\nstdout: {res.stdout}\nstderr: {res.stderr}"
        assert not os.path.exists(sample_file), "Sample file should be encrypted"
        
        # Unlock AES
        res = run_exe(exe_path, ["--unlock", temp_dir, "--password-stdin", "--quiet"], stdin_text="TestPass123!\n")
        assert res.returncode == 0, f"AES Unlock failed (code {res.returncode}):\nstdout: {res.stdout}\nstderr: {res.stderr}"
        assert os.path.isfile(sample_file), "Sample file should be restored"
        with open(sample_file, "r", encoding="utf-8") as f:
            assert f.read() == "E2E instant test data"
            
        print(f"[{name}] ALL E2E tests PASSED successfully!")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_metadata_handle(exe_path, name):
    """Exercise the reported WinError 5 across real process boundaries."""
    temp_dir = tempfile.mkdtemp(prefix="folderlock_binary_handles_")
    handle = None
    try:
        folder = os.path.join(temp_dir, "Folder with spaces İ")
        nested = os.path.join(folder, "s", "nested")
        os.makedirs(nested)
        photo = os.path.join(nested, "photo.jpg")
        content = b"Synthetic binary metadata-handle regression" * 100
        with open(photo, "wb") as stream:
            stream.write(content)
        handle = safe_fs._CreateFileW(photo, 0x80, 3, None, 3, 0, None)
        assert handle != safe_fs.INVALID_HANDLE_VALUE, ctypes.get_last_error()
        for action in ("--lock", "--unlock"):
            args = [action, folder, "--password-stdin", "--quiet"]
            if action == "--lock":
                args += ["--mode", "instant"]
            res = run_exe(exe_path, args, stdin_text="Synthetic-binary-password!\n")
            assert res.returncode == 0, f"{name} {action}: {res.stdout} {res.stderr}"
        with open(photo, "rb") as stream:
            assert stream.read() == content
        safe_fs._CloseHandle(handle)
        # A COM thumbnail reader can hold GENERIC_READ and FILE_SHARE_DELETE.
        # Reproduce that real sharing mode across the built EXE boundary.
        handle = safe_fs._CreateFileW(photo, safe_fs.GENERIC_READ, 7, None, 3, 0, None)
        assert handle != safe_fs.INVALID_HANDLE_VALUE, ctypes.get_last_error()
        for action in ("--lock", "--unlock", "--relock", "--unlock"):
            args = [action, folder, "--quiet"]
            if action != "--relock":
                args += ["--password-stdin"]
            if action == "--lock":
                args += ["--mode", "instant"]
            res = run_exe(exe_path, args, stdin_text="Synthetic-binary-password!\n")
            assert res.returncode == 0, f"{name} shared reader {action}: {res.stdout} {res.stderr}"
        with open(photo, "rb") as stream:
            assert stream.read() == content
        safe_fs._CloseHandle(handle)
        handle = safe_fs._CreateFileW(photo, safe_fs.GENERIC_READ, 3, None, 3, 0, None)
        assert handle != safe_fs.INVALID_HANDLE_VALUE, ctypes.get_last_error()
        res = run_exe(exe_path, ["--lock", folder, "--mode", "instant", "--password-stdin", "--quiet"],
                      stdin_text="Synthetic-binary-password!\n")
        assert res.returncode == 1, f"{name} ignored an active reader"
        assert os.path.isfile(photo), "Failed lock did not restore the source"
        assert not os.path.exists(os.path.join(folder, ".locked_data")), "Failed lock left a container"
        res = run_exe(exe_path, ["--recover", os.path.join(temp_dir, "missing"), "--password-stdin", "--quiet"],
                      stdin_text="Synthetic-binary-password!\n")
        assert res.returncode == 1 and "[ERROR]" in res.stdout and "Traceback" not in res.stderr
        print(f"[{name}] metadata/shared-reader lock-unlock-relock, genuine sharing refusal, invalid recovery PASSED")
    finally:
        if handle not in (None, safe_fs.INVALID_HANDLE_VALUE):
            safe_fs._CloseHandle(handle)
        container = os.path.join(temp_dir, "Folder with spaces İ", ".locked_data")
        if os.path.isdir(container):
            safe_fs.run_icacls_safe([container, "/remove:d", "*S-1-1-0"])
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_binary(ONEFILE_EXE, "Onefile EXE")
    test_metadata_handle(ONEFILE_EXE, "Onefile EXE")
    test_binary(PORTABLE_EXE, "Portable EXE")
    test_metadata_handle(PORTABLE_EXE, "Portable EXE")
    print("\n>>> ALL BINARIES PASSED E2E VERIFICATION! <<<")
