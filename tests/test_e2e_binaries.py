import os
import sys
import tempfile
import subprocess
import shutil

ONEFILE_EXE = os.path.abspath("dist/FolderLock.exe")
PORTABLE_EXE = os.path.abspath("dist/FolderLock_portable/FolderLock.exe")

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

if __name__ == "__main__":
    test_binary(ONEFILE_EXE, "Onefile EXE")
    test_binary(PORTABLE_EXE, "Portable EXE")
    print("\n>>> ALL BINARIES PASSED E2E VERIFICATION! <<<")
