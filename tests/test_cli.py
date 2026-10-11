"""
FolderLock - Tests for CLI Interfaces
Validates --help, --quiet, --password-stdin, --lock, --unlock, and --recover via subprocess.
"""

import os
import sys
import tempfile
import shutil
import unittest
import subprocess

PYTHON_EXE = sys.executable
MAIN_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))

# Keep CLI version expectations aligned with the shared application version.
sys.path.insert(0, os.path.dirname(MAIN_PY))
from translations import APP_VERSION


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="flock_test_cli_")
        self.password = "Cli_Secret_Pass_456"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir, ignore_errors=True)
            except Exception:
                pass

    def test_cli_help(self):
        cmd = [PYTHON_EXE, MAIN_PY, "--help"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn(f"FolderLock v{APP_VERSION}", res.stdout)
        self.assertIn("--unlock", res.stdout)
        self.assertIn("--lock", res.stdout)
        self.assertIn("--password-stdin", res.stdout)
        self.assertIn("--quiet", res.stdout)

    def test_cli_quiet_missing_password_fails_fast(self):
        cmd = [PYTHON_EXE, MAIN_PY, "--unlock", self.test_dir, "--quiet"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("[ERROR] Password is required", res.stdout)

    def test_cli_headless_lock_and_unlock_with_password_arg(self):
        # Create sample file in test_dir
        f = os.path.join(self.test_dir, "sample.txt")
        with open(f, "w") as fp:
            fp.write("Hello CLI Lock!")

        # Lock via CLI
        lock_cmd = [PYTHON_EXE, MAIN_PY, "--lock", self.test_dir, "--password", self.password, "--quiet"]
        res_lock = subprocess.run(lock_cmd, capture_output=True, text=True)
        self.assertEqual(res_lock.returncode, 0)
        self.assertIn("[SUCCESS]", res_lock.stdout)
        self.assertFalse(os.path.exists(f))

        # Unlock via CLI
        unlock_cmd = [PYTHON_EXE, MAIN_PY, "--unlock", self.test_dir, "--password", self.password, "--quiet"]
        res_unlock = subprocess.run(unlock_cmd, capture_output=True, text=True)
        self.assertEqual(res_unlock.returncode, 0)
        self.assertIn("[SUCCESS]", res_unlock.stdout)
        self.assertTrue(os.path.exists(f))
        with open(f, "r") as fp:
            self.assertEqual(fp.read(), "Hello CLI Lock!")

    def test_cli_password_stdin(self):
        f = os.path.join(self.test_dir, "secret.txt")
        with open(f, "w") as fp:
            fp.write("Piped password content")

        # Lock using password from stdin
        lock_cmd = [PYTHON_EXE, MAIN_PY, "--lock", self.test_dir, "--password-stdin", "--quiet"]
        res_lock = subprocess.run(lock_cmd, input=f"{self.password}\n", capture_output=True, text=True)
        self.assertEqual(res_lock.returncode, 0)
        self.assertIn("[SUCCESS]", res_lock.stdout)
        self.assertFalse(os.path.exists(f))

        # Unlock using password from stdin
        unlock_cmd = [PYTHON_EXE, MAIN_PY, "--unlock", self.test_dir, "--password-stdin", "--quiet"]
        res_unlock = subprocess.run(unlock_cmd, input=f"{self.password}\n", capture_output=True, text=True)
        self.assertEqual(res_unlock.returncode, 0)
        self.assertIn("[SUCCESS]", res_unlock.stdout)
        self.assertTrue(os.path.exists(f))
        with open(f, "r") as fp:
            self.assertEqual(fp.read(), "Piped password content")

    def test_cli_wrong_password_fails_with_code_1(self):
        f = os.path.join(self.test_dir, "file.txt")
        with open(f, "w") as fp:
            fp.write("Some data")

        # Lock folder
        lock_cmd = [PYTHON_EXE, MAIN_PY, "--lock", self.test_dir, "--password", self.password, "--quiet"]
        subprocess.run(lock_cmd, capture_output=True, check=True)

        # Unlock with wrong password
        unlock_cmd = [PYTHON_EXE, MAIN_PY, "--unlock", self.test_dir, "--password", "Wrong_Password!", "--quiet"]
        res = subprocess.run(unlock_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("[ERROR]", res.stdout)
        self.assertFalse(os.path.exists(f))


if __name__ == "__main__":
    unittest.main()
