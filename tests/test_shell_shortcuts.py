"""Isolated native Windows Shell Link tests. No existing user folders."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from shell_shortcuts import create_prototype, inspect_prototype


@unittest.skipUnless(os.name == 'nt', 'Windows COM required')
class ShellLinkPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fl105_link_poc_')
        self.addCleanup(self.temp.cleanup)
        self.folder = os.path.join(self.temp.name, 'Turkce Folder With Spaces')
        os.mkdir(self.folder)
        self.executable = os.path.abspath(sys.executable)

    def test_native_com_lock_unlock_shortcuts(self):
        for action in ('lock', 'unlock'):
            self.assertTrue(create_prototype(self.folder, self.executable, action))
            link_path = os.path.join(self.folder, f'FolderLock - {action.title()}.lnk')
            self.assertTrue(os.path.isfile(link_path))
            target, args, working_directory = inspect_prototype(link_path)
            self.assertEqual(os.path.normcase(os.path.normpath(target)),
                             os.path.normcase(os.path.normpath(self.executable)))
            self.assertEqual(args, subprocess.list2cmdline([f'--{action}', self.folder]))
            self.assertEqual(os.path.normcase(os.path.normpath(working_directory)),
                             os.path.normcase(os.path.normpath(self.folder)))

    def test_existing_user_shortcut_never_overwritten(self):
        path = os.path.join(self.folder, 'FolderLock - Unlock.lnk')
        original = b'SYNTHETIC USER BYTES - NOT A SHORTCUT'
        with open(path, 'wb') as stream:
            stream.write(original)
        self.assertFalse(create_prototype(self.folder, self.executable, 'unlock'))
        with open(path, 'rb') as stream:
            self.assertEqual(stream.read(), original)

    def test_repeat_creation_does_not_overwrite_existing_shortcut(self):
        self.assertTrue(create_prototype(self.folder, self.executable, 'lock'))
        path = os.path.join(self.folder, 'FolderLock - Lock.lnk')
        with open(path, 'rb') as stream:
            original = stream.read()
        self.assertFalse(create_prototype(self.folder, self.executable, 'lock'))
        with open(path, 'rb') as stream:
            self.assertEqual(stream.read(), original)

    def test_invalid_action_fails_without_creation(self):
        with self.assertRaises(ValueError):
            create_prototype(self.folder, self.executable, 'delete')
        self.assertEqual(os.listdir(self.folder), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
