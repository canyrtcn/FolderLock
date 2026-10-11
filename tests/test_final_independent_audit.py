"""Independent safety tests for FolderLock-audit-final.zip.
All filesystem mutations target TemporaryDirectory fixtures, never user folders.
Some tests intentionally FAIL on the audited version; a pass requires safer behavior.
Run: FOLDERLOCK_REPO=<extracted_folder> python -m unittest -v FolderLock_final_independent_regressions.py
"""
import os,sys,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import crypto_engine as ce

class IndependentFinalAudit(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix='fl_final_audit_');self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name);self.protected=self.root/'protected';self.protected.mkdir()
        self.pwd='Synthetic-Only-Pass!'

    def test_root_metadata_named_user_file_must_be_protected_or_rejected(self):
        user_file=self.protected/'.flock_meta'
        original=b'IMPORTANT SYNTHETIC USER BYTES'
        user_file.write_bytes(original)
        (self.protected/'ordinary.txt').write_text('ordinary',encoding='utf-8')
        try:
            ce.lock_folder(str(self.protected),self.pwd)
        except Exception:
            self.assertEqual(user_file.read_bytes(),original)
            return # fail-closed before mutation is acceptable
        self.assertFalse(user_file.exists(),'AES locked successfully but left user .flock_meta in plaintext')
        ce.unlock_folder(str(self.protected),self.pwd)
        self.assertEqual(user_file.read_bytes(),original)

    def test_json_shaped_user_relock_file_must_not_be_deleted(self):
        p=self.protected/'.flock_relock'
        user_payload={'magic':'FLCK_RELOCK_V1','mode':'crypto','salt':'aa'*32,'hash':'','extra_user_field':'this is user data'}
        original=json.dumps(user_payload,sort_keys=True).encode('utf-8')
        p.write_bytes(original)
        (self.protected/'doc.txt').write_text('data',encoding='utf-8')
        try:
            ce.lock_folder(str(self.protected),self.pwd)
        except Exception:
            self.assertEqual(p.read_bytes(),original)
            return
        # Must not delete a user file merely because it matches an editable JSON schema.
        self.assertFalse(p.exists(),'User-controlled JSON was deleted as if application-owned relock metadata')
        ce.unlock_folder(str(self.protected),self.pwd)
        self.assertEqual(p.read_bytes(),original)

    def test_user_instruction_file_with_forgeable_marker_not_deleted(self):
        p=self.protected/ce.INSTRUCTION_FILENAME
        original=(ce.FOLDERLOCK_OWNERSHIP_TAG + "\nSYNTHETIC USER-CREATED NOTES").encode('utf-8')
        p.write_bytes(original)
        (self.protected/'doc.txt').write_text('doc',encoding='utf-8')
        try:
            ce.lock_folder(str(self.protected),self.pwd)
        except Exception:
            self.assertEqual(p.read_bytes(),original)
            return
        # Correct protection encrypts the user note (therefore it must be
        # absent in plaintext), then restores its exact bytes on unlock.
        self.assertFalse(p.exists(), 'User instruction must not remain plaintext after AES lock')
        ce.unlock_folder(str(self.protected),self.pwd)
        self.assertEqual(p.read_bytes(),original)

    def test_file_modified_between_hash_and_delete_must_survive(self):
        p=self.protected/'doc.txt'; p.write_text('BEFORE',encoding='utf-8')
        original=ce.TransactionJournal.record_pending_step
        fired=[False]
        def change_after_hash(self_,step):
            if step.get('action')=='CLEANUP_FILE' and not fired[0]:
                fired[0]=True
                p.write_text('AFTER!',encoding='utf-8') # same length, concurrent update
            return original(self_,step)
        with patch.object(ce.TransactionJournal,'record_pending_step',change_after_hash):
            try:
                ce.lock_folder(str(self.protected),self.pwd)
            except Exception:
                self.assertTrue(p.exists(),'Failed lock must preserve post-hash file update')
                self.assertEqual(p.read_text(encoding='utf-8'),'AFTER!')
                return
        self.assertTrue(fired[0])
        self.assertTrue(p.exists(),'Concurrent update was deleted after previous SHA256 verification')
        self.assertEqual(p.read_text(encoding='utf-8'),'AFTER!')

    def test_precommit_recovery_must_verify_source_before_removing_journal(self):
        source=self.protected/'document.txt' # Missing source after interrupted preparation
        journal=self.protected/'.flock_journal'
        j={'schema_version':'1.0.3','operation_id':'dead-op','operation_type':'aes_lock',
           'target_path':str(self.protected),'state':'ENCRYPTING',
           'source_manifest':[{'rel_path':'document.txt','size':8,'sha256':'aa'*32,'is_dir':False}],
           'temp_paths':[],'recovery_required':True}
        journal.write_text(json.dumps(j),encoding='utf-8')
        try:
            success,msg=ce.recover_aes_folder(str(self.protected),self.pwd)
        except Exception:
            self.assertTrue(journal.exists(),'Exception must not erase source recovery evidence')
            return
        self.assertFalse(success,'Recovery reported success though manifest source file is missing')
        self.assertTrue(journal.exists(),'Recovery discarded journal before verifying user files')

    def test_instant_root_metadata_collision_is_rejected_without_mutation(self):
        p = self.protected / '.flock_meta'
        payload = b'USER METADATA THAT MUST NOT BE OVERWRITTEN'
        p.write_bytes(payload)
        (self.protected / 'regular.txt').write_text('important', encoding='utf-8')
        with self.assertRaises(Exception):
            ce.lock_folder_instant(str(self.protected), self.pwd)
        self.assertEqual(p.read_bytes(), payload)
        self.assertFalse((self.protected / '.locked_data').exists())

    def test_instant_legacy_acl_fallback_requires_verified_password(self):
        with patch.object(ce,'run_icacls_safe',return_value=SimpleNamespace(stdout='EXAMPLE:(DENY)',returncode=0)), \
             patch.object(ce,'remove_hidden_system_attributes',return_value=None):
            try:
                result=ce.unlock_folder_instant(str(self.protected),'wrong-and-unverified')
            except Exception:
                return # Reject/exception acceptable
        self.assertFalse(result,'Legacy fallback returned True without salt/hash password proof')

if __name__=='__main__':unittest.main(verbosity=2)
