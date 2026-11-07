"""Synthetic asset provenance contract tests (no lab access)."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from stig_evidence.cli import ReleaseError, validate_asset_record


class AssetContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pre = Path(self.temp.name) / 'pre.xml'
        self.pre.write_bytes(b'<synthetic-scan/>')
        self.record = dict(schema_version=1, cycle_id='2026-q4', asset_fqdn='node.example.test',
                           os_release='rhel9', role='node', baseline_state='clean',
                           baseline_sha256='a' * 64,
                           pre_scan_sha256=hashlib.sha256(self.pre.read_bytes()).hexdigest(),
                           lab_commit='b' * 40)
        self.asset = Path(self.temp.name) / 'asset.json'

    def check(self, record=None, host='node.example.test'):
        self.asset.write_text(json.dumps(self.record if record is None else record))
        return validate_asset_record(self.asset, host, self.pre)

    def test_valid_record(self):
        self.assertEqual(self.check(), self.record)

    def test_fqdn_must_match_exact_host(self):
        with self.assertRaisesRegex(ReleaseError, 'asset_fqdn'):
            self.check(host='other.example.test')
        with self.assertRaisesRegex(ReleaseError, 'asset_fqdn'):
            self.check(host='NODE.EXAMPLE.TEST')

    def test_schema_version_and_keys_fail_closed(self):
        for change in ({'schema_version': 2}, {'schema_version': True}, {'extra': 'bad'}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                self.check({**self.record, **change})
        incomplete = dict(self.record)
        del incomplete['cycle_id']
        with self.assertRaises(ReleaseError):
            self.check(incomplete)

    def test_state_role_identifiers_and_types(self):
        for change in ({'baseline_state': 'dirty'}, {'role': 'other'},
                       {'cycle_id': ''}, {'cycle_id': '../bad'}, {'os_release': 9},
                       {'asset_fqdn': 'not-an-fqdn'}, {'lab_commit': 'B' * 40},
                       {'baseline_sha256': 'A' * 64}, {'pre_scan_sha256': '0' * 63}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                self.check({**self.record, **change})

    def test_pre_scan_hash_must_match_snapshotted_bytes(self):
        self.pre.write_bytes(b'<different/>')
        with self.assertRaisesRegex(ReleaseError, 'pre_scan_sha256'):
            self.check()

    def test_invalid_json_and_duplicate_fields(self):
        self.asset.write_text('{')
        with self.assertRaises(ReleaseError):
            validate_asset_record(self.asset, 'node.example.test', self.pre)
        self.asset.write_text(json.dumps(self.record)[:-1] + ', "role": "gui"}')
        with self.assertRaises(ReleaseError):
            validate_asset_record(self.asset, 'node.example.test', self.pre)


if __name__ == '__main__':
    unittest.main()
