"""Operator entry point, signed approval and protected evidence tests."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stig_evidence import cli


class EvidenceCLITests(unittest.TestCase):
    def test_tailor_cli_creates_private_output_without_overwrite(self):
        from test_cklb import BENCHMARK, policy
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / 'policy.json'; p.write_text(json.dumps(policy()))
            bench = root / 'benchmark.xml'; bench.write_text(BENCHMARK)
            out = root / 'tailoring.xml'
            args = ['tailor', '--policy', str(p), '--benchmark', str(bench),
                    '--benchmark-href', bench.name, '--out', str(out)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args), 0)
            self.assertIn('Tailoring', out.read_text())
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(args), 2)

    def test_signed_approval_binds_exact_policy_and_benchmark(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / 'policy.json'; benchmark = root / 'bench.xml'
            policy.write_text('{"policy_version":1}')
            benchmark.write_text('<Benchmark/>')
            ledger = root / 'ledger.json'; sig = root / 'ledger.sig'; key = root / 'private.pem'; pub = root / 'trusted.pub'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(pub)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            doc = {'schema': 1, 'policy_sha256': cli.digest_file(policy), 'benchmark_sha256': cli.digest_file(benchmark), 'approvals': [{'approval_id': 'A-1', 'rule_id': 'rule-1', 'approver': 'ISSO', 'disposition': 'documented_only', 'expires': '2030-01-01'}]}
            ledger.write_text(json.dumps(doc))
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-out', str(sig), str(ledger)], check=True)
            exceptions = [{'approval_id': 'A-1', 'rule_id': 'rule-1', 'approver': 'ISSO', 'disposition': 'documented_only', 'expires': '2030-01-01'}]
            self.assertEqual(cli.verify_approvals(exceptions, policy, benchmark, ledger, sig, pub), cli.digest_file(ledger))
            policy.write_text('{"policy_version":2}')
            with self.assertRaises(cli.ReleaseError):
                cli.verify_approvals(exceptions, policy, benchmark, ledger, sig, pub)
            policy.write_text('{"policy_version":1}')
            ledger.write_text(ledger.read_text() + ' ')
            with self.assertRaises(cli.ReleaseError):
                cli.verify_approvals(exceptions, policy, benchmark, ledger, sig, pub)

    def test_ledger_swap_after_openssl_does_not_authorize_unsigned_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy = root / 'policy.json'; benchmark = root / 'bench.xml'
            policy.write_text('{}'); benchmark.write_text('<Benchmark/>')
            ledger = root / 'ledger.json'; sig = root / 'ledger.sig'
            private = root / 'private.pem'; public = root / 'trusted.pub'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            bound = {'schema': 1, 'policy_sha256': cli.digest_file(policy), 'benchmark_sha256': cli.digest_file(benchmark), 'approvals': []}
            ledger.write_text(json.dumps(bound))
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private), '-out', str(sig), str(ledger)], check=True)
            real_run = subprocess.run

            def swap_after_verify(*args, **kwargs):
                result = real_run(*args, **kwargs)
                ledger.write_text(json.dumps(bound, indent=2))  # valid JSON, not signed bytes
                return result

            with patch.object(cli.subprocess, 'run', side_effect=swap_after_verify):
                verified = cli.verify_approvals([], policy, benchmark, ledger, sig, public)
            self.assertEqual(verified, hashlib.sha256(json.dumps(bound).encode()).hexdigest())
            self.assertNotEqual(verified, cli.digest_file(ledger))

    def test_signed_full_coverage_release_and_missing_rule_rejected(self):
        from test_cklb import BENCHMARK, SCAN, policy
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            host = 'node.example.test'
            now = datetime.now(timezone.utc)
            started = (now - timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
            ended = (now - timedelta(minutes=4)).isoformat().replace('+00:00', 'Z')
            source = (SCAN.replace('host1', host)
                      .replace('2026-11-06T15:00:00Z', started)
                      .replace('2026-11-06T15:03:00Z', ended)
                      .replace('</TestResult>', '<rule-result idref="xccdf_mil.disa.stig_rule_SV-4"><result>notchecked</result></rule-result></TestResult>'))
            full = source.replace('idref="quarterly-profile"', 'idref="xccdf_mil.disa.stig_profile_MAC-2"')
            paths = {name: root / (name + '.xml') for name in ('benchmark', 'pre', 'post', 'coverage', 'tailoring')}
            paths['benchmark'].write_text(BENCHMARK)
            for name in ('post',):
                paths[name].write_text(source)
            from stig_evidence.policy import generate_tailoring
            paths['tailoring'].write_text(generate_tailoring(policy(), BENCHMARK, 'benchmark.xml'))
            paths['coverage'].write_text(full)
            pre = full.replace(started, (now - timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')).replace(ended, (now - timedelta(minutes=9)).isoformat().replace('+00:00', 'Z'))
            paths['pre'].write_text(pre)
            p = root / 'policy.json'; p.write_text(json.dumps(policy()))
            schema = Path(os.environ.get('STIG_EVIDENCE_SCHEMA', '/nonexistent/cklb-schema.json'))
            if not schema.is_file():
                self.skipTest('official DISA CKLB schema must be supplied outside the repository')
            from stig_evidence.cklb import OFFICIAL_CKLB_SCHEMA_SHA256
            self.assertEqual(cli.digest_file(schema), OFFICIAL_CKLB_SCHEMA_SHA256)
            key = root / 'private.pem'; pub = root / 'trusted.pub'; sig = root / 'ledger.sig'; ledger = root / 'ledger.json'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(pub)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ledger.write_text(json.dumps({'schema':1, 'policy_sha256':cli.digest_file(p), 'benchmark_sha256':cli.digest_file(paths['benchmark']),
                                     'approvals':[{k:item[k] for k in ('approval_id','rule_id','approver','disposition','expires')} for item in policy()['exceptions']]}))
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-out', str(sig), str(ledger)], check=True)
            out = root / 'run-01'
            asset = root / 'asset.json'
            asset.write_text(json.dumps({'schema_version': 1, 'cycle_id': 'cycle-2026-q4', 'asset_fqdn': host, 'os_release': 'rhel9', 'role': 'node', 'baseline_state': 'clean', 'baseline_sha256': 'a' * 64, 'pre_scan_sha256': cli.digest_file(paths['pre']), 'lab_commit': 'b' * 40}))
            args = ['cklb', '--asset', str(asset), '--policy', str(p), '--benchmark', str(paths['benchmark']), '--pre', str(paths['pre']),
                    '--post', str(paths['post']), '--coverage', str(paths['coverage']), '--tailoring', str(paths['tailoring']),
                    '--schema', str(schema), '--approval-ledger', str(ledger), '--approval-signature', str(sig),
                    '--trusted-key', str(pub), '--evidence-dir', str(out), '--host', host]
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args), 0)
            self.assertEqual(json.loads((out / (host + '.cklb')).read_text())['stigs'][0]['size'], 4)
            manifest = json.loads((out / 'manifest.json').read_text())
            retained = {'policy': p, **paths, 'schema': schema, 'approval_ledger': ledger,
                        'approval_signature': sig, 'trusted_key': pub, 'asset': asset}
            self.assertEqual(set(manifest['inputs']), set(retained))
            for name, original in retained.items():
                with self.subTest(retained=name):
                    copy = out / manifest['inputs'][name]['file']
                    self.assertEqual(copy.read_bytes(), original.read_bytes())
                    self.assertEqual(manifest['inputs'][name]['sha256'], cli.digest_file(copy))
                    self.assertEqual(copy.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest['metadata']['asset_sha256'], cli.digest_file(asset))
            good_record = json.loads(asset.read_text())
            for label, change in (('fqdn', {'asset_fqdn': 'other.example.test'}),
                                  ('schema', {'schema_version': 2}),
                                  ('state', {'baseline_state': 'dirty'}),
                                  ('hash', {'pre_scan_sha256': '0' * 64})):
                with self.subTest(asset_rejection=label):
                    asset.write_text(json.dumps({**good_record, **change}))
                    rejected = root / ('rejected-' + label)
                    argv = args[:args.index('--evidence-dir')] + ['--evidence-dir', str(rejected), '--host', host]
                    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(cli.main(argv), 2)
                    self.assertFalse(rejected.exists())
            asset.write_text(json.dumps(good_record))
            self.assertFalse(any('PRIVATE KEY' in f.read_text(errors='ignore') for f in out.iterdir()))
            original_asset = asset.read_bytes()
            original_pre = paths['pre'].read_bytes()
            real_snapshot = cli._snapshot_inputs
            def change_sources_immediately_after_snapshot(snapshot_args, directory):
                snapshots = real_snapshot(snapshot_args, directory)
                paths['pre'].write_text('changed before validation')
                asset.write_text('{}')
                return snapshots
            early_out = root / 'run-early-swap'
            with patch.object(cli, '_snapshot_inputs', side_effect=change_sources_immediately_after_snapshot), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(early_out), '--host', host]), 0)
            early_manifest = json.loads((early_out / 'manifest.json').read_text())
            self.assertEqual((early_out / early_manifest['inputs']['pre']['file']).read_bytes(), original_pre)
            self.assertEqual((early_out / early_manifest['inputs']['asset']['file']).read_bytes(), original_asset)
            paths['pre'].write_bytes(original_pre)
            asset.write_bytes(original_asset)
            original_coverage = paths['coverage'].read_bytes()
            original_ledger = ledger.read_bytes()
            real_verify = cli.verify_approvals

            def replace_sources_after_snapshot(*verify_args):
                result = real_verify(*verify_args)
                paths['coverage'].write_text('replaced after snapshot')
                paths['pre'].write_text('replaced after snapshot')
                asset.write_text('{}')
                ledger.write_text('replaced after snapshot')
                return result

            snapshot_out = root / 'run-snapshot'
            with patch.object(cli, 'verify_approvals', side_effect=replace_sources_after_snapshot), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(snapshot_out), '--host', host]), 0)
            snapshot_manifest = json.loads((snapshot_out / 'manifest.json').read_text())
            self.assertEqual((snapshot_out / snapshot_manifest['inputs']['coverage']['file']).read_bytes(), original_coverage)
            self.assertEqual((snapshot_out / snapshot_manifest['inputs']['approval_ledger']['file']).read_bytes(), original_ledger)
            self.assertEqual((snapshot_out / snapshot_manifest['inputs']['asset']['file']).read_bytes(), original_asset)
            self.assertEqual((snapshot_out / snapshot_manifest['inputs']['pre']['file']).read_bytes(), original_pre)
            self.assertEqual(snapshot_manifest['metadata']['asset_sha256'], hashlib.sha256(original_asset).hexdigest())
            paths['pre'].write_bytes(original_pre)
            asset.write_bytes(original_asset)
            paths['coverage'].write_bytes(original_coverage)
            ledger.write_bytes(original_ledger)
            ledger.write_bytes(original_ledger + b' ')
            real_snapshot = cli._snapshot_inputs
            captured_snapshots = []

            def capture_snapshot(snapshot_args, directory):
                captured_snapshots.append(Path(directory))
                self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)
                return real_snapshot(snapshot_args, directory)

            with patch.object(cli, '_snapshot_inputs', side_effect=capture_snapshot), \
                    contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-bad-signature'), '--host', host]), 2)
            self.assertFalse((root / 'run-bad-signature').exists())
            self.assertEqual(len(captured_snapshots), 1)
            self.assertFalse(captured_snapshots[0].exists())
            ledger.write_bytes(original_ledger)
            paths['coverage'].write_text(full.replace('<rule-result idref="xccdf_mil.disa.stig_rule_SV-4"><result>notchecked</result></rule-result>', ''))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-02'), '--host', host]), 2)
            self.assertFalse((root / 'run-02').exists())
            paths['coverage'].write_text(full)
            paths['pre'].write_text(pre.replace(host, 'wrong-target'))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-03'), '--host', host]), 2)
            self.assertFalse((root / 'run-03').exists())
            paths['pre'].write_text(pre)
            paths['tailoring'].write_text(paths['tailoring'].read_text().replace('quarterly-profile', 'tampered-profile'))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-04'), '--host', host]), 2)
            self.assertFalse((root / 'run-04').exists())
            from stig_evidence.policy import generate_tailoring
            paths['tailoring'].write_text(generate_tailoring(policy(), BENCHMARK, 'benchmark.xml'))
            paths['post'].write_text(source.replace('<result>pass</result>', '<result>fail</result>'))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-05'), '--host', host]), 2)
            self.assertFalse((root / 'run-05').exists())
            paths['post'].write_text(source.replace('<rule-result idref="xccdf_mil.disa.stig_rule_SV-2"><result>pass</result></rule-result>', ''))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-06'), '--host', host]), 2)
            self.assertFalse((root / 'run-06').exists())
            paths['post'].write_text(source.replace('<result>pass</result>', '<result>unknown</result>'))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-07'), '--host', host]), 2)
            self.assertFalse((root / 'run-07').exists())
            # Both values map to CKLB not_reviewed, but the raw scans disagree.
            paths['post'].write_text(source.replace('<result>notchecked</result>', '<result>error</result>'))
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(args[:args.index('--evidence-dir')] + ['--evidence-dir', str(root / 'run-raw-mismatch'), '--host', host]), 2)
            self.assertFalse((root / 'run-raw-mismatch').exists())

    def test_bad_evidence_source_never_creates_final_run_directory(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td)
            valid = parent / 'valid.xml'; valid.write_text('safe')
            target = parent / 'run'
            with self.assertRaises(cli.ReleaseError):
                cli.write_evidence(target, 'host1', {'cklb_version': '1.0'},
                                   {'valid': valid, 'missing': parent / 'absent.xml'}, {})
            self.assertFalse(target.exists())

    def test_evidence_bundle_is_private_immutable_and_hashes_copied_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inputs = {}
            for name in ('policy', 'benchmark', 'pre', 'post', 'coverage', 'tailoring'):
                p = root / (name + '.xml'); p.write_text(name)
                inputs[name] = p
            evidence = root / 'evidence'
            cklb = {'cklb_version':'1.0', 'target_data': {'host_name':'host1'}}
            result = cli.write_evidence(evidence, 'host1', cklb, inputs, {'approval_ledger_sha256': 'a' * 64})
            self.assertEqual(result, evidence / 'host1.cklb')
            self.assertEqual(json.loads(result.read_text()), cklb)
            self.assertEqual((evidence.stat().st_mode & 0o777), 0o700)
            self.assertEqual((result.stat().st_mode & 0o777), 0o600)
            manifest = json.loads((evidence / 'manifest.json').read_text())
            self.assertEqual(manifest['host'], 'host1')
            self.assertEqual(manifest['inputs']['pre']['sha256'], cli.digest_file(inputs['pre']))
            with self.assertRaises(cli.ReleaseError):
                cli.write_evidence(evidence, 'host1', cklb, inputs, {})
            self.assertEqual(json.loads(result.read_text()), cklb)

    def test_symlink_evidence_parent_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / 'private'; parent.mkdir(mode=0o700)
            link = root / 'link'; link.symlink_to(parent, target_is_directory=True)
            source = root / 'source.xml'; source.write_text('safe')
            with self.assertRaises(cli.ReleaseError):
                cli.write_evidence(link / 'run', 'host1', {}, {'source': source}, {})
            self.assertFalse((parent / 'run').exists())

    def test_stage_replacement_before_open_cannot_redirect_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / 'source.xml'; source.write_text('safe')
            real_open = os.open
            def swap_stage(path, flags, *args, **kwargs):
                if str(path).startswith('.stig-evidence-') and kwargs.get('dir_fd') is not None:
                    (root / path).rename(root / 'displaced')
                    os.mkdir(path, mode=0o700, dir_fd=kwargs['dir_fd'])
                return real_open(path, flags, *args, **kwargs)
            with patch.object(cli.os, 'open', side_effect=swap_stage):
                with self.assertRaises(cli.ReleaseError):
                    cli.write_evidence(root / 'run', 'host1', {}, {'source': source}, {})
            self.assertFalse((root / 'run').exists())
            self.assertEqual(list((root / 'displaced').iterdir()), [])
            self.assertEqual(list(next(root.glob('.stig-evidence-*')).iterdir()), [])

    def test_parent_swap_before_publish_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / 'private'; parent.mkdir(mode=0o700)
            moved = root / 'moved'
            attacker = root / 'attacker'; attacker.mkdir(mode=0o700)
            source = root / 'source.xml'; source.write_text('safe')
            real_mkdir = os.mkdir
            def swap_parent(path, mode=0o777, *, dir_fd=None):
                result = real_mkdir(path, mode, dir_fd=dir_fd)
                if str(path).startswith('.stig-evidence-'):
                    parent.rename(moved)
                    parent.symlink_to(attacker, target_is_directory=True)
                return result
            with patch.object(cli.os, 'mkdir', side_effect=swap_parent):
                with self.assertRaises(cli.ReleaseError):
                    cli.write_evidence(parent / 'run', 'host1', {}, {'source': source}, {})
            self.assertFalse((moved / 'run').exists())
            self.assertEqual(list(attacker.iterdir()), [])

    def test_parent_swap_after_publish_cannot_return_stale_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / 'private'; parent.mkdir(mode=0o700)
            moved = root / 'moved'
            attacker = root / 'attacker'; attacker.mkdir(mode=0o700)
            source = root / 'source.xml'; source.write_text('safe')
            real_rename = cli._rename_noreplace
            def swap_after_publish(*args):
                real_rename(*args)
                parent.rename(moved)
                parent.symlink_to(attacker, target_is_directory=True)
            with patch.object(cli, '_rename_noreplace', side_effect=swap_after_publish):
                with self.assertRaises(cli.ReleaseError):
                    cli.write_evidence(parent / 'run', 'host1', {}, {'source': source}, {})
            self.assertTrue((moved / 'run' / 'host1.cklb').is_file())
            self.assertEqual(list(attacker.iterdir()), [])

    def test_collision_at_atomic_publish_preserves_existing_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / 'source.xml'; source.write_text('safe')
            existing = root / 'run'
            real_rename = cli._rename_noreplace
            def collide(parent_fd, staging, destination):
                existing.mkdir()
                (existing / 'sentinel').write_text('unchanged')
                return real_rename(parent_fd, staging, destination)
            with patch.object(cli, '_rename_noreplace', side_effect=collide):
                with self.assertRaises(cli.ReleaseError):
                    cli.write_evidence(existing, 'host1', {}, {'source': source}, {})
            self.assertEqual((existing / 'sentinel').read_text(), 'unchanged')
            self.assertEqual(list(existing.iterdir()), [existing / 'sentinel'])
            self.assertTrue(next(root.glob('.stig-evidence-*')).is_dir())

    def test_parent_must_be_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            parent = root / 'public'; parent.mkdir(mode=0o755)
            source = root / 'source.xml'; source.write_text('safe')
            with self.assertRaises(cli.ReleaseError):
                cli.write_evidence(parent / 'run', 'host1', {}, {'source': source}, {})
            self.assertEqual(list(parent.iterdir()), [])

    def test_final_symlink_collision_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / 'source.xml'; source.write_text('safe')
            existing = root / 'existing'; existing.mkdir()
            (root / 'run').symlink_to(existing, target_is_directory=True)
            with self.assertRaises(cli.ReleaseError):
                cli.write_evidence(root / 'run', 'host1', {}, {'source': source}, {})
            self.assertTrue((root / 'run').is_symlink())
            self.assertEqual(list(existing.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
