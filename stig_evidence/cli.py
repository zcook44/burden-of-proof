"""Offline STIG evidence release; no lab operations.
"""
import argparse
import ctypes
import errno
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import re
import secrets
import tempfile

from .policy import PolicyError, X, _xml, load_policy, generate_tailoring
from .cklb import EvidenceError, generate_cklb


class ReleaseError(ValueError):
    """Evidence/approval gate failure; nothing was published."""


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_approvals(exceptions, policy, benchmark, ledger, signature, trusted_key):
    """Check detached signature and bind every exception to exact policy/benchmark.

    Trust in the public key's owner must be established out of band by the ISSO.
    """
    try:
        ledger_bytes = Path(ledger).read_bytes()
        # OpenSSL requires paths for the signature and key; pin their exact bytes
        # in a private directory so a later replacement of either path is inert.
        with tempfile.TemporaryDirectory(prefix='stig-evidence-approval-') as td:
            key_copy = Path(td) / 'trusted.pub'
            signature_copy = Path(td) / 'approval.sig'
            _create_private(key_copy, Path(trusted_key).read_bytes())
            _create_private(signature_copy, Path(signature).read_bytes())
            result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(key_copy),
                                     '-signature', str(signature_copy)],
                                    input=ledger_bytes, capture_output=True, timeout=20)
        if result.returncode or result.stdout.strip() != b'Verified OK':
            raise ReleaseError('approval ledger signature failed verification')
        data = json.loads(ledger_bytes.decode('utf-8'))
        if (data.get('schema') != 1 or data.get('policy_sha256') != digest_file(policy)
                or data.get('benchmark_sha256') != digest_file(benchmark)):
            raise ReleaseError('signed ledger is not bound to the exact policy and benchmark files')
        entries = data.get('approvals')
        if not isinstance(entries, list):
            raise ReleaseError('signed approval list missing')
        indexed = {}
        for entry in entries:
            identifier = entry.get('approval_id')
            if not identifier or identifier in indexed:
                raise ReleaseError('missing or duplicate approval ID')
            indexed[identifier] = entry
        for item in exceptions:
            entry = indexed.get(item['approval_id'])
            if entry is None or any(entry.get(k) != item[k] for k in ('rule_id', 'approver', 'disposition', 'expires')):
                raise ReleaseError('signed approval does not match policy exception')
        return hashlib.sha256(ledger_bytes).hexdigest()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, KeyError, TypeError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError('approval verification could not complete') from exc


def _create_private(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def _write_evidence_file(directory_fd, name, data):
    """Write and hash through the pinned bundle directory, without path re-resolution."""
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, 'w+b') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


_RELEASE_INPUTS = ('policy', 'benchmark', 'pre', 'post', 'coverage', 'tailoring',
                   'schema', 'asset', 'approval_ledger', 'approval_signature', 'trusted_key')


def _snapshot_inputs(args, directory):
    """Capture release inputs once in an owner-only directory before any gates."""
    paths = {}
    for name in _RELEASE_INPUTS:
        source = getattr(args, name)
        try:
            fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            with os.fdopen(fd, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ReleaseError('invalid release input')
                content = stream.read()
            target = Path(directory) / (name + source.suffix)
            _create_private(target, content)
            paths[name] = target
        except OSError as exc:
            raise ReleaseError('unable to snapshot release input') from exc
    return paths


def _same_inode(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _rename_noreplace(parent_fd, staging, destination):
    """Publish atomically without replacing a file, directory, or symlink (Linux)."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, 'renameat2', None)
    if renameat2 is None:
        raise ReleaseError('atomic no-overwrite publication is unavailable')
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(staging), parent_fd,
                 os.fsencode(destination), 1) != 0:  # RENAME_NOREPLACE
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise ReleaseError('evidence destination exists: choose a new run directory')
        raise OSError(error, os.strerror(error))


def _verify_parent(root, parent_fd):
    """Reject a moved/replaced parent before publication and before return."""
    try:
        current_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not _same_inode(os.fstat(parent_fd), os.fstat(current_fd)):
                raise ReleaseError('evidence parent was replaced')
        finally:
            os.close(current_fd)
    except OSError as exc:
        raise ReleaseError('evidence parent path was replaced') from exc


def write_evidence(destination, host, cklb, inputs, metadata):
    """Stage through pinned descriptors, then atomically publish without overwrite."""
    root = Path(destination)
    if root.name in ('.', '..', '') or not host or '/' in host or host in ('.', '..') or not all(c.isalnum() or c in '-._' for c in host):
        raise ReleaseError('invalid asset hostname or evidence destination')
    sources = {}
    for name, source in sorted(inputs.items()):
        path = Path(source)
        if not name.isidentifier() or not path.is_file() or path.is_symlink():
            raise ReleaseError('invalid evidence source')
        sources[name] = (path.suffix, path.read_bytes())
    try:
        parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ReleaseError('evidence parent must exist and not be a symlink') from exc
    with ExitStack() as stack:
        stack.callback(os.close, parent_fd)
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise ReleaseError('evidence parent must be owner-only (0700) and owned by this user')
        _verify_parent(root, parent_fd)
        # Random name in an owner-only parent. Keep partial stage on any failure.
        staging = '.stig-evidence-' + secrets.token_hex(16)
        os.mkdir(staging, mode=0o700, dir_fd=parent_fd)
        stage_info = os.stat(staging, dir_fd=parent_fd, follow_symlinks=False)
        bundle_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
        stack.callback(os.close, bundle_fd)
        if (not _same_inode(stage_info, os.fstat(bundle_fd)) or not stat.S_ISDIR(stage_info.st_mode)
                or stage_info.st_uid != os.geteuid() or stat.S_IMODE(stage_info.st_mode) != 0o700):
            raise ReleaseError('evidence staging directory was replaced or is not owner-only')
        records = {}
        for name, (suffix, content) in sources.items():
            filename = name + suffix
            records[name] = {'file': filename,
                             'sha256': _write_evidence_file(bundle_fd, filename, content)}
        checklist = root / (host + '.cklb')
        checklist_sha = _write_evidence_file(bundle_fd, checklist.name,
            (json.dumps(cklb, indent=2, sort_keys=True) + '\n').encode())
        manifest = {'host': host, 'cklb': {'file': checklist.name, 'sha256': checklist_sha},
                    'inputs': records, 'metadata': metadata,
                    'created_utc': datetime.now(timezone.utc).isoformat(),
                    'review_state': 'pending ISSO STIG Viewer import and signed per-asset acceptance'}
        _write_evidence_file(bundle_fd, 'manifest.json',
                             (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        if not _same_inode(os.fstat(bundle_fd), os.stat(staging, dir_fd=parent_fd,
                                                     follow_symlinks=False)):
            raise ReleaseError('evidence staging directory was replaced')
        _verify_parent(root, parent_fd)
        _rename_noreplace(parent_fd, staging, root.name)
        _verify_parent(root, parent_fd)
        try:
            if not _same_inode(os.fstat(bundle_fd), os.stat(root, follow_symlinks=False)):
                raise ReleaseError('published evidence path was replaced')
            if not _same_inode(os.stat(checklist.name, dir_fd=bundle_fd,
                                       follow_symlinks=False), os.stat(checklist, follow_symlinks=False)):
                raise ReleaseError('published checklist path was replaced')
        except OSError as exc:
            raise ReleaseError('published evidence path is unavailable') from exc
        return checklist


_ASSET_FIELDS = frozenset({'schema_version', 'cycle_id', 'asset_fqdn', 'os_release',
                           'role', 'baseline_state', 'baseline_sha256',
                           'pre_scan_sha256', 'lab_commit'})


def validate_asset_record(asset_path, host, pre_path):
    """Validate the v1 handoff against the *snapshotted* pre-scan input."""
    def unique_pairs(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ReleaseError('duplicate asset record field')
            data[key] = value
        return data

    try:
        record = json.loads(Path(asset_path).read_bytes().decode('utf-8'),
                            object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseError('invalid asset record JSON') from exc
    if not isinstance(record, dict) or record.keys() != _ASSET_FIELDS or type(record['schema_version']) is not int or record['schema_version'] != 1:
        raise ReleaseError('invalid asset record schema_version or fields')
    if (not isinstance(record['cycle_id'], str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', record['cycle_id'])):
        raise ReleaseError('invalid cycle_id')
    fqdn = record['asset_fqdn']
    if (not isinstance(fqdn, str) or not re.fullmatch(
            r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+', fqdn)
            or fqdn != host):
        raise ReleaseError('asset_fqdn must match exact --host FQDN')
    if not isinstance(record['os_release'], str) or not record['os_release'].strip():
        raise ReleaseError('invalid os_release')
    if record['role'] not in ('node', 'gui', 'controller') or type(record['role']) is not str:
        raise ReleaseError('invalid role')
    if record['baseline_state'] != 'clean' or type(record['baseline_state']) is not str:
        raise ReleaseError('baseline_state must be clean')
    for key, length in (('baseline_sha256', 64), ('pre_scan_sha256', 64), ('lab_commit', 40)):
        value = record[key]
        if type(value) is not str or not re.fullmatch(r'[0-9a-f]{' + str(length) + r'}', value):
            raise ReleaseError('invalid ' + key)
    if record['pre_scan_sha256'] != digest_file(pre_path):
        raise ReleaseError('pre_scan_sha256 differs from snapshotted pre-scan')
    return record


def _release_cklb(args, paths):
    """Validate and publish from the same private snapshot, not mutable sources."""
    policy = load_policy(paths['policy'])
    validate_asset_record(paths['asset'], args.host, paths['pre'])
    signed = verify_approvals(policy.get('exceptions', []), paths['policy'], paths['benchmark'],
                              paths['approval_ledger'], paths['approval_signature'], paths['trusted_key'])
    tailoring_root = _xml(paths['tailoring'])
    hrefs = tailoring_root.findall(f'{{{X}}}benchmark')
    href = hrefs[0].get('href') if len(hrefs) == 1 else None
    if not href or Path(href).name != args.benchmark.name:
        raise ReleaseError('tailoring benchmark reference differs from pinned input')
    from xml.etree import ElementTree as ET
    expected = _xml(generate_tailoring(policy, paths['benchmark'], href))
    if ET.canonicalize(ET.tostring(tailoring_root, encoding='unicode'), strip_text=True) != ET.canonicalize(ET.tostring(expected, encoding='unicode'), strip_text=True):
        raise ReleaseError('tailoring differs from master policy')
    # The untailored coverage scan determines every rule; a tailored post-scan
    # remains separately retained for comparison and human review.
    doc = generate_cklb(policy, paths['benchmark'], paths['coverage'], args.host,
                        require_full_coverage=True, scan_profile=policy['profile_id'],
                        schema_path=paths['schema'])
    generate_cklb(policy, paths['benchmark'], paths['pre'], args.host,
                  require_full_coverage=True, scan_profile=policy['profile_id'],
                  max_age_hours=72)
    generate_cklb(policy, paths['benchmark'], paths['post'], args.host)
    post_root = _xml(paths['post'])
    post_result = post_root.find(f'{{{X}}}TestResult')
    if post_result is None:
        raise ReleaseError('tailored post-scan has no TestResult')
    def raw_results(result):
        return {item.get('idref'): item.find(f'{{{X}}}result').text.strip()
                for item in result.findall(f'{{{X}}}rule-result')}
    post_raw = raw_results(post_result)
    coverage_result = _xml(paths['coverage']).find(f'{{{X}}}TestResult')
    coverage_raw = raw_results(coverage_result)
    post_ids = set(post_raw)
    coverage_rules = {r['rule_id_src'] for r in doc['stigs'][0]['rules']}
    required_post = {rid for rid in coverage_rules if policy.get('selections', {}).get(rid) is not False}
    if required_post - post_ids:
        raise ReleaseError('selected post-scan rule missing: ' + ', '.join(sorted(required_post - post_ids)))
    for rid in required_post:
        if coverage_raw[rid] != post_raw[rid]:
            raise ReleaseError('tailored post-scan disagrees with coverage scan: ' + rid)
    def scan_end(path):
        result = _xml(path).find(f'{{{X}}}TestResult')
        if result is None:
            raise ReleaseError('scan has no TestResult')
        return datetime.fromisoformat(result.attrib['end-time'].replace('Z', '+00:00'))
    if not scan_end(paths['pre']) < scan_end(paths['post']) <= scan_end(paths['coverage']):
        raise ReleaseError('scan chronology must be pre < post <= coverage')
    metadata = {'approval_ledger_sha256': signed, 'schema_sha256': digest_file(paths['schema']),
                'trusted_key_sha256': digest_file(paths['trusted_key']),
                'asset_sha256': digest_file(paths['asset']),
                'review_state': 'unsigned: pending independent ISSO signoff'}
    return write_evidence(args.evidence_dir, args.host, doc, paths, metadata)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline STIG evidence release')
    sub = parser.add_subparsers(dest='command', required=True)
    tailor = sub.add_parser('tailor')
    for arg in ('policy', 'benchmark', 'out'):
        tailor.add_argument('--' + arg, type=Path, required=True)
    tailor.add_argument('--benchmark-href', required=True)
    evidence = sub.add_parser('cklb')
    for arg in ('policy', 'benchmark', 'pre', 'post', 'coverage', 'tailoring', 'schema', 'asset',
                'approval-ledger', 'approval-signature', 'trusted-key', 'evidence-dir', 'host'):
        evidence.add_argument('--' + arg, required=True, type=str if arg == 'host' else Path)
    try:
        args = parser.parse_args(argv)
        if args.command == 'tailor':
            xml = generate_tailoring(load_policy(args.policy), args.benchmark, args.benchmark_href)
            _create_private(args.out, xml.encode())
            print(args.out)
        else:
            with tempfile.TemporaryDirectory(prefix='stig-evidence-input-') as td:
                paths = _snapshot_inputs(args, td)
                print(_release_cklb(args, paths))
        return 0
    except (ReleaseError, PolicyError, EvidenceError, OSError, ValueError,
            subprocess.SubprocessError) as exc:
        print(f'stig-evidence: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
