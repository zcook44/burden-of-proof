#!/usr/bin/env python3
"""Seed one private auto-only tailoring policy per official Cisco XCCDF benchmark.

Read a flat, owner-private extracted library. Do not copy benchmark check text or
make administrator review decisions. Existing policies are never replaced.
"""
import argparse
import hashlib
import os
import re
import stat
import sys
import xml.etree.ElementTree as ET
from xml.parsers import expat

NAMESPACE = "http://checklists.nist.gov/xccdf/1.1"
BENCHMARK = re.compile(r"Cisco_[A-Za-z0-9_-]+_STIG\Z")
STIG = re.compile(r"V-([0-9]+)\Z")
SV = re.compile(r"SV-([0-9]+)r[0-9]+_rule\Z")


def require_private(info, mode, kind, name):
    valid_type = stat.S_ISDIR(info.st_mode) if kind == "directory" else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError(f"{name}: expected owner-owned {mode:04o} {kind}")


def parse_benchmark(data, filename):
    # ElementTree expands internal entities; reject every DTD before it parses.
    parser = expat.ParserCreate()
    def forbidden(*_args):
        raise ValueError(f"{filename}: DTD/entity declarations forbidden")
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    try:
        parser.Parse(data, True)
        root = ET.fromstring(data)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError(f"{filename}: invalid XML: {exc}") from exc
    benchmark_id = root.get("id", "")
    if root.tag != f"{{{NAMESPACE}}}Benchmark" or not BENCHMARK.fullmatch(benchmark_id):
        raise ValueError(f"{filename}: expected Cisco XCCDF 1.1 Benchmark ID")
    group_tag = f"{{{NAMESPACE}}}Group"
    rule_tag = f"{{{NAMESPACE}}}Rule"
    parents = {child: parent for parent in root.iter() for child in parent}
    groups = []
    for node in root.iter():
        local = node.tag.rsplit("}", 1)[-1]
        if local not in ("Group", "Rule"):
            continue
        parent = parents.get(node)
        if node.tag == group_tag and parent is not None and parent.tag in (root.tag, group_tag):
            groups.append(node)
        elif node.tag == rule_tag and parent is not None and parent.tag == group_tag:
            pass
        else:
            raise ValueError(f"{filename}: foreign or misplaced XCCDF Group/Rule")
    if not groups:
        raise ValueError(f"{filename}: no controls")
    seen_stig, seen_sv, rules = set(), set(), []
    for group in groups:
        stig_id = group.get("id", "")
        match = STIG.fullmatch(stig_id)
        children = [child for child in group if child.tag == rule_tag]
        if match is None or stig_id in seen_stig or len(children) != 1:
            raise ValueError(f"{filename}: invalid/duplicate V ID or missing/multiple rules: {stig_id}")
        sv_id = children[0].get("id", "")
        rule_match = SV.fullmatch(sv_id)
        if rule_match is None or rule_match.group(1) != match.group(1) or sv_id in seen_sv:
            raise ValueError(f"{filename}: invalid/duplicate/mismatched SV ID: {sv_id}")
        seen_stig.add(stig_id)
        seen_sv.add(sv_id)
        rules.append((stig_id, sv_id))
    return benchmark_id, rules


def generate(root, dry_run):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require_private(os.fstat(fd), 0o700, "directory", root)
        names = sorted(entry.name for entry in os.scandir(fd))
        sources = [name for name in names if name.endswith(".xml")]
        if not sources:
            raise ValueError("library has no XML benchmarks")
        if any(stat.S_ISLNK(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode) for name in names):
            raise ValueError("symlink in Cisco library")
        if any(stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode) for name in names):
            raise ValueError("Cisco library must be flat; nested directories are not scanned")
        outputs = []
        benchmark_ids = set()
        total_rules = 0
        for name in sources:
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                info = os.fstat(source_fd)
                require_private(info, 0o600, "file", name)
                with os.fdopen(source_fd, "rb", closefd=False) as stream:
                    data = stream.read()
            finally:
                os.close(source_fd)
            benchmark_id, rules = parse_benchmark(data, name)
            if benchmark_id in benchmark_ids:
                raise ValueError(f"duplicate Cisco Benchmark ID: {benchmark_id}")
            benchmark_ids.add(benchmark_id)
            output = benchmark_id + ".tailoring.yaml"
            if output in names:
                raise ValueError(f"refusing to overwrite existing output: {output}")
            text = (f"schema_version: 1\nbenchmark_id: {benchmark_id}\n"
                    f"benchmark_sha256: {hashlib.sha256(data).hexdigest()}\nrules:\n")
            text += "".join(f"  - stig_id: {v}\n    sv_id: {sv}\n    status: auto\n" for v, sv in rules)
            outputs.append((output, text.encode("ascii")))
            total_rules += len(rules)
        if not dry_run:
            for name, body in outputs:
                output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=fd)
                with os.fdopen(output_fd, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(body)
        print(f"{'DRY RUN' if dry_run else 'CREATED'}: {len(outputs)} benchmark(s), {total_rules} rules"
              + ("; no files written" if dry_run else ""))
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-root", required=True, help="owner-private flat Cisco XML library")
    parser.add_argument("--dry-run", action="store_true", help="preflight and count without writing")
    args = parser.parse_args()
    try:
        generate(args.library_root, args.dry_run)
    except (OSError, ValueError, ET.ParseError, expat.ExpatError) as exc:
        print(f"Cisco tailoring generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
