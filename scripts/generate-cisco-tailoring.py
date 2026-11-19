#!/usr/bin/env python3
"""Seed one partial schema v3 root tailoring file per official Cisco XCCDF benchmark.

The file pins the benchmark and lists no rules. Add a rule only for a real
administrator decision. Existing policies are never replaced. Manual XCCDF may
be mode 0644; the generated tailoring file is mode 0600.
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


def require_private_dir(info, name):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"{name}: expected an owner-owned 0700 directory")


def require_benchmark_file(info, name):
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or mode & 0o111:
        raise ValueError(f"{name}: expected a non-executable regular benchmark file")
    # DISA manuals are public. 0600 is not required. Refuse group/world write.
    if mode & 0o022:
        raise ValueError(f"{name}: benchmark must not be group or world writable")


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
        require_private_dir(os.fstat(fd), root)
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
                require_benchmark_file(info, name)
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
            text = (f"# Partial Cisco root tailoring for {benchmark_id}.\n"
                    f"# Generated by generate-cisco-tailoring.py. Schema version 3.\n"
                    f"# No rules yet. Add a row only for an administrator decision.\n"
                    f"# {len(rules)} controls were read from the manual and are not listed.\n"
                    f"schema_version: 3\nbenchmark_id: {benchmark_id}\n"
                    f"benchmark_sha256: {hashlib.sha256(data).hexdigest()}\nrules: []\n")
            outputs.append((output, text.encode("ascii")))
            total_rules += len(rules)
        if not dry_run:
            for name, body in outputs:
                output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=fd)
                with os.fdopen(output_fd, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(body)
        print(f"{'DRY RUN' if dry_run else 'CREATED'}: {len(outputs)} partial root file(s); {total_rules} controls left unscored"
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
