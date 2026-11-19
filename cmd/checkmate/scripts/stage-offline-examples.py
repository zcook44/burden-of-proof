#!/usr/bin/env python3
"""Stage private, copied RHEL 7/8/9/10 offline examples; never alter originals."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

OS_VERSIONS = (7, 8, 9, 10)
SUFFIXES = (".results.xml", ".report.html", ".results.arf.xml", ".cklb")


def fail(message):
    raise ValueError(message)


def private_dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        fail(f"must be an owner-private directory (0700): {path}")


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        fail(f"must be an owner-private regular file (0600): {path}")


def one(items, label):
    if len(items) != 1:
        fail(f"expected exactly one {label}; found {len(items)}")
    return items[0]


def sources(scans, library):
    plan = {"examples": [], "benchmarks": []}
    for number in OS_VERSIONS:
        os_dir = scans / f"rhel{number}"
        node_dir = os_dir / f"RHEL{number}-NODE1"
        private_dir(os_dir)
        private_dir(node_dir)
        run = one(sorted(node_dir.glob("scan_*")), f"RHEL {number} NODE1 scan directory")
        private_dir(run)
        host = one(sorted(run.iterdir()), f"RHEL {number} host directory")
        private_dir(host)
        dest = Path(f"rhel{number}") / host.name
        for suffix in SUFFIXES:
            match = one(sorted(p for p in host.iterdir() if p.name.endswith(suffix)),
                        f"RHEL {number} {suffix}")
            private_file(match)
            plan["examples"].append((match, dest / match.name))
        pattern = re.compile(rf"^U_RHEL_{number}_STIG_V([0-9]+)R([0-9]+)_Manual-xccdf\.xml$")
        found = []
        for item in library.iterdir():
            match = pattern.fullmatch(item.name)
            if match:
                private_file(item)
                found.append(((int(match[1]), int(match[2])), item))
        if not found:
            fail(f"no manual XCCDF benchmark for RHEL {number} in {library}")
        found.sort()
        plan["benchmarks"].append((found[-1][1], Path(found[-1][1].name)))
        policy = library / f"RHEL_{number}_STIG.tailoring.yaml"
        private_file(policy)
        plan["benchmarks"].append((policy, Path(policy.name)))
    return plan


def stage_files(stage, pairs):
    lines = []
    for source, relative in pairs:
        dest = stage / relative
        dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        digest = hashlib.sha256()
        # Open the validated source without following a swapped-in symlink.
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                fail(f"source changed during staging: {source}")
            with os.fdopen(fd, "rb", closefd=False) as reader, dest.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                    digest.update(chunk)
            dest.chmod(0o600)
        finally:
            os.close(fd)
        lines.append(f"{digest.hexdigest()}  {relative.as_posix()}\n")
    manifest = stage / "SHA256SUMS"
    manifest.write_text("".join(lines))
    manifest.chmod(0o600)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-root", required=True, type=Path, help="owner-private quarterly tree containing rhelN/RHELN-NODE1/scan_*/HOST")
    parser.add_argument("--library-root", required=True, type=Path, help="owner-private extracted XCCDF and per-OS tailoring YAML")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1], help="repository directory (default: Checkmate repo)")
    args = parser.parse_args()
    for path in (args.scan_root, args.library_root):
        if not path.is_absolute() or path.resolve() != path:
            fail(f"source path must be canonical and absolute: {path}")
        private_dir(path)
    output = args.output
    if not output.is_absolute() or output.resolve() != output or output.is_symlink():
        fail(f"output must be an existing canonical absolute directory: {output}")
    st = output.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        fail(f"output must be owner-owned and not group/world writable: {output}")
    for name in ("examples", "benchmarks"):
        if (output / name).exists() or (output / name).is_symlink():
            fail(f"destination already exists; refusing overwrite: {output / name}")
    plan = sources(args.scan_root, args.library_root)
    stages = {}
    try:
        for name, pairs in plan.items():
            stages[name] = Path(tempfile.mkdtemp(prefix=f".{name}-stage-", dir=output))
            stage_files(stages[name], pairs)
        for name, stage in stages.items():
            if (output / name).exists() or (output / name).is_symlink():
                fail(f"destination appeared during staging: {output / name}")
            stage.rename(output / name)
            print(f"{output / name}: {len(plan[name])} private files and SHA256SUMS")
    finally:
        for stage in stages.values():
            if stage.exists():
                shutil.rmtree(stage)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"stage-offline-examples: {error}", file=sys.stderr)
        sys.exit(1)
