#!/usr/bin/env python3
"""Generate synthetic Cisco CKLB examples from separately supplied official XML.

This copies converter-produced bytes and sidecars into one benchmark directory per
host so Checkmate's newest-per-directory discovery sees every example. It does
not score compliance or bundle DISA benchmark XML.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
BENCHMARK = re.compile(r"Cisco_[A-Za-z0-9_-]+_STIG\Z")


def private_directory(path):
    info = path.lstat()
    if not path.is_dir() or path.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"not an owner-private ordinary directory: {path}")


def create_private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    private_directory(path)


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not __import__("stat").S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError(f"not an owner-private regular file: {path}")
        with os.fdopen(os.dup(fd), "rb") as f:
            return f.read()
    finally:
        os.close(fd)


def publish_copy(source, destination):
    data = read_private(source)
    try:
        old = read_private(destination)
    except FileNotFoundError:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return
    if old != data:
        raise ValueError(f"refusing to overwrite differing checklist: {destination}")


def generate(args):
    source = Path(args.source_root).resolve()
    library = Path(args.library_root).resolve()
    output = Path(args.output_root).absolute()
    converter = Path(args.converter).resolve()
    if source == output or output == source / "targets" or output.is_relative_to(source / "targets"):
        raise ValueError("output must be separate from source targets")
    private_directory(library)
    if not converter.is_file() or converter.is_symlink():
        raise ValueError("converter must be an ordinary executable")
    manifest = json.loads((source / "manifest.json").read_bytes())
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("targets"), list):
        raise ValueError("unsupported example manifest")
    create_private_directory(output)
    seen = set()
    count = 0
    for target in manifest["targets"]:
        host, ids = target["host"], target["benchmarks"]
        if not HOST.fullmatch(host) or ".." in host or not isinstance(ids, list):
            raise ValueError(f"invalid target entry: {host}")
        host_dir = source / "targets" / host
        private_directory(host_dir)
        cfg = host_dir / "scan.running-config"
        cfg_bytes = read_private(cfg)
        if b"SYNTHETIC" not in cfg_bytes.upper():
            raise ValueError(f"refusing to publish an unmarked real config: {cfg}")
        for benchmark in ids:
            if not isinstance(benchmark, str) or not BENCHMARK.fullmatch(benchmark) or (host, benchmark) in seen:
                raise ValueError(f"invalid or duplicate benchmark: {benchmark}")
            seen.add((host, benchmark))
            command = [str(converter), "cisco-cklb", "--config", str(cfg), "--target", host,
                       "--library-root", str(library), "--benchmark-id", benchmark]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            line = next((line for line in result.stdout.splitlines() if line.startswith(("CREATED ", "SKIP "))), None)
            if line is None or " (" not in line:
                raise ValueError(f"converter did not name its output for {host}/{benchmark}")
            created = line.startswith("CREATED ")
            generated = Path(line.split(" (", 1)[0].split(" ", 1)[1])
            if generated.parent != host_dir or not generated.name.endswith("-ASSESSMENT.cklb"):
                raise ValueError(f"converter output escaped host directory: {generated}")
            generated_sidecar = Path(str(generated) + ".provenance.json")
            body = read_private(generated)
            provenance = json.loads(read_private(generated_sidecar))
            if (provenance["target"] != host or provenance["benchmark_id"] != benchmark
                    or provenance["config"]["sha256"] != hashlib.sha256(cfg_bytes).hexdigest()
                    or provenance["checklist_sha256"] != hashlib.sha256(body).hexdigest()):
                raise ValueError(f"unbound converter output: {generated}")
            bench_dir = output / benchmark
            create_private_directory(bench_dir)
            out_dir = bench_dir / host
            create_private_directory(out_dir)
            published = out_dir / generated.name
            publish_copy(generated, published)
            publish_copy(generated_sidecar, Path(str(published) + ".provenance.json"))
            if created:
                generated.unlink()
                generated_sidecar.unlink()
            count += 1
    print(f"STAGED {count} synthetic Cisco CKLB review candidates; no compliance assertion")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("converter", "library-root", "source-root", "output-root"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    try:
        generate(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"Cisco example generation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
