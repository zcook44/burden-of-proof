#!/usr/bin/env python3
"""Read-only contract for synthetic Cisco examples (not a compliance test)."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "examples" / "cisco-synthetic"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    manifest = json.loads((BASE / "manifest.json").read_text())
    require(manifest["schema_version"] == 1, "unsupported manifest")
    seen_hosts, seen_pairs = set(), set()
    for target in manifest["targets"]:
        host, benchmarks = target["host"], target["benchmarks"]
        require(host not in seen_hosts, f"duplicate host: {host}")
        seen_hosts.add(host)
        config = BASE / "targets" / host / "scan.running-config"
        data = config.read_bytes()
        require(len(data.splitlines()) >= 30, f"not a usable config example: {host}")
        require(b"SYNTHETIC" in data.upper(), f"missing synthetic disclosure: {host}")
        require(b"hostname " + host.encode() in data, f"host mismatch: {host}")
        digest = hashlib.sha256(data).hexdigest()
        for benchmark in benchmarks:
            pair = benchmark, host
            require(pair not in seen_pairs, f"duplicate benchmark/host: {pair}")
            seen_pairs.add(pair)
            directory = BASE / "checklists" / benchmark / host
            checklists = list(directory.glob("*.cklb"))
            require(len(checklists) == 1, f"expected one CKLB for {pair}: {checklists}")
            path = checklists[0]
            doc = json.loads(path.read_bytes())
            require("NOT REVIEWED" in doc["title"], f"unsafe title: {path}")
            require(doc["target_data"]["host_name"] == host, f"wrong target: {path}")
            require(len(doc["stigs"]) == 1, f"wrong STIG count: {path}")
            stig = doc["stigs"][0]
            require(stig["stig_id"] == benchmark, f"wrong benchmark: {path}")
            rules = stig["rules"]
            require(len(rules) > 0 and stig["size"] == len(rules), f"empty/incomplete rules: {path}")
            for rule in rules:
                require(rule["status"] == "not_reviewed", f"fabricated finding in {path}")
                require("NOT REVIEWED" in rule["comments"], f"missing review comment: {path}")
                require(digest in rule["finding_details"], f"unbound config: {path}")
            sidecar = json.loads(Path(str(path) + ".provenance.json").read_bytes())
            require(sidecar["benchmark_id"] == benchmark and sidecar["target"] == host,
                    f"wrong sidecar identity: {path}")
            require(sidecar["config"]["sha256"] == digest, f"unbound sidecar config: {path}")
            require(sidecar["checklist_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest(),
                    f"stale sidecar: {path}")
            require("config-only" in sidecar["mapping_method"], f"missing review boundary: {path}")
            for asset in (config, path, Path(str(path) + ".provenance.json")):
                result = subprocess.run(["git", "check-ignore", "--no-index", "-q", "--", str(asset)], cwd=ROOT)
                require(result.returncode == 1, f"example unexpectedly gitignored: {asset}")
    actual = {(p.parent.parent.name, p.parent.name) for p in (BASE / "checklists").rglob("*.cklb")}
    require(actual == seen_pairs, f"extra/missing CKLB examples: {actual ^ seen_pairs}")
    print(f"PASS: {len(seen_hosts)} synthetic Cisco targets, {len(seen_pairs)} schema-shaped review candidates; no compliance claim")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, ValueError, OSError) as exc:
        print(f"Cisco examples: {exc}", file=sys.stderr)
        sys.exit(1)
