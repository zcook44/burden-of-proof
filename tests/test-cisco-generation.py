#!/usr/bin/env python3
"""Exercise the synthetic Cisco example generator without private benchmarks."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
XML = b'''<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Cisco_IOS_Router_NDM_STIG"><title>Fixture only</title><version>1</version><plain-text id="release-info">Release: 1 Benchmark Date: 30 Sep 2026</plain-text><Group id="V-123"><Rule id="SV-123r456_rule" severity="high"><title>Test</title><version>FIXTURE-1</version><fixtext>Manual review</fixtext></Rule></Group></Benchmark>'''


def main():
    with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"], prefix="cisco-example-gen.") as temp:
        root = Path(temp)
        os.chmod(root, 0o700)
        source, library, output = root / "source", root / "library", root / "output"
        for path in (source, library, output):
            path.mkdir(mode=0o700)
        (source / "manifest.json").write_text(json.dumps({"schema_version": 1, "targets": [{"host": "router.example.test", "platform": "IOS router", "benchmarks": ["Cisco_IOS_Router_NDM_STIG"]}]}))
        host = source / "targets" / "router.example.test"
        host.mkdir(parents=True, mode=0o700)
        os.chmod(host.parent, 0o700)
        cfg = host / "scan.running-config"
        cfg.write_text("! SYNTHETIC\nhostname router.example.test\n!")
        cfg.chmod(0o600)
        bench = library / "U_Cisco_IOS_Router_NDM_STIG_V1R1_Manual-xccdf.xml"
        bench.write_bytes(XML)
        bench.chmod(0o600)
        binary = root / "stig-evidence"
        subprocess.run(["go", "build", "-mod=vendor", "-o", str(binary), "./cmd/stig-evidence"], cwd=REPO, check=True, env={**os.environ, "GOPROXY": "off", "GOSUMDB": "off"})
        script = REPO / "scripts/generate-cisco-examples.py"
        assert script.is_file(), "Cisco example generator missing"
        command = ["python3", str(script), "--converter", str(binary), "--library-root", str(library), "--source-root", str(source), "--output-root", str(output)]
        for attempt in range(2):
            subprocess.run(command, check=True, capture_output=True, text=True)
            ck = list(output.rglob("*.cklb"))
            assert len(ck) == 1, (attempt, ck)
            doc = json.loads(ck[0].read_bytes())
            assert len(doc["stigs"][0]["rules"]) == 1
            assert doc["stigs"][0]["rules"][0]["status"] == "not_reviewed"
            sidecar = Path(str(ck[0]) + ".provenance.json")
            assert json.loads(sidecar.read_bytes())["checklist_sha256"] == hashlib.sha256(ck[0].read_bytes()).hexdigest()
            assert not list(host.glob("*.cklb")), "generator left an ambiguous CKLB in source directory"
        print("PASS: synthetic Cisco generator is repeatable and never fabricates findings")


if __name__ == "__main__":
    main()
