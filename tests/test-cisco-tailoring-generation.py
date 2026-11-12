#!/usr/bin/env python3
"""Offline synthetic contract tests for the Cisco tailoring generator."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/generate-cisco-tailoring.py"
NS = "http://checklists.nist.gov/xccdf/1.1"


def benchmark(benchmark_id="Cisco_IOS_Router_NDM_STIG", groups=None, namespace=NS):
    if groups is None:
        groups = '<Group id="V-100"><Rule id="SV-100r2_rule"/></Group><Group id="V-101"><Rule id="SV-101r3_rule"/></Group>'
    return f'<Benchmark xmlns="{namespace}" id="{benchmark_id}">{groups}</Benchmark>'.encode()


class CiscoTailoringGeneration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.library = Path(self.temp.name) / "library"
        self.library.mkdir(mode=0o700)

    def source(self, name="first.xml", body=None):
        path = self.library / name
        path.write_bytes(benchmark() if body is None else body)
        path.chmod(0o600)
        return path

    def run_generator(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--library-root", str(self.library), *args],
                              capture_output=True, text=True)

    def test_dry_run_counts_without_writing(self):
        self.source()
        result = self.run_generator("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 benchmark", result.stdout)
        self.assertIn("2 rules", result.stdout)
        self.assertEqual(sorted(p.name for p in self.library.iterdir()), ["first.xml"])

    def assert_rejected_without_output(self, error):
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(error, result.stderr)
        self.assertEqual(list(self.library.glob("*.tailoring.yaml")), [])

    def test_preflights_every_source_before_any_output(self):
        self.source()
        self.source("second.xml", b"not XML")
        self.assert_rejected_without_output("second.xml")

    def test_multiple_benchmarks_generate_separate_policies(self):
        self.source()
        self.source("second.xml", benchmark("Cisco_ASA_FW_STIG", '<Group id="V-42"><Rule id="SV-42r1_rule"/></Group>'))
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 benchmark", result.stdout)
        self.assertIn("3 rules", result.stdout)
        self.assertEqual(len(list(self.library.glob("*.tailoring.yaml"))), 2)

    def test_existing_output_collision_aborts_batch_without_overwrite(self):
        self.source()
        self.source("second.xml", benchmark("Cisco_ASA_FW_STIG"))
        existing = self.library / "Cisco_ASA_FW_STIG.tailoring.yaml"
        existing.write_text("admin override\n")
        existing.chmod(0o600)
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertEqual(existing.read_text(), "admin override\n")
        self.assertFalse((self.library / "Cisco_IOS_Router_NDM_STIG.tailoring.yaml").exists())

    def test_duplicate_benchmark_id_rejected_before_creation(self):
        self.source()
        self.source("second.xml")
        self.assert_rejected_without_output("duplicate Cisco Benchmark ID")

    def test_rejects_bad_xml_inventories(self):
        cases = [
            (b"<Benchmark", "XML"),
            (benchmark(namespace="urn:wrong"), "XCCDF"),
            (benchmark(groups='<Group id="V-100"><Rule id="SV-101r1_rule"/></Group>'), "mismatched SV"),
            (benchmark(groups='<Group id="V-100"><Rule id="SV-100r1_rule"/></Group>' * 2), "duplicate V"),
            (benchmark(groups='<Group id="V-100"><Rule id="SV-100r1_rule"/><Rule id="SV-100r2_rule"/></Group>'), "multiple rules"),
            (benchmark(groups='<Group id="V-100"><Rule id="SV-100r1_rule"/></Group><Group id="V-101"><Rule id="SV-100r1_rule"/></Group>'), "mismatched SV"),
            (benchmark(groups='<Group id="V-100"><Rule xmlns="urn:foreign" id="SV-100r1_rule"/></Group>'), "foreign"),
            (benchmark(groups='<Group id="V-100"><Rule id="SV-100r1_rule"/><Group id="V-101"><Rule id="SV-101r1_rule"/></Group></Group>'), None),
            (b'<!DOCTYPE Benchmark [<!ENTITY x "secret">]>' + benchmark(), "DTD"),
        ]
        for body, message in cases:
            with self.subTest(message=message):
                path = self.source(body=body)
                if message is None:
                    result = self.run_generator()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((self.library / "Cisco_IOS_Router_NDM_STIG.tailoring.yaml").read_text().count("status: auto"), 2)
                    (self.library / "Cisco_IOS_Router_NDM_STIG.tailoring.yaml").unlink()
                else:
                    self.assert_rejected_without_output(message)
                path.unlink()

    def test_rejects_nonflat_library_before_any_output(self):
        self.source()
        (self.library / "nested").mkdir(mode=0o700)
        self.assert_rejected_without_output("flat")

    def test_rejects_symlink_and_non_private_sources(self):
        source = self.source()
        source.chmod(0o644)
        self.assert_rejected_without_output("0600")
        source.chmod(0o600)
        (self.library / "elsewhere.xml").symlink_to(source)
        self.assert_rejected_without_output("symlink")

    def test_rejects_symlink_library_and_non_private_directory(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.library, target_is_directory=True)
        result = subprocess.run([sys.executable, str(SCRIPT), "--library-root", str(alias)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.library.chmod(0o755)
        self.source()
        self.assert_rejected_without_output("0700")

    def test_creates_exact_minimal_yaml_with_byte_hash_and_private_permissions(self):
        body = benchmark()
        self.source(body=body)
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.library / "Cisco_IOS_Router_NDM_STIG.tailoring.yaml"
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.read_text(),
                         "schema_version: 1\nbenchmark_id: Cisco_IOS_Router_NDM_STIG\n"
                         f"benchmark_sha256: {hashlib.sha256(body).hexdigest()}\n"
                         "rules:\n  - stig_id: V-100\n    sv_id: SV-100r2_rule\n    status: auto\n"
                         "  - stig_id: V-101\n    sv_id: SV-101r3_rule\n    status: auto\n")
        rerun = self.run_generator()
        self.assertNotEqual(rerun.returncode, 0)
        self.assertEqual(output.read_text().count("status: auto"), 2)


if __name__ == "__main__":
    unittest.main()
