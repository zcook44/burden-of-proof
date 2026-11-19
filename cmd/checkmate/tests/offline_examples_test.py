#!/usr/bin/env python3
"""Synthetic, disposable contract tests for the owner-private offline examples."""
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/stage-offline-examples.py"


class OfflineExamplesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="checkmate-fixtures-", dir=os.environ.get("TMPDIR", os.path.expanduser("~")))
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.scans = self.base / "scans"
        self.library = self.base / "library"
        self.output = self.base / "repo"
        for path in (self.scans, self.library, self.output):
            path.mkdir(mode=0o700)
        for n in (7, 8, 9, 10):
            host = self.scans / f"rhel{n}" / f"RHEL{n}-NODE1" / "scan_test" / f"rhel{n}-node1.lab.test"
            host.mkdir(parents=True, mode=0o700)
            for parent in host.parents:
                if parent == self.base:
                    break
                parent.chmod(0o700)
            for suffix in ("results.xml", "report.html", "results.arf.xml", "ASSESSMENT.cklb"):
                self._put(host / f"RHEL{n}.{suffix}", f"synthetic {n} {suffix}\n")
            self._put(self.library / f"U_RHEL_{n}_STIG_V1R2_Manual-xccdf.xml", f"synthetic benchmark {n}\n")
            self._put(self.library / f"RHEL_{n}_STIG.tailoring.yaml", "rules: []\n")

    def _put(self, path, text):
        path.write_text(text)
        path.chmod(0o600)

    def run_script(self):
        return subprocess.run([sys.executable, str(SCRIPT), "--scan-root", str(self.scans),
                               "--library-root", str(self.library), "--output", str(self.output)],
                              capture_output=True, text=True)

    def test_copies_all_four_os_with_private_modes_and_no_source_mutation(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        for n in (7, 8, 9, 10):
            host = self.output / "examples" / f"rhel{n}" / f"rhel{n}-node1.lab.test"
            src = self.scans / f"rhel{n}" / f"RHEL{n}-NODE1" / "scan_test" / host.name
            self.assertEqual(stat.S_IMODE(host.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(host.stat().st_mode), 0o700)
            self.assertEqual(len(list(host.iterdir())), 4)
            for item in host.iterdir():
                self.assertEqual(item.read_bytes(), (src / item.name).read_bytes())
                self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
            for item in (self.output / "benchmarks").iterdir():
                self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        self.assertEqual(len(list((self.output / "benchmarks").glob("*.xml"))), 4)
        self.assertEqual(len(list((self.output / "benchmarks").glob("*.yaml"))), 4)
        for name in ("examples", "benchmarks"):
            manifest = self.output / name / "SHA256SUMS"
            self.assertTrue(manifest.is_file())
            checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=manifest.parent,
                                     capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertEqual(stat.S_IMODE((self.output / "examples").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "benchmarks").stat().st_mode), 0o700)
        self.assertNotEqual(self.run_script().returncode, 0, "must not overwrite existing examples")

    def test_missing_source_leaves_no_output(self):
        (self.library / "RHEL_10_STIG.tailoring.yaml").unlink()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.output / "examples").exists())
        self.assertFalse((self.output / "benchmarks").exists())

    def test_symlink_input_leaves_no_output(self):
        p = self.library / "RHEL_8_STIG.tailoring.yaml"
        p.unlink()
        p.symlink_to(self.library / "RHEL_7_STIG.tailoring.yaml")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.output / "examples").exists())
        self.assertFalse((self.output / "benchmarks").exists())


if __name__ == "__main__":
    unittest.main()
