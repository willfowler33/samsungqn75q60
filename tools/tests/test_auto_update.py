import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_scripts


class AutoUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "value").write_text("1")
        (self.root / "os-release").write_text("BUILD_ID=test\n")
        (self.root / "boot").write_text("test-boot\n")

    def run_control(self, mode, fail_write=False, build="test"):
        script = device_scripts.AUTO_UPDATE.replace("@@MODE@@", mode).replace(
            "@@BUILD@@", build
        )
        for original, target in (
            ("/opt/usr/home/owner/share/frame-auto-update-v1", self.root / "journal"),
            ("/run/frame-runtime-v1.lock", self.root / "lock"),
            ("/etc/os-release", self.root / "os-release"),
            ("/proc/sys/kernel/random/boot_id", self.root / "boot"),
        ):
            script = script.replace(original, str(target))
        helpers = r"""
id() { echo 0; }
vconftool() {
 if [[ $1 == get ]]; then
  printf '%s, value = %s (Int32)\n' "$2" "$(cat "$TEST_ROOT/value")"
 else
  [[ $6 == -f ]] || return 1
  if [[ $FAIL_WRITE == 1 && $5 == 0 ]]; then return 1; fi
  printf '%s' "$5" > "$TEST_ROOT/value"
 fi
}
"""
        return subprocess.run(
            ["/bin/bash"],
            input=helpers + script,
            text=True,
            capture_output=True,
            env=os.environ
            | {"TEST_ROOT": str(self.root), "FAIL_WRITE": str(int(fail_write))},
        )

    def test_disable_readback_and_restore_original(self):
        for operation, value in [
            ("disable", "0"),
            ("status", "0"),
            ("disable", "0"),
            ("restore", "1"),
            ("restore", "1"),
        ]:
            result = self.run_control(operation)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.root / "value").read_text(), value)
        self.assertEqual((self.root / "journal/original").read_text().strip(), "1")
        self.assertNotEqual(self.run_control("disable").returncode, 0)

    def test_already_off_restores_off(self):
        (self.root / "value").write_text("0")
        self.assertEqual(self.run_control("disable").returncode, 0)
        self.assertEqual(self.run_control("restore").returncode, 0)
        self.assertEqual((self.root / "value").read_text(), "0")

    def test_failed_write_preserves_original_and_journal(self):
        self.assertNotEqual(self.run_control("disable", fail_write=True).returncode, 0)
        self.assertEqual((self.root / "value").read_text(), "1")
        self.assertTrue((self.root / "journal/restored").exists())
        self.assertFalse((self.root / "journal/complete").exists())

    def test_rejects_drift_before_mutation(self):
        self.assertNotEqual(self.run_control("disable", build="other").returncode, 0)
        self.assertFalse((self.root / "journal").exists())
        (self.root / "value").write_text("2")
        self.assertNotEqual(self.run_control("disable").returncode, 0)
        self.assertFalse((self.root / "journal").exists())

    def test_incomplete_unchanged_transaction_can_resume(self):
        journal = self.root / "journal"
        journal.mkdir()
        (journal / "original").write_text("1\n")
        (journal / "boot-id").write_text("old-boot\n")
        result = self.run_control("disable")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "value").read_text(), "0")
        self.assertEqual((journal / "original").read_text(), "1\n")
        self.assertTrue((journal / "complete").exists())

    def test_restore_does_not_overwrite_external_change(self):
        self.assertEqual(self.run_control("disable").returncode, 0)
        (self.root / "value").write_text("1")
        self.assertNotEqual(self.run_control("restore").returncode, 0)
        self.assertEqual((self.root / "value").read_text(), "1")
