"""Q60D boundary checks: wrong target/scope/file must stop before control."""

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import frame
import q60d


class Q60DTests(unittest.TestCase):
    def test_ui_refresh_group_is_q60d_only_and_has_separate_journal(self):
        args = Namespace(action="apps", operation="apply", group="voice-ui-refresh")
        script = q60d.render(args, frame)
        self.assertIn(q60d.UI_STATE, script)
        self.assertNotIn(q60d.APP_STATE, script)
        selected = script.split("apps() { cat <<'APPS'\n", 1)[1].split("\nAPPS", 1)[0]
        self.assertEqual(
            set(selected.splitlines()),
            {"com.samsung.tv.voice-instant-app", "com.samsung.tv.aov-dashboard"},
        )
        with (
            patch.object(
                frame.sys,
                "argv",
                ["frame.py", "apps", "apply", "--group", "voice-ui-refresh"],
            ),
            patch.object(frame, "verify_files") as verify,
            patch("sys.stderr", io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                frame.main()
            verify.assert_not_called()

    def test_scope_rejected_before_network_or_root(self):
        for action, scope, group in (
            ("packages", None, None),
            ("certificates", None, None),
            ("apply", "both", None),
            ("apps", None, "advertising"),
        ):
            args = Namespace(action=action, scope=scope, group=group)
            with self.subTest(action=action), self.assertRaises(ValueError):
                q60d.validate_action(args)

    def test_live_model_mismatch_is_rejected(self):
        opener = unittest.mock.Mock()
        opener.open.return_value = io.StringIO(
            json.dumps({"device": {"modelName": "OTHER"}})
        )
        with patch.object(q60d.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ValueError, "model"):
                q60d.verify_model("192.0.2.1", q60d.policy()["model"])

    def test_changed_file_stops_before_control(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            app.write_text("changed executable")
            release = root / "os-release"
            release.write_text("BUILD_ID=expected\n")
            p = {
                "build": "expected",
                "architecture": "armv7l",
                "app_files": {
                    "org.example.voice": {"path": str(app), "sha256": "0" * 64}
                },
                "unit_sha256": {},
            }
            script = q60d.preflight(p).replace("/etc/os-release", str(release))
            helpers = f"""id() {{ echo 0; }}
stat() {{ echo 5001; }}
uname() {{ echo armv7l; }}
sqlite3() {{ echo 'org.example.voice|{app}'; }}
nsenter() {{ /bin/bash; }}
export -f id stat uname sqlite3 nsenter
"""
            result = subprocess.run(
                ["/bin/bash"],
                input=helpers + script + "echo CONTROL_REACHED\n",
                text=True,
                capture_output=True,
                timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("CONTROL_REACHED", result.stdout)

    def test_all_supported_payloads_have_valid_shell(self):
        for action, operation in (
            ("apps", "apply"),
            ("apps", "verify"),
            ("apps", "restore"),
            ("sound-sensor", "apply"),
            ("guards-apply", None),
            ("voice-audit", None),
            ("apply", None),
            ("status", None),
            ("restore", None),
        ):
            args = Namespace(
                action=action, operation=operation, scope="voice", group=None
            )
            with self.subTest(action=action, operation=operation):
                script = q60d.render(args, frame)
                self.assertNotIn("@@", script)
                subprocess.run(["/bin/bash", "-n"], input=script, text=True, check=True)

    def test_startup_bundle_enrolls_only_q60d_voice_and_checks_native_flags(self):
        with tarfile.open(fileobj=io.BytesIO(q60d.startup_bundle(frame))) as archive:
            names = archive.getnames()
            candidates = archive.extractfile("candidates").read().decode()
            self.assertEqual(candidates, f"voice\t{q60d.RUNTIME_STATE}\tvoice\n")
            self.assertNotIn("packages.status", names)
            self.assertNotIn("certificates.apply", names)
            postflight = archive.extractfile("policy.postflight").read().decode()
            self.assertIn(q60d.APP_STATE, postflight)
            self.assertIn(q60d.SOUND_STATE, postflight)
            self.assertNotIn("MODE=apply", postflight)
            core = archive.extractfile("policy.preflight").read().decode()
            self.assertNotIn("/opt/usr/apps/", core)
            self.assertIn("/usr/lib/systemd/system/", core)
            self.assertIn("app_rows=$(sqlite3", postflight)
            runtime = archive.extractfile("voice.apply").read().decode()
            self.assertIn("nsenter --mount=/proc/1/ns/mnt", runtime)

    def test_registration_query_error_cannot_pass_with_partial_output(self):
        p = {"app_files": {"org.example.voice": {"path": "/voice"}}}
        script = "set -e\nsqlite3() { echo 'org.example.voice|/voice'; return 5; }\n"
        result = subprocess.run(
            ["/bin/bash"],
            input=script + q60d.registration_check(p) + "echo CONTROL_REACHED\n",
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CONTROL_REACHED", result.stdout)

    def test_startup_operations_fit_transport_and_have_valid_shell(self):
        for operation in ("audit", "probe", "install", "status", "run", "remove"):
            with self.subTest(operation=operation):
                args = Namespace(action="startup", operation=operation, group=None)
                script = q60d.render(args, frame)
                self.assertLessEqual(len(frame.wrapped(script).encode()), 65536)
                subprocess.run(["/bin/bash", "-n"], input=script, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
