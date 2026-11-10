import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor"))
from samsung_tv_root.archive_root import ArchiveRootError, _runtime


class RuntimeDetectionTests(unittest.TestCase):
    def client(self, *outputs):
        client = Mock()
        client.capture.side_effect = [SimpleNamespace(output=s) for s in outputs]
        return client

    def test_standard_runtime_enumeration(self):
        for version, expected in [("6.0.9", "6.0"), ("3.1.32", "3.1")]:
            with self.subTest(version=version):
                self.assertEqual(
                    _runtime(
                        self.client(
                            f"Microsoft.NETCore.App {version} [/runtime]\n[exit:0]"
                        )
                    ),
                    expected,
                )

    def test_samsung_apphost_with_valid_runtime(self):
        client = self.client(
            "Unknown option --list-runtimes.\n[exit:255]",
            "/usr/share/dotnet.tizen/framework/6.0.9\n[exit:0]",
            "\n[exit:0]",
        )
        self.assertEqual(_runtime(client), "6.0")

    def test_unknown_path_is_rejected(self):
        with self.assertRaises(ArchiveRootError):
            _runtime(
                self.client(
                    "Unknown option --list-runtimes.\n[exit:255]",
                    "/usr/share/dotnet.tizen/missing\n[exit:0]",
                )
            )

    def test_missing_runtime_files_are_rejected(self):
        with self.assertRaises(ArchiveRootError):
            _runtime(
                self.client(
                    "Unknown option --list-runtimes.\n[exit:255]",
                    "/usr/share/dotnet.tizen/framework/6.0.9\n[exit:0]",
                    "\n[exit:1]",
                )
            )

    def test_other_command_failure_does_not_trigger_fallback(self):
        with self.assertRaises(ArchiveRootError):
            _runtime(self.client("Permission denied\n[exit:1]"))

    def test_unsupported_runtime_is_rejected(self):
        with self.assertRaises(ArchiveRootError):
            _runtime(self.client("Microsoft.NETCore.App 5.0.1 [/runtime]\n[exit:0]"))
