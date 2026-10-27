"""Regression tests for ambiguous YAML scalars and unresolved network modes."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from compose_exposure.audit import ComposeError, inspect, risky
from compose_exposure.cli import main


class EdgeCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "compose.yaml"

    def scan(self, text):
        self.path.write_text(text, encoding="utf-8")
        return inspect(self.path)

    def test_unquoted_short_port_is_not_sexagesimal(self):
        result = self.scan("services:\n  web:\n    ports: [1:20]\n")
        self.assertEqual((result[0].published, result[0].target), ("1", "20"))

    def test_service_names_on_off_yes_no_are_strings(self):
        result = self.scan("services:\n  on:\n    ports: [1:20]\n  off:\n    ports: [2:20]\n  yes:\n    ports: [3:20]\n  no:\n    ports: [4:20]\n")
        self.assertEqual({x.service for x in result}, {"on", "off", "yes", "no"})

    def test_boolean_ports_still_rejected(self):
        with self.assertRaises(ComposeError):
            self.scan("services:\n  web:\n    ports: [true]\n")

    def test_explicit_duplicate_keys_still_rejected(self):
        with self.assertRaisesRegex(ComposeError, "Duplicate YAML key"):
            self.scan("services:\n  web:\n    ports: [80]\n    ports: [81]\n")

    def test_interpolated_network_mode_is_not_silently_ignored(self):
        result = self.scan("services:\n  web:\n    network_mode: ${NETWORK_MODE:-host}\n")
        self.assertEqual(result[0].scope, "unknown")
        self.assertEqual(result[0].kind, "network-mode-unknown")
        self.assertTrue(risky(result, "nonlocal"))
        self.assertFalse(risky(result, "all"))

    def test_invalid_network_mode_type_rejected(self):
        with self.assertRaisesRegex(ComposeError, "network_mode must be a string"):
            self.scan("services:\n  web:\n    network_mode: true\n")

    def test_malformed_ipv6_brackets_rejected(self):
        for value in ('"[[::1]]:8080:80"', '"[::1]]:8080:80"'):
            with self.subTest(value=value), self.assertRaises(ComposeError):
                self.scan("services:\n  web:\n    ports: [" + value + "]\n")

    def test_long_ipv6_binding(self):
        result = self.scan('services:\n  web:\n    ports:\n      - target: 80\n        published: 8080\n        host_ip: "[::1]"\n')
        self.assertEqual(result[0].scope, "loopback")
        self.assertEqual(result[0].bind, "::1")

    def test_unsafe_yaml_tags_rejected(self):
        with self.assertRaises(ComposeError):
            self.scan('services:\n  web:\n    ports: !!python/object/apply:os.system ["echo no"]\n')

    def test_scan_does_not_modify_input(self):
        original = 'services:\n  web:\n    ports: ["127.0.0.1:8080:80"]\n'
        self.scan(original)
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_cli_json_and_nonlocal_failure(self):
        self.path.write_text("services:\n  web:\n    network_mode: ${NETWORK_MODE:-host}\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = main(["scan", str(self.path), "--format", "json", "--fail-on", "nonlocal"])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(out.getvalue())["exposures"][0]["scope"], "unknown")


if __name__ == "__main__":
    unittest.main()
