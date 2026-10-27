"""Final regression checks for input handling and CLI behavior."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from compose_exposure.audit import ComposeError, inspect


class FinalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "compose.yaml"

    def parse(self, content):
        self.path.write_text(content, encoding="utf-8")
        return inspect(self.path)

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "compose_exposure", *args],
            capture_output=True, text=True, check=False,
        )

    def test_reject_non_string_long_host_bindings(self):
        for value in ("true", "{address: 127.0.0.1}", "[127.0.0.1]"):
            with self.subTest(value=value), self.assertRaises(ComposeError):
                self.parse("services:\n  app:\n    ports:\n      - target: 80\n        host_ip: " + value + "\n")

    def test_malformed_yaml_error_omits_source_line(self):
        marker = "PASSWORD_SHOULD_NOT_LEAK"
        with self.assertRaises(ComposeError) as caught:
            self.parse("services:\n  app:\n    ports: [\"8080:80\", " + marker + "\n")
        self.assertNotIn(marker, str(caught.exception))

    def test_oversized_quoted_port_is_input_error(self):
        with self.assertRaises(ComposeError):
            self.parse('services:\n  app:\n    ports: ["' + '9' * 5000 + ':80"]\n')

    def test_oversized_unquoted_port_is_input_error(self):
        with self.assertRaises(ComposeError):
            self.parse('services:\n  app:\n    ports: [' + '9' * 5000 + ']\n')

    def test_cli_exit_codes_and_json(self):
        self.parse('services:\n  app:\n    ports: ["192.0.2.1:8080:80"]\n')
        for threshold, expected in (("all", 0), ("nonlocal", 1)):
            with self.subTest(threshold=threshold):
                run = self.run_cli("scan", str(self.path), "--format", "json", "--fail-on", threshold)
                self.assertEqual(run.returncode, expected, run.stderr)
                self.assertEqual(json.loads(run.stdout)["exposures"][0]["scope"], "specific")
        missing = self.run_cli("scan", str(self.path) + ".missing")
        self.assertEqual(missing.returncode, 2)

    def test_cli_compare_only_new_exposure_is_risky(self):
        self.parse('services:\n  app:\n    ports: ["8080:80"]\n')
        candidate = Path(self.tmp.name) / "candidate.yaml"
        candidate.write_text('services:\n  app:\n    ports: ["127.0.0.1:8080:80"]\n', encoding="utf-8")
        run = self.run_cli("compare", str(self.path), str(candidate), "--format", "json", "--fail-on", "all")
        self.assertEqual(run.returncode, 0, run.stderr)
        delta = json.loads(run.stdout)
        self.assertEqual(delta["added"][0]["scope"], "loopback")
        self.assertEqual(delta["removed"][0]["scope"], "all")

    def test_yaml_merge_override_is_valid(self):
        result = self.parse('services:\n  app:\n    <<: &defaults {ports: ["8080:80"]}\n    ports: ["127.0.0.1:8080:80"]\n')
        self.assertEqual([r.scope for r in result], ["loopback"])


if __name__ == "__main__":
    unittest.main()
