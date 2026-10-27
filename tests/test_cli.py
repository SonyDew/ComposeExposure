import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from compose_exposure.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "compose.yaml"
        self.file.write_text('services:\n  api:\n    ports: ["8080:80"]\n', encoding="utf-8")

    def test_scan_and_fail_on(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["scan", str(self.file), "--fail-on", "all"])
        self.assertEqual(code, 1)
        self.assertIn("scope: all", output.getvalue())

    def test_json_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["scan", str(self.file), "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn('"exposures"', output.getvalue())

    def test_missing_file(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = main(["scan", "missing-file.yaml"])
        self.assertEqual(code, 2)
        self.assertIn("Cannot read", errors.getvalue())

    def test_compare(self):
        candidate = Path(self.temp.name) / "candidate.yaml"
        candidate.write_text('services:\n  api:\n    ports: ["127.0.0.1:8080:80"]\n', encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["compare", str(self.file), str(candidate), "--fail-on", "all"])
        self.assertEqual(code, 0)
        self.assertIn("Removed exposures:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
