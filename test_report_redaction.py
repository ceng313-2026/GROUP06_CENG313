import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from secureguard.cli import main
from secureguard.report import write


class ReportRedactionTests(unittest.TestCase):
    def test_cli_redacts_credentials_in_every_report(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "app.py"
            source.write_text(
                'api_key = "fake-api-token-for-test"\n'
                'password = "fake-password-for-test"\n',
                encoding="utf-8",
            )
            out_dir = root / "reports"

            self.assertEqual(main([str(source), "--no-llm", "--out", str(out_dir)]), 0)

            for filename in ("report.md", "findings.json", "findings.sarif"):
                with self.subTest(filename=filename):
                    content = (out_dir / filename).read_text(encoding="utf-8")
                    self.assertNotIn("fake-api-token-for-test", content)
                    self.assertNotIn("fake-password-for-test", content)
                    self.assertIn("[REDACTED]", content)
                    self.assertIn("CWE-798", content)

            findings = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [(item["file"], item["line"], item["cwe"]) for item in findings],
                [(str(source), 1, "CWE-798"), (str(source), 2, "CWE-798")],
            )

    def test_other_findings_on_the_same_line_also_hide_evidence(self):
        credential_line = 'password = "fake-secret-for-test"; other_call()'
        findings = [
            {"file": "app.py", "line": 1, "cwe": "CWE-798", "evidence": credential_line},
            {"file": "app.py", "line": 1, "cwe": "CWE-78", "evidence": credential_line},
            {"file": "app.py", "line": 2, "cwe": "CWE-78", "evidence": "separate_call()"},
            {"file": "other.py", "line": 1, "cwe": "CWE-78", "evidence": "other_file_call()"},
        ]

        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            write(findings, {"model": "disabled"}, out_dir)
            for filename in ("report.md", "findings.json", "findings.sarif"):
                with self.subTest(filename=filename):
                    content = (out_dir / filename).read_text(encoding="utf-8")
                    self.assertNotIn("fake-secret-for-test", content)
                    self.assertIn("separate_call()", content)
                    self.assertIn("other_file_call()", content)

        self.assertEqual(findings[0]["evidence"], credential_line)


if __name__ == "__main__":
    unittest.main()
