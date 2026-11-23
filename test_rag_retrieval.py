import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from secureguard.cli import main
from secureguard.rag import LocalRAG


class RagRetrievalTests(unittest.TestCase):
    def test_tempfile_finding_retrieves_python_reference(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "temp_example.py"
            source.write_text("import tempfile\npath = tempfile.mktemp()\n", encoding="utf-8")
            out = root / "report"

            self.assertEqual(main([str(source), "--no-llm", "--out", str(out)]), 0)

            finding, = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            reference, = finding["references"]
            self.assertEqual(finding["cwe"], "CWE-367")
            self.assertEqual(reference["cwe"], finding["cwe"])
            self.assertEqual(reference["lang"], "python")
            self.assertEqual(reference["retrieval_method"], "exact_cwe")
            self.assertEqual(reference["knowledge_base_file"], "knowledge_base.jsonl")
            self.assertIn("NamedTemporaryFile", finding["recommendation"])

            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Exact CWE match", report)
            self.assertIn("https://docs.python.org/3/library/tempfile.html", report)

    def test_model_context_prioritizes_the_exact_cwe(self):
        rag = LocalRAG([
            {"cwe": "CWE-378", "title": "Temporary permissions", "keywords": ["mktemp"]},
            {"cwe": "CWE-367", "title": "Temporary file race", "lang": "python",
             "mitigation": "Use NamedTemporaryFile()."},
        ])

        context = rag.context("mktemp", limit=1, lang="python", preferred_cwes=["CWE-367"])

        self.assertIn("CWE-367", context)
        self.assertIn("Use NamedTemporaryFile().", context)
        self.assertNotIn("CWE-378", context)

    def test_bm25_reference_does_not_replace_finding_cwe(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "temp_example.py"
            source.write_text("import tempfile\npath = tempfile.mktemp()\n", encoding="utf-8")
            kb = root / "related.json"
            kb.write_text(json.dumps([{
                "cwe": "CWE-378",
                "title": "Temporary file permissions",
                "keywords": ["tempfile", "mktemp"],
                "mitigation": "Use restrictive file permissions.",
            }]), encoding="utf-8")
            out = root / "report"

            self.assertEqual(main([str(source), "--no-llm", "--kb", str(kb), "--out", str(out)]), 0)

            finding, = json.loads((out / "findings.json").read_text(encoding="utf-8"))
            reference, = finding["references"]
            self.assertEqual(finding["cwe"], "CWE-367")
            self.assertEqual(reference["cwe"], "CWE-378")
            self.assertEqual(reference["retrieval_method"], "bm25")
            self.assertEqual(reference["knowledge_base_file"], kb.name)
            self.assertNotIn(reference["mitigation"], finding["recommendation"])

            report = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("Related local reference", report)
            self.assertIn("BM25 text match", report)


if __name__ == "__main__":
    unittest.main()
