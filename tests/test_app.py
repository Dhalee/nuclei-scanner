import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as scanner


class ScannerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        p = patch.object(scanner, "RESULTS", Path(temp.name))
        p.start()
        self.addCleanup(p.stop)
        p = patch.dict(os.environ, {"ALLOWED_ORIGINS": "http://127.0.0.1:8000"})
        p.start()
        self.addCleanup(p.stop)
        self.client = scanner.app.test_client()

    def request(self, url):
        return self.client.post("/scan", data={"target": url})

    def test_home(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_unauthorized_urls(self):
        for value in ("https://example.org", "file:///etc/passwd",
                      "http://127.0.0.1:9000", "http://localhost:8000",
                      "http://127.0.0.1:8000@evil.org",
                      "http://user:pass@127.0.0.1:8000/",
                      "http://127.0.0.1.evil.org:8000",
                      "http://127.0.0.1:bad", "http://127.0.0.1:8000#part"):
            with self.subTest(value=value), patch.object(scanner.subprocess, "run") as run:
                self.assertEqual(self.request(value).status_code, 400)
                run.assert_not_called()

    def test_invalid_allowlist(self):
        with patch.dict(os.environ, {"ALLOWED_ORIGINS": "http://127.0.0.1:8000/not-an-origin"}):
            self.assertEqual(self.request("http://127.0.0.1:8000").status_code, 400)

    def test_binary_missing(self):
        with patch.object(scanner.subprocess, "run", side_effect=FileNotFoundError()):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"Nuclei not found", response.data)

    def test_exit_failure(self):
        failure = subprocess.CompletedProcess([], 1, "", "bad template")
        with patch.object(scanner.subprocess, "run", return_value=failure):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"bad template", response.data)

    def test_timeout(self):
        with patch.object(scanner.subprocess, "run", side_effect=subprocess.TimeoutExpired("nuclei", 45)):
            self.assertEqual(self.request("http://127.0.0.1:8000").status_code, 502)

    def test_zero_findings_distinguished_from_failure(self):
        with patch.object(scanner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"does not establish that the target is secure", response.data)

    def test_normal_jsonl_and_fixed_template(self):
        def run(cmd, **kwargs):
            self.assertEqual(cmd[cmd.index("-t") + 1], str(scanner.TEMPLATE))
            self.assertEqual(cmd[cmd.index("-u") + 1], "http://127.0.0.1:8000")
            self.assertEqual(kwargs["timeout"], 45)
            self.assertIn("-no-stdin", cmd)
            self.assertIn("-dr", cmd)
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            Path(cmd[cmd.index("-o") + 1]).write_text(
                json.dumps({"info": {"name": "Header test", "severity": "info"},
                            "matcher-name": "x-frame-options"}) + "\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with patch.object(scanner.subprocess, "run", side_effect=run):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"x-frame-options", response.data)

    # --- Improvement: header summary ---
    def test_summary_normal_case(self):
        """Two headers reported missing -> summary says 2 of 4, others Present."""
        def run(cmd, **kwargs):
            lines = [json.dumps({"info": {"name": "Header test", "severity": "info"},
                                 "matcher-name": name}) for name in
                     ("content-security-policy", "x-frame-options")]
            Path(cmd[cmd.index("-o") + 1]).write_text("\n".join(lines) + "\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with patch.object(scanner.subprocess, "run", side_effect=run):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"2 of 4 checked headers missing", response.data)
        summary = scanner.summarize_headers([
            {"matcher-name": "content-security-policy"}, {"matcher-name": "x-frame-options"}])
        status = {r["header"]: r["status"] for r in summary["rows"]}
        self.assertEqual(status["content-security-policy"], "Missing")
        self.assertEqual(status["x-frame-options"], "Missing")
        self.assertEqual(status["x-content-type-options"], "Present")
        self.assertEqual(status["referrer-policy"], "Present")

    def test_summary_zero_findings(self):
        with patch.object(scanner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            response = self.request("http://127.0.0.1:8000")
        self.assertIn(b"0 of 4 checked headers missing", response.data)

    def test_summary_not_shown_on_failure(self):
        """If Nuclei fails, the app must NOT claim headers are Present."""
        with patch.object(scanner.subprocess, "run", side_effect=FileNotFoundError()):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(b"Header summary", response.data)
        self.assertNotIn(b"Present", response.data)

    def test_unreachable_target_is_error_not_all_present(self):
        """Nuclei exits 0 with no findings when the site is down; the error log must turn that into an error."""
        def run(cmd, **kwargs):
            Path(cmd[cmd.index("-elog") + 1]).write_text(
                json.dumps({"input": "http://127.0.0.1:8000",
                            "error": "port closed or filtered"}) + "\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with patch.object(scanner.subprocess, "run", side_effect=run):
            response = self.request("http://127.0.0.1:8000")
        self.assertEqual(response.status_code, 502)
        self.assertIn(b"port closed or filtered", response.data)
        self.assertNotIn(b"Header summary", response.data)

    def test_bad_jsonl_is_error(self):
        def run(cmd, **kwargs):
            Path(cmd[cmd.index("-o") + 1]).write_text("{bad", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with patch.object(scanner.subprocess, "run", side_effect=run):
            self.assertEqual(self.request("http://127.0.0.1:8000").status_code, 502)


if __name__ == "__main__":
    unittest.main()
