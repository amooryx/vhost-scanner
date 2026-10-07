import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import vhost_scanner


class TestHandler(BaseHTTPRequestHandler):
    unexpected_requests = 0
    unstable_baseline = False
    baseline_request_count = 0
    server_port = 0

    def do_GET(self):
        host = self.headers.get("Host", "")
        if self.path != "/":
            type(self).unexpected_requests += 1
            body = b"unexpected redirect destination"
            self.send_response(200)
        elif host.startswith("vhost-scanner-") and type(self).unstable_baseline:
            type(self).baseline_request_count += 1
            body = f"baseline-{type(self).baseline_request_count}".encode()
            self.send_response(200)
        elif host == "app.example.test":
            body = b"<html><title>App portal</title>app body</html>"
            self.send_response(200)
        elif host == "error.example.test":
            body = b"<html><title>Custom not found</title>custom error page</html>"
            self.send_response(404)
        elif host == "redirect.example.test":
            body = b"redirect body"
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{type(self).server_port}/redirect-target",
            )
        elif host == "large.example.test":
            body = b"x" * 70_000
            self.send_response(200)
        else:
            body = b"<html><title>Default</title>default page</html>"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "test-server")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class VHostScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.port = cls.server.server_address[1]
        TestHandler.server_port = cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def setUp(self):
        TestHandler.unexpected_requests = 0
        TestHandler.unstable_baseline = False
        TestHandler.baseline_request_count = 0
        self.limiter = vhost_scanner.RequestLimiter(1000)

    def baseline(self):
        return vhost_scanner.get_baseline(
            "127.0.0.1", self.port, False, 2, "test-suite", self.limiter
        )

    def test_normalizes_targets_and_rejects_header_injection(self):
        self.assertEqual(vhost_scanner.normalize_target("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(vhost_scanner.normalize_hostname("ExAmPle.test.", "domain"), "example.test")
        self.assertEqual(vhost_scanner.url_authority("2001:db8::1"), "[2001:db8::1]")
        with self.assertRaises(ValueError):
            vhost_scanner.normalize_target("example.test\r\nHost: attacker.test")
        with self.assertRaises(ValueError):
            vhost_scanner.normalize_hostname("https://example.test/path", "domain")

    def test_confirms_distinct_host_and_reads_non_success_response_bodies(self):
        baseline_fingerprints, baseline_fingerprint = self.baseline()
        result = vhost_scanner.check_vhost(
            "127.0.0.1", self.port, "error.example.test", False,
            baseline_fingerprints, baseline_fingerprint, 2, "test-suite", self.limiter,
        )
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["title"], "Custom not found")

    def test_does_not_follow_redirects(self):
        baseline_fingerprints, baseline_fingerprint = self.baseline()
        result = vhost_scanner.check_vhost(
            "127.0.0.1", self.port, "redirect.example.test", False,
            baseline_fingerprints, baseline_fingerprint, 2, "test-suite", self.limiter,
        )
        self.assertEqual(result["status"], 302)
        self.assertEqual(TestHandler.unexpected_requests, 0)

    def test_response_body_is_bounded_and_reports_original_length(self):
        response = vhost_scanner.fetch(
            "127.0.0.1", self.port, "large.example.test", False, 2, "test-suite", self.limiter
        )
        self.assertEqual(len(response.body), vhost_scanner.MAX_RESPONSE_BYTES)
        self.assertEqual(response.length, 70_000)
        self.assertTrue(response.truncated)

    def test_request_limiter_spaces_request_starts(self):
        limiter = vhost_scanner.RequestLimiter(20)
        start = time.monotonic()
        limiter.wait()
        limiter.wait()
        self.assertGreaterEqual(time.monotonic() - start, 0.045)

    def test_unstable_baseline_fails_loudly(self):
        TestHandler.unstable_baseline = True
        with self.assertRaisesRegex(vhost_scanner.ScanError, "baseline is unstable"):
            self.baseline()

    def test_cli_writes_sorted_confirmed_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist = Path(temp_dir) / "words.txt"
            output = Path(temp_dir) / "results.json"
            wordlist.write_text(
                "app\nerror\nredirect\n# comment\napp\n", encoding="utf-8"
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = vhost_scanner.main([
                    "127.0.0.1", "example.test", "--port", str(self.port),
                    "--wordlist", str(wordlist), "--threads", "3",
                    "--rate-limit", "100", "--timeout", "2", "--out", str(output),
                ])
            findings = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result, 0)
        self.assertEqual(
            [finding["host"] for finding in findings],
            ["app.example.test", "error.example.test", "redirect.example.test"],
        )
        self.assertIn("3 confirmed vhost(s)", stdout.getvalue())
        self.assertEqual(TestHandler.unexpected_requests, 0)

    def test_network_failures_produce_nonzero_exit_and_message(self):
        stderr = io.StringIO()
        with patch.object(
            vhost_scanner, "get_baseline",
            side_effect=vhost_scanner.ScanError("baseline request failed: connection refused"),
        ):
            with contextlib.redirect_stderr(stderr):
                result = vhost_scanner.main(["127.0.0.1", "example.test"])
        self.assertEqual(result, 2)
        self.assertIn("connection refused", stderr.getvalue())

    def test_candidate_network_failures_produce_nonzero_exit_and_message(self):
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            wordlist = Path(temp_dir) / "words.txt"
            wordlist.write_text("www\n", encoding="utf-8")
            with patch.object(
                vhost_scanner, "check_vhost",
                side_effect=vhost_scanner.ScanError("request for www.example.test failed: timeout"),
            ):
                with contextlib.redirect_stderr(stderr):
                    result = vhost_scanner.main([
                        "127.0.0.1", "example.test", "--port", str(self.port),
                        "--wordlist", str(wordlist), "--rate-limit", "100", "--timeout", "2",
                    ])
        self.assertEqual(result, 2)
        self.assertIn("timeout", stderr.getvalue())

    def test_cli_rejects_non_finite_timeout_and_rate(self):
        for option in ("--timeout", "--rate-limit"):
            with self.subTest(option=option):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as error:
                        vhost_scanner.main(["127.0.0.1", "example.test", option, "nan"])
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
