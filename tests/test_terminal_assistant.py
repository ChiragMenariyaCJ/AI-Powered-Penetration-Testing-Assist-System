import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.terminal_assistant.sources import FollowFileSource, new_snapshot_text
from Backend.services.nmap_service import NmapService


class SanitizerTests(unittest.TestCase):
    def test_redacts_secrets_and_terminal_codes(self):
        raw = (
            '\x1b[31mcurl -H "Authorization: Bearer secret-token" '
            "https://user:password@lab.example.test/\x1b[0m\n"
            "API_KEY=very-secret"
        )

        sanitized = sanitize_terminal_text(raw)

        self.assertNotIn("secret-token", sanitized)
        self.assertNotIn("password@", sanitized)
        self.assertNotIn("very-secret", sanitized)
        self.assertNotIn("\x1b", sanitized)
        self.assertIn("[REDACTED]", sanitized)


class ScopeGuardTests(unittest.TestCase):
    def test_ip_network_scope(self):
        guard = ScopeGuard(["10.10.10.0/24"])

        self.assertTrue(guard.is_allowed("10.10.10.20"))
        self.assertFalse(guard.is_allowed("10.10.11.20"))

    def test_domain_scope_includes_subdomains_only(self):
        guard = ScopeGuard(["example.test"])

        self.assertTrue(guard.is_allowed("example.test"))
        self.assertTrue(guard.is_allowed("api.example.test"))
        self.assertFalse(guard.is_allowed("badexample.test"))

    def test_single_label_lab_hostname_scope(self):
        guard = ScopeGuard(["metasploitable"])

        self.assertTrue(guard.is_allowed("metasploitable"))
        self.assertFalse(guard.is_allowed("another-lab-host"))

    def test_scope_is_required(self):
        with self.assertRaises(ValueError):
            ScopeGuard([])


class AnalyzerTests(unittest.TestCase):
    def test_prompt_only_extraction_ignores_printed_recommendation_commands(self):
        printed = "Suggested command:\n  nmap -sV 10.10.10.20\n"
        executed = "kali@kali:~$ nmap -sV 10.10.10.20\n"

        self.assertIsNone(TerminalAnalyzer.extract_latest_prompt_command(printed))
        self.assertEqual(
            "nmap -sV 10.10.10.20",
            TerminalAnalyzer.extract_latest_prompt_command(executed),
        )

    def test_parses_authorized_nmap_output(self):
        transcript = """kali@kali:~$ nmap -sV 10.10.10.20
22/tcp open ssh OpenSSH 8.4
80/tcp open http Apache httpd 2.4.57
"""
        analyzer = TerminalAnalyzer(ScopeGuard(["10.10.10.0/24"]))

        result = analyzer.analyze(transcript)

        self.assertEqual("nmap -sV 10.10.10.20", result.command)
        self.assertTrue(result.scope_allowed)
        self.assertEqual(2, len(result.findings))
        self.assertTrue(any("HTTP headers" in item for item in result.suggestions))

    def test_blocks_out_of_scope_target_without_scan_advice(self):
        transcript = """kali@kali:~$ nmap -sV 192.0.2.10
22/tcp open ssh OpenSSH 8.4
"""
        analyzer = TerminalAnalyzer(ScopeGuard(["10.10.10.0/24"]))

        result = analyzer.analyze(transcript)

        self.assertFalse(result.scope_allowed)
        self.assertEqual(["192.0.2.10"], result.blocked_targets)
        self.assertEqual("scope", result.findings[0].kind)
        self.assertEqual(1, len(result.suggestions))


class SourceTests(unittest.TestCase):
    def test_extracts_appended_snapshot_text(self):
        previous = "prompt\nline one\nline two\n"
        current = "line one\nline two\nline three\n"

        self.assertEqual("line three\n", new_snapshot_text(previous, current))

    def test_follows_only_new_transcript_bytes(self):
        with TemporaryDirectory() as temp_directory:
            transcript = Path(temp_directory) / "session.log"
            transcript.write_text("existing\n", encoding="utf-8")
            source = FollowFileSource(transcript)
            with transcript.open("a", encoding="utf-8") as handle:
                handle.write("new output\n")

            observed = source.read_new().replace("\r\n", "\n")
            self.assertEqual("new output\n", observed)


class NmapSafetyTests(unittest.TestCase):
    def test_accepts_normal_targets(self):
        self.assertEqual(
            "10.10.10.0/24",
            NmapService._validate_target("10.10.10.0/24"),
        )
        self.assertEqual(
            "lab.example.test",
            NmapService._validate_target("lab.example.test"),
        )

    def test_rejects_option_and_multi_target_injection(self):
        for target in ("--script exploit", "10.0.0.1 10.0.0.2", "-iL"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    NmapService._validate_target(target)


if __name__ == "__main__":
    unittest.main()
