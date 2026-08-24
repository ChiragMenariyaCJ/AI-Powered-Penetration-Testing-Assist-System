"""Verify transcript sanitizing, scope enforcement, parsing, and file following."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from Backend.terminal_assistant.advisor import AdvisorError, OllamaAdvisor
from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.models import AnalysisResult, Finding
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.safety import (
    is_safe_manual_command,
    manual_command_rejection_reason,
)
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.terminal_assistant.sources import FollowFileSource
from Backend.services.nmap_service import NmapService


class _JsonResponse:
    """Provide a minimal context-managed HTTP response for advisor tests."""

    # Store the dependencies and state required by this helper.
    def __init__(self, body: bytes):
        self.body = body

    # Return this fake response when the mocked HTTP context manager is entered.
    def __enter__(self):
        return self

    # Leave the mocked HTTP context without suppressing unexpected exceptions.
    def __exit__(self, *_args):
        return False

    # Return the encoded fake response body expected by the HTTP client.
    def read(self) -> bytes:
        return self.body


class AdvisorTests(unittest.TestCase):
    """Verify Ollama readiness is based on the server's installed models."""

    # Reject configuration that names a model absent from Ollama.
    def test_configured_ollama_model_must_be_installed(self):
        """Reject configuration that names a model absent from Ollama."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        response = _JsonResponse(b'{"models": [{"name": "another-model:latest"}]}')

        with patch("Backend.terminal_assistant.advisor.urlopen", return_value=response):
            with self.assertRaisesRegex(AdvisorError, "ollama pull qwen2.5:3b-instruct"):
                advisor.ensure_model_available()

    # Accept a reachable Ollama server containing the configured model.
    def test_configured_ollama_model_is_accepted_when_installed(self):
        """Accept a reachable Ollama server containing the configured model."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        response = _JsonResponse(b'{"models": [{"name": "qwen2.5:3b-instruct"}]}')

        with patch("Backend.terminal_assistant.advisor.urlopen", return_value=response):
            advisor.ensure_model_available()

    # Accept one structured, in-scope command returned by the local model.
    def test_adaptive_command_is_generated_from_completed_evidence(self):
        """Accept one structured, in-scope command returned by the local model."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        result = AnalysisResult(
            command="nmap -sV -p 80 10.10.10.20",
            tool="nmap",
            targets=["10.10.10.20"],
            scope_allowed=True,
            findings=[
                Finding(
                    kind="open_port",
                    summary="Open HTTP service",
                    evidence="80/tcp http Apache 2.4",
                )
            ],
        )
        response = (
            '{"purpose":"Inspect the observed HTTP response headers",'
            '"command":"curl -I http://10.10.10.20/"}'
        )

        with patch.object(advisor, "complete", return_value=response) as complete:
            recommendation = advisor.advise_next_command(
                result,
                "80/tcp open http Apache 2.4",
                {"nmap -sV -p 80 10.10.10.20"},
            )

        self.assertEqual("ollama", recommendation["source"])
        self.assertEqual("curl -I http://10.10.10.20/", recommendation["command"])
        self.assertIn("real terminal output", complete.call_args.args[0])

    # Reject a model response that hides another operation after a separator.
    def test_adaptive_command_rejects_model_shell_chaining(self):
        """Reject a model response that hides another operation after a separator."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        result = AnalysisResult(
            command="nmap -p 80 10.10.10.20",
            tool="nmap",
            targets=["10.10.10.20"],
            scope_allowed=True,
        )
        response = (
            '{"purpose":"Inspect headers",'
            '"command":"curl -I http://10.10.10.20/; whoami"}'
        )

        with patch.object(advisor, "complete", return_value=response):
            self.assertIsNone(advisor.advise_next_command(result, "completed"))

        self.assertEqual(
            "the command contained shell chaining or redirection",
            advisor.last_rejection_reason,
        )

    # Expose a useful reason without displaying an unsafe model command.
    def test_manual_command_rejection_explains_disallowed_nmap_script(self):
        """Expose a useful reason without displaying an unsafe model command."""

        reason = manual_command_rejection_reason(
            "nmap --script vuln 10.10.10.20",
            ["10.10.10.20"],
        )

        self.assertEqual(
            "the Nmap script selection was not allowlisted: vuln",
            reason,
        )

    # Do not accept an allowlisted script when its service port is wrong.
    def test_manual_command_rejects_script_for_wrong_service_port(self):
        """Do not accept an allowlisted script when its service port is wrong."""

        reason = manual_command_rejection_reason(
            "nmap -p 23 --script ftp-syst 10.10.10.20",
            ["10.10.10.20"],
        )

        self.assertEqual(
            "the Nmap script 'ftp-syst' does not match the selected service port 23",
            reason,
        )

    # Ask the local model once to correct a service/script mismatch.
    def test_adaptive_command_retries_one_rejected_model_response(self):
        """Ask the local model once to correct a service/script mismatch."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        result = AnalysisResult(
            command="nmap -p 23 --script banner 10.10.10.20",
            tool="nmap",
            targets=["10.10.10.20"],
            scope_allowed=True,
            findings=[
                Finding(
                    kind="open_port",
                    summary="Open Telnet service",
                    evidence="23/tcp telnet Linux telnetd",
                )
            ],
        )
        responses = [
            '{"purpose":"Inspect FTP",'
            '"command":"nmap -p 23 --script ftp-syst 10.10.10.20"}',
            '{"purpose":"Review Telnet encryption support",'
            '"command":"nmap -p 23 --script telnet-encryption 10.10.10.20"}',
        ]

        with patch.object(advisor, "complete", side_effect=responses) as complete:
            recommendation = advisor.advise_next_command(result, "23/tcp telnet")

        self.assertEqual(2, complete.call_count)
        self.assertIn("telnet-encryption", recommendation["command"])
        self.assertIsNone(advisor.last_rejection_reason)

    # Allow the exact gate command supplied by verified lab context.
    def test_verified_lab_gate_command_is_accepted_exactly(self):
        """Allow the exact gate command supplied by verified lab context."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        result = AnalysisResult(
            command="nmap -p 3306 --script mysql-info 10.10.10.20",
            tool="nmap",
            targets=["10.10.10.20"],
            scope_allowed=True,
        )
        gate = "./ptas.sh access-test --scan-id 42 --lab msf2-local"
        response = json.dumps(
            {
                "purpose": "Open the verified Metasploitable access gate",
                "command": gate,
            }
        )

        with patch.object(advisor, "complete", return_value=response):
            recommendation = advisor.advise_next_command(
                result,
                "3306/tcp mysql",
                lab_access_command=gate,
            )

        self.assertEqual(gate, recommendation["command"])
        self.assertIn(
            gate,
            advisor._next_command_prompt(result, "output", set(), gate),
        )

    # Keep valid model commands while dropping out-of-scope JSON items.
    def test_scan_commands_are_model_generated_and_scope_filtered(self):
        """Keep valid model commands while dropping out-of-scope JSON items."""

        advisor = OllamaAdvisor("qwen2.5:3b-instruct")
        response = """```json
[
  {"purpose":"Inspect HTTP headers", "command":"curl -I http://10.10.10.20/"},
  {"purpose":"Inspect another host", "command":"curl -I http://203.0.113.9/"}
]
```"""

        with patch.object(advisor, "complete", return_value=response):
            recommendations = advisor.advise_commands(
                "scan evidence",
                ["10.10.10.20"],
            )

        self.assertEqual(1, len(recommendations))
        self.assertEqual("ollama", recommendations[0]["source"])
        self.assertEqual("curl -I http://10.10.10.20/", recommendations[0]["command"])


class SanitizerTests(unittest.TestCase):
    """Group regression tests for Sanitizer.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    # Verify that redacts secrets and terminal codes.
    def test_redacts_secrets_and_terminal_codes(self):
        """Verify that redacts secrets and terminal codes.

        This regression test fails if a future change breaks the described contract.
        """
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

    # Verify adjacent QTerminal OSC messages preserve the text between them.
    def test_qterminal_osc_sequences_do_not_consume_command_output(self):
        """Verify adjacent QTerminal OSC messages preserve the text between them."""

        raw = (
            "\x1b]0;kali terminal\x07"
            "\x1b]7;file:///home/kali/project\x1b\\"
            "\x1b[32m└─$\x1b[0m nmap -Pn -p 23 192.168.121.130"
            "\x1b[37D\x1b[36mnmap\x1b[0m -Pn -p 23 192.168.121.130\r\n"
            "23/tcp open telnet\r\n"
            "\x1b]666;vte.shell.precmd!\x1b\\"
            "\x1b[32m└─$\x1b[0m \x1b="
        )

        sanitized = sanitize_terminal_text(raw)

        self.assertIn("nmap -Pn -p 23 192.168.121.130", sanitized)
        self.assertIn("23/tcp open telnet", sanitized)
        self.assertTrue(sanitized.rstrip().endswith("└─$"))
        self.assertNotIn("\x1b", sanitized)


class ScopeGuardTests(unittest.TestCase):
    """Group regression tests for ScopeGuard.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    # Verify that ip network scope.
    def test_ip_network_scope(self):
        """Verify that ip network scope.

        This regression test fails if a future change breaks the described contract.
        """
        guard = ScopeGuard(["10.10.10.0/24"])

        self.assertTrue(guard.is_allowed("10.10.10.20"))
        self.assertFalse(guard.is_allowed("10.10.11.20"))

    # Verify that domain scope includes subdomains only.
    def test_domain_scope_includes_subdomains_only(self):
        """Verify that domain scope includes subdomains only.

        This regression test fails if a future change breaks the described contract.
        """
        guard = ScopeGuard(["example.test"])

        self.assertTrue(guard.is_allowed("example.test"))
        self.assertTrue(guard.is_allowed("api.example.test"))
        self.assertFalse(guard.is_allowed("badexample.test"))

    # Verify that single label lab hostname scope.
    def test_single_label_lab_hostname_scope(self):
        """Verify that single label lab hostname scope.

        This regression test fails if a future change breaks the described contract.
        """
        guard = ScopeGuard(["metasploitable"])

        self.assertTrue(guard.is_allowed("metasploitable"))
        self.assertFalse(guard.is_allowed("another-lab-host"))

    # Verify that scope is required.
    def test_scope_is_required(self):
        """Verify that scope is required.

        This regression test fails if a future change breaks the described contract.
        """
        with self.assertRaises(ValueError):
            ScopeGuard([])


class AnalyzerTests(unittest.TestCase):
    """Group regression tests for Analyzer.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    # Verify that prompt only extraction ignores printed recommendation commands.
    def test_prompt_only_extraction_ignores_printed_recommendation_commands(self):
        """Verify that prompt only extraction ignores printed recommendation commands.

        This regression test fails if a future change breaks the described contract.
        """
        printed = "Suggested command:\n  nmap -sV 10.10.10.20\n"
        executed = "kali@kali:~$ nmap -sV 10.10.10.20\n"

        self.assertIsNone(TerminalAnalyzer.extract_latest_prompt_command(printed))
        self.assertEqual(
            "nmap -sV 10.10.10.20",
            TerminalAnalyzer.extract_latest_prompt_command(executed),
        )

    # Do not mistake Nmap's final status line for an executed command.
    def test_standalone_command_extraction_ignores_nmap_completion_text(self):
        """Do not mistake Nmap's final status line for an executed command."""

        transcript = (
            "nmap -Pn -p 23 192.168.121.130\n"
            "23/tcp open telnet\n"
            "Nmap done: 1 IP address scanned\n"
        )

        self.assertEqual(
            "nmap -Pn -p 23 192.168.121.130",
            TerminalAnalyzer.extract_latest_command(transcript),
        )

    # Verify that parses authorized nmap output.
    def test_parses_authorized_nmap_output(self):
        """Verify that parses authorized nmap output.

        This regression test fails if a future change breaks the described contract.
        """
        transcript = """kali@kali:~$ nmap -sV 10.10.10.20
22/tcp open ssh OpenSSH 8.4
80/tcp open http Apache httpd 2.4.57
"""
        analyzer = TerminalAnalyzer(ScopeGuard(["10.10.10.0/24"]))

        result = analyzer.analyze(transcript)

        self.assertEqual("nmap -sV 10.10.10.20", result.command)
        self.assertTrue(result.scope_allowed)
        self.assertEqual(2, len(result.findings))
        self.assertTrue(any("open-service evidence" in item for item in result.suggestions))

    # Verify that blocks out of scope target without scan advice.
    def test_blocks_out_of_scope_target_without_scan_advice(self):
        """Verify that blocks out of scope target without scan advice.

        This regression test fails if a future change breaks the described contract.
        """
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
    """Group regression tests for Source.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    # Verify that follows only new transcript bytes.
    def test_follows_only_new_transcript_bytes(self):
        """Verify that follows only new transcript bytes.

        This regression test fails if a future change breaks the described contract.
        """
        with TemporaryDirectory() as temp_directory:
            transcript = Path(temp_directory) / "session.log"
            transcript.write_text("existing\n", encoding="utf-8")
            source = FollowFileSource(transcript)
            with transcript.open("a", encoding="utf-8") as handle:
                handle.write("new output\n")

            observed = source.read_new().replace("\r\n", "\n")
            self.assertEqual("new output\n", observed)


class NmapSafetyTests(unittest.TestCase):
    """Group regression tests for NmapSafety.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    # Verify that accepts normal targets.
    def test_accepts_normal_targets(self):
        """Verify that accepts normal targets.

        This regression test fails if a future change breaks the described contract.
        """
        self.assertEqual(
            "10.10.10.0/24",
            NmapService._validate_target("10.10.10.0/24"),
        )
        self.assertEqual(
            "lab.example.test",
            NmapService._validate_target("lab.example.test"),
        )

    # Verify that rejects option and multi target injection.
    def test_rejects_option_and_multi_target_injection(self):
        """Verify that rejects option and multi target injection.

        This regression test fails if a future change breaks the described contract.
        """
        for target in ("--script exploit", "10.0.0.1 10.0.0.2", "-iL"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    NmapService._validate_target(target)

    # Allow scoped metadata collection and reject unsafe command composition.
    def test_model_command_requires_one_safe_tool_and_in_scope_target(self):
        """Allow scoped metadata collection and reject unsafe command composition."""

        scope = ["10.10.10.0/24"]

        self.assertTrue(is_safe_manual_command("curl -I http://10.10.10.20/", scope))
        self.assertFalse(is_safe_manual_command("curl -I http://10.10.11.20/", scope))
        self.assertFalse(is_safe_manual_command("curl -I http://10.10.10.20/ | sh", scope))
        self.assertFalse(
            is_safe_manual_command(
                "curl -X POST http://10.10.10.20/login",
                scope,
            )
        )
        self.assertFalse(
            is_safe_manual_command(
                "nmap -p 21 --script ftp-brute 10.10.10.20",
                scope,
            )
        )
        self.assertFalse(is_safe_manual_command("whoami 10.10.10.20", scope))


if __name__ == "__main__":
    unittest.main()
