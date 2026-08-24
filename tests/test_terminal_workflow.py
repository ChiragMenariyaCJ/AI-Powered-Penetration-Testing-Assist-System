"""Exercise the guided terminal application and native split-terminal helpers."""

from contextlib import redirect_stdout
import io
import json
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from Backend.cli import build_parser
from Backend.database import Base
from Backend.models.project_model import Project
from Backend.models.recommendation_model import Recommendation
from Backend.models.report_model import Report  # noqa: F401
from Backend.models.scan_model import Scan
from Backend.models.target_model import Target
from Backend.models.user_model import User
from Backend.models.vulnerability_model import Vulnerability
from Backend.services.nmap_service import NmapService
from Backend.services.exploitdb_service import ExploitDbService
from Backend.services.service_scan_service import ServiceScanService
from Backend.services.html_report_renderer import HtmlReportRenderer
from Backend.services.ai_recommendation_engine import AIRecommendationEngine
from Backend.services.lab_profile_service import (
    AccessExercise,
    LabVerificationError,
    Metasploitable2LabService,
)
from Backend.services.vulnerability_parser import VulnerabilityParser
from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.split_terminal import (
    build_terminator_layout,
    qterminal_argument_map,
    split_qterminal_recommendations,
)
from Backend.terminal_workflow import (
    CVE_SCAN_STAGE,
    RECOMMENDATION_SAFETY_NOTICE,
    SHELL_READY_PATTERN,
    SCAN_STAGES,
    _authenticate,
    _append_live_prompt_context,
    _completed_finding_count,
    _configure_target,
    _extract_live_executed_command,
    _finding_display_label,
    _is_manual_validation_command,
    _select_project,
    persist_validation_suggestions,
    select_next_recommendation,
    render_existing_report,
    run_dashboard,
    select_next_access_exercise,
    select_follow_up_suggestion,
    validation_suggestions,
)


class TerminalWorkflowTests(unittest.TestCase):
    """Group regression tests for TerminalWorkflow.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    class RecordingApi:
        """Provide the RecordingApi test double used by this test module.

        It records or returns deterministic data so the tests do not require an external
        process.
        """

        def __init__(self):
            """Support the test scenario by providing the init behavior.

            The deterministic implementation keeps the test focused on PTAS rather than
            external systems.
            """
            self.access_token = None
            self.calls = []

        def get(self, path, *, query=None, timeout=15):
            """Support the test scenario by providing the get behavior.

            The deterministic implementation keeps the test focused on PTAS rather than
            external systems.
            """
            self.calls.append(("GET", path, query))
            return {
                "projects": [
                    {
                        "id": 4,
                        "user_id": 7,
                        "project_name": "API project",
                        "status": "ACTIVE",
                    }
                ]
            }

        def post(self, path, payload=None, *, query=None, timeout=15):
            """Support the test scenario by providing the post behavior.

            The deterministic implementation keeps the test focused on PTAS rather than
            external systems.
            """
            self.calls.append(("POST", path, payload))
            if path == "/api/auth/login":
                return {
                    "access_token": "test-token",
                    "user": {
                        "id": 7,
                        "full_name": "Student Tester",
                        "email": "student@example.com",
                    },
                }
            if path == "/api/scope-validation/check-target-scope":
                return {"is_in_scope": True}
            if path == "/api/targets/":
                return {"id": 9, **payload}
            return {"id": 8, **(payload or {})}

    def test_login_and_project_selection_use_the_api(self):
        """Verify that login and project selection use the api.

        This regression test fails if a future change breaks the described contract.
        """
        api = self.RecordingApi()

        with patch(
            "builtins.input",
            side_effect=["login", "student@example.com", "4"],
        ), patch(
            "Backend.terminal_workflow.getpass",
            return_value="test-password",
        ), patch("builtins.print"):
            user = _authenticate(api)
            project = _select_project(api, user)

        self.assertEqual("test-token", api.access_token)
        self.assertEqual(4, project["id"])
        self.assertEqual(
            [
                ("POST", "/api/auth/login"),
                ("GET", "/api/projects/"),
            ],
            [(method, path) for method, path, _ in api.calls],
        )

    def test_scope_and_target_creation_use_the_api(self):
        """Verify that scope and target creation use the api.

        This regression test fails if a future change breaks the described contract.
        """
        api = self.RecordingApi()
        project = {"id": 4, "project_name": "API project"}

        with patch(
            "builtins.input",
            side_effect=["10.10.10.0/24", "10.10.10.20", "yes"],
        ), patch("builtins.print"):
            target, scope = _configure_target(api, project)

        self.assertEqual("10.10.10.0/24", scope)
        self.assertEqual("10.10.10.20", target["target_value"])
        self.assertEqual(
            [
                "/api/scope-validation/",
                "/api/scope-validation/check-target-scope",
                "/api/targets/",
            ],
            [path for _, path, _ in api.calls],
        )

    def test_start_and_report_commands_are_available(self):
        """Verify that start and report commands are available.

        This regression test fails if a future change breaks the described contract.
        """
        parser = build_parser()

        start = parser.parse_args(["start", "--plain"])
        report = parser.parse_args(
            ["report", "--scan-id", "7", "--output", "reports/test.json"]
        )

        self.assertTrue(start.plain)
        self.assertEqual(7, report.scan_id)
        self.assertEqual("reports/test.json", report.output)

        recommend = parser.parse_args(["recommend", "--scan-id", "7"])
        self.assertEqual(7, recommend.scan_id)
        self.assertFalse(recommend.reset)

        render = parser.parse_args(["render-report", "reports/example.json"])
        self.assertEqual("reports/example.json", render.json_report)

        access = parser.parse_args(
            ["access-test", "--scan-id", "22", "--lab", "msf2"]
        )
        self.assertEqual("msf2", access.lab)

        vmware = parser.parse_args(
            [
                "lab-register",
                "--name",
                "msf2",
                "--target",
                "192.168.178.128",
                "--provider",
                "vmware",
                "--vm",
                "/labs/Metasploitable.vmx",
                "--interface",
                "vmnet1",
                "--kali-source",
                "192.168.178.129",
            ]
        )
        self.assertEqual("vmware", vmware.provider)
        self.assertEqual("vmnet1", vmware.interface)
        self.assertEqual("192.168.178.129", vmware.kali_source)

        dashboard = parser.parse_args(
            [
                "dashboard",
                "--event-log",
                "/tmp/events.jsonl",
                "--transcript",
                "/tmp/student.typescript",
            ]
        )
        self.assertEqual("/tmp/student.typescript", dashboard.transcript)

    def test_native_layout_uses_two_real_left_right_terminals(self):
        """Verify that native layout uses two real left right terminals.

        This regression test fails if a future change breaks the described contract.
        """
        project = Path("/opt/ptas project")
        layout = build_terminator_layout(
            project,
            Path("/tmp/ptas-events.jsonl"),
            Path("/tmp/ptas-session.typescript"),
            "env PTAS_LLM_PROVIDER=rules ",
            "/bin/zsh",
        )

        definition = layout["layout"]
        panes = definition["ptas"]
        left = panes[0]["command"]
        right = panes[1]["command"]

        self.assertFalse(definition["vertical"])
        self.assertEqual(2, len(panes))
        self.assertEqual(0.62, panes[0]["ratio"])
        self.assertIn("script -q -f", left)
        self.assertIn("ptas project/ptas.sh", left)
        self.assertIn("student --event-log", left)
        self.assertIn("exec /bin/zsh -l", left)
        self.assertIn("ptas project/ptas.sh", right)
        self.assertIn("dashboard --event-log", right)
        self.assertIn("--transcript /tmp/ptas-session.typescript", right)

    def test_qterminal_uses_native_left_right_split_with_dashboard_command(self):
        """Verify that qterminal uses native left right split with dashboard command.

        This regression test fails if a future change breaks the described contract.
        """
        command = [
            "/opt/ptas/ptas.sh",
            "dashboard",
            "--transcript",
            "/tmp/session.typescript",
        ]
        completed = SimpleNamespace(returncode=0, stdout="('/terminals/right',)", stderr="")

        with patch(
            "Backend.split_terminal.shutil.which", return_value="/usr/bin/gdbus"
        ), patch(
            "Backend.split_terminal.subprocess.run", return_value=completed
        ) as run:
            result = split_qterminal_recommendations(
                "org.lxqt.QTerminal-1234",
                "/terminals/aabbcc",
                Path("/opt/ptas"),
                command,
            )

        arguments = run.call_args_list[0].args[0]
        self.assertEqual(0, result)
        self.assertIn("org.lxqt.QTerminal.Terminal.splitHorizontal", arguments)
        self.assertIn("'workingDirectory': <'/opt/ptas'>", arguments[-1])
        self.assertIn("'/opt/ptas/ptas.sh'", arguments[-1])
        self.assertIn("'/tmp/session.typescript'", arguments[-1])

    def test_qterminal_argument_map_escapes_paths(self):
        """Verify that qterminal argument map escapes paths.

        This regression test fails if a future change breaks the described contract.
        """
        serialized = qterminal_argument_map(
            Path("/opt/student's ptas"),
            ["/bin/example", "student's value"],
        )

        self.assertIn("student\\'s ptas", serialized)
        self.assertIn("student\\'s value", serialized)

    def test_recommendation_sequence_skips_previously_shown_items(self):
        """Verify that recommendation sequence skips previously shown items.

        This regression test fails if a future change breaks the described contract.
        """
        recommendations = [SimpleNamespace(id=10), SimpleNamespace(id=11)]

        selected = select_next_recommendation(recommendations, {10})
        exhausted = select_next_recommendation(recommendations, {10, 11})

        self.assertEqual(11, selected.id)
        self.assertIsNone(exhausted)

    def test_follow_up_advances_after_the_command_actually_executed(self):
        """Select the next unexecuted command after the student's chosen item."""

        suggestions = [
            {"purpose": "First", "command": "nmap -p 21 10.10.10.20"},
            {"purpose": "Second", "command": "nmap -p 22 10.10.10.20"},
            {"purpose": "Third", "command": "nmap -p 80 10.10.10.20"},
        ]
        completed = "nmap -p 22 10.10.10.20"

        selected = select_follow_up_suggestion(
            suggestions,
            {completed},
            completed,
        )

        self.assertEqual("nmap -p 80 10.10.10.20", selected["command"])

    def test_shell_ready_detection_waits_for_command_completion_prompt(self):
        """Verify that shell ready detection waits for command completion prompt.

        This regression test fails if a future change breaks the described contract.
        """
        running = "kali@kali:~$ nmap -sV 10.10.10.20\nStarting Nmap"
        completed = running + "\nNmap done\n└─$ "

        self.assertIsNone(SHELL_READY_PATTERN.search(running))
        self.assertIsNotNone(SHELL_READY_PATTERN.search(completed))

    def test_qterminal_transcript_preserves_command_and_completion_prompt(self):
        """Verify dashboard detection works with Kali QTerminal control sequences."""

        raw = (
            "\x1b]0;kali terminal\x07"
            "\x1b]7;file:///home/kali/project\x1b\\"
            "\x1b[32m└─$\x1b[0m "
            "nmap -Pn -sV -p 23 --script banner 192.168.121.130"
            "\x1b[55D\x1b[36mnmap\x1b[0m -Pn -sV -p 23 --script banner "
            "192.168.121.130\r\n"
            "23/tcp open telnet Linux telnetd\r\n"
            "Nmap done: 1 IP address scanned\r\n"
            "\x1b]666;vte.shell.precmd!\x1b\\"
            "\x1b[32m└─$\x1b[0m \x1b="
        )
        clean = sanitize_terminal_text(raw)

        self.assertEqual(
            "nmap -Pn -sV -p 23 --script banner 192.168.121.130",
            TerminalAnalyzer.extract_latest_prompt_command(clean),
        )
        self.assertIsNotNone(SHELL_READY_PATTERN.search(clean))

    def test_dashboard_joins_prompt_and_command_from_separate_file_reads(self):
        """Verify live command tracking survives QTerminal's chunk boundaries."""

        # QTerminal commonly flushes the rendered prompt before the student
        # begins typing. The next transcript read consequently starts with the
        # command rather than with the dollar-sign prompt.
        prompt_read = sanitize_terminal_text("\x1b[32m└─$\x1b[0m ")
        command_read = sanitize_terminal_text(
            "nmap -Pn -sV -p 21 --script ftp-syst,banner "
            "--script-timeout 20s 192.168.121.130\r\n"
            "21/tcp open ftp vsftpd 2.3.4\r\n"
            "Nmap done: 1 IP address scanned\r\n"
            "\x1b[32m└─$\x1b[0m "
        )

        context = _append_live_prompt_context(prompt_read, command_read)

        self.assertEqual(
            "nmap -Pn -sV -p 21 --script ftp-syst,banner "
            "--script-timeout 20s 192.168.121.130",
            TerminalAnalyzer.extract_latest_prompt_command(context),
        )
        self.assertIsNotNone(SHELL_READY_PATTERN.search(command_read))

    def test_dashboard_detects_kali_zsh_repainted_standalone_command(self):
        """Verify zsh cursor rewinds do not hide an actually executed command."""

        raw = (
            "\x1b[32m└─$\x1b[0m n"
            "\x1b[79D"
            "nmap -Pn -sV -p 21 --script ftp-syst,banner 192.168.121.130"
            "\x1b[71D"
            "\x1b[36mnmap\x1b[0m -Pn -sV -p 23 --script banner "
            "--script-timeout 20s 192.168.121.130\r\n"
        )
        clean = sanitize_terminal_text(raw)
        analyzer = TerminalAnalyzer(ScopeGuard(["192.168.121.130"]))

        self.assertEqual(
            "nmap -Pn -sV -p 23 --script banner --script-timeout 20s "
            "192.168.121.130",
            _extract_live_executed_command(analyzer, clean),
        )

    def test_dashboard_analyzes_completion_before_showing_model_follow_up(self):
        """Verify the live pane turns completed output into a new model command."""

        class StubSource:
            """Return one complete command transcript to the dashboard."""

            def read_new(self):
                return (
                    "└─$ nmap -sV -p 80 10.10.10.20\n"
                    "80/tcp open http Apache 2.4\n"
                    "Nmap done: 1 IP address scanned\n"
                    "└─$ "
                )

        class StubAdvisor:
            """Return a deterministic stand-in for locally generated JSON."""

            model = "test-model"

            def advise_next_command(self, result, excerpt, completed_commands):
                self.result = result
                self.excerpt = excerpt
                self.completed_commands = completed_commands
                return {
                    "purpose": "Inspect the observed HTTP response headers",
                    "command": "curl -I http://10.10.10.20/",
                    "source": "ollama",
                }

        with TemporaryDirectory() as directory:
            event_log = Path(directory) / "events.jsonl"
            transcript = Path(directory) / "terminal.typescript"
            transcript.touch()
            events = [
                {"kind": "target", "scope": "10.10.10.0/24"},
                {"kind": "assessment_completed", "scan_id": 42},
                {
                    "kind": "report_ready",
                    "scan_id": 42,
                    "command": "./ptas.sh report --scan-id 42 --output report.json",
                },
            ]
            event_log.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            advisor = StubAdvisor()
            output = io.StringIO()

            with patch(
                "Backend.terminal_workflow.FollowFileSource",
                return_value=StubSource(),
            ), patch(
                "Backend.terminal_workflow._optional_realtime_advisor",
                return_value=advisor,
            ), patch(
                "Backend.terminal_workflow._scan_validation_catalog",
                return_value=[],
            ), patch(
                "Backend.terminal_workflow.time.sleep",
                side_effect=KeyboardInterrupt,
            ), redirect_stdout(output):
                self.assertEqual(0, run_dashboard(event_log, transcript))

        rendered = output.getvalue()
        self.assertIn("[COMMAND ANALYSIS COMPLETE]", rendered)
        self.assertIn("Open http service", rendered)
        self.assertIn("Asking local Ollama model 'test-model'", rendered)
        self.assertIn("[NEXT ADAPTIVE RECOMMENDATION]", rendered)
        self.assertIn("Source: local Ollama model 'test-model'", rendered)
        self.assertIn("curl -I http://10.10.10.20/", rendered)
        self.assertIn("nmap -sV -p 80 10.10.10.20", advisor.completed_commands)

    def test_dashboard_advances_with_safe_fallback_after_model_rejection(self):
        """Keep the recommendation loop moving when local-model output is rejected."""

        class StubSource:
            def read_new(self):
                return (
                    "└─$ nmap -sV -p 23 --script banner 10.10.10.20\n"
                    "23/tcp open telnet Linux telnetd\n"
                    "Nmap done: 1 IP address scanned\n"
                    "└─$ "
                )

        class RejectingAdvisor:
            model = "test-model"
            last_rejection_reason = "the model repeated a command that was already completed"

            def advise_next_command(self, result, excerpt, completed_commands):
                return None

        fallback = {
            "purpose": "Review Telnet encryption support",
            "command": "nmap -Pn -p 23 --script telnet-encryption 10.10.10.20",
        }
        with TemporaryDirectory() as directory:
            event_log = Path(directory) / "events.jsonl"
            transcript = Path(directory) / "terminal.typescript"
            transcript.touch()
            event_log.write_text(
                "".join(
                    json.dumps(event) + "\n"
                    for event in (
                        {"kind": "target", "scope": "10.10.10.0/24"},
                        {"kind": "assessment_completed", "scan_id": 42},
                    )
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch(
                "Backend.terminal_workflow.FollowFileSource",
                return_value=StubSource(),
            ), patch(
                "Backend.terminal_workflow._optional_realtime_advisor",
                return_value=RejectingAdvisor(),
            ), patch(
                "Backend.terminal_workflow._scan_validation_catalog",
                return_value=[fallback],
            ), patch(
                "Backend.terminal_workflow.time.sleep",
                side_effect=KeyboardInterrupt,
            ), redirect_stdout(output):
                self.assertEqual(0, run_dashboard(event_log, transcript))

        rendered = output.getvalue()
        self.assertIn("[NO SAFE MODEL RECOMMENDATION]", rendered)
        self.assertIn("Reason: the model repeated", rendered)
        self.assertIn("[NEXT SAFETY FALLBACK]", rendered)
        self.assertIn("--script telnet-encryption", rendered)

    def test_dashboard_uses_registered_lab_gate_instead_of_safe_fallback(self):
        """Transition an exact verified lab target when model guidance ends."""

        class StubSource:
            def read_new(self):
                return (
                    "└─$ nmap -p 3306 --script mysql-info 10.10.10.20\n"
                    "3306/tcp open mysql MySQL 5.0\n"
                    "Nmap done: 1 IP address scanned\n"
                    "└─$ "
                )

        class EmptyAdvisor:
            model = "test-model"
            last_rejection_reason = "the model returned an empty command"

            def advise_next_command(
                self,
                result,
                excerpt,
                completed_commands,
                lab_access_command=None,
            ):
                self.lab_access_command = lab_access_command
                return None

        with TemporaryDirectory() as directory:
            event_log = Path(directory) / "events.jsonl"
            transcript = Path(directory) / "terminal.typescript"
            transcript.touch()
            event_log.write_text(
                "".join(
                    json.dumps(event) + "\n"
                    for event in (
                        {
                            "kind": "target",
                            "scope": "10.10.10.0/24",
                            "target": "10.10.10.20",
                        },
                        {
                            "kind": "assessment_completed",
                            "scan_id": 42,
                            "target": "10.10.10.20",
                        },
                    )
                ),
                encoding="utf-8",
            )
            advisor = EmptyAdvisor()
            output = io.StringIO()
            verified_lab = SimpleNamespace(
                name="msf2-local",
                target="10.10.10.20",
            )
            with patch(
                "Backend.terminal_workflow.FollowFileSource",
                return_value=StubSource(),
            ), patch(
                "Backend.terminal_workflow._optional_realtime_advisor",
                return_value=advisor,
            ), patch(
                "Backend.terminal_workflow._scan_validation_catalog",
                return_value=[],
            ), patch(
                "Backend.terminal_workflow._verified_metasploitable_lab",
                return_value=verified_lab,
            ), patch(
                "Backend.terminal_workflow.time.sleep",
                side_effect=KeyboardInterrupt,
            ), redirect_stdout(output):
                self.assertEqual(0, run_dashboard(event_log, transcript))

        rendered = output.getvalue()
        gate = "./ptas.sh access-test --scan-id 42 --lab msf2-local"
        self.assertIn("[METASPLOITABLE 2 LAB MODE ENABLED]", rendered)
        self.assertIn("[NEXT METASPLOITABLE 2 LAB STEP]", rendered)
        self.assertNotIn("[NO SAFE MODEL RECOMMENDATION]", rendered)
        self.assertIn(gate, rendered)
        self.assertEqual(gate, advisor.lab_access_command)

    def test_access_sequence_skips_previously_shown_exercises(self):
        """Verify that access sequence skips previously shown exercises.

        This regression test fails if a future change breaks the described contract.
        """
        exercises = [
            AccessExercise("ssh", "SSH", 22, "SSH", "Purpose", "ssh host", "Prompt"),
            AccessExercise("ftp", "FTP", 21, "FTP", "Purpose", "ftp host", "Prompt"),
        ]

        selected = select_next_access_exercise(exercises, {"ssh"})

        self.assertEqual("ftp", selected.key)
        self.assertIsNone(select_next_access_exercise(exercises, {"ssh", "ftp"}))

    def test_metasploitable_profile_rejects_loopback_cidr_and_weak_fingerprint(self):
        """Verify that metasploitable profile rejects loopback cidr and weak fingerprint.

        This regression test fails if a future change breaks the described contract.
        """
        with TemporaryDirectory() as directory:
            service = Metasploitable2LabService(Path(directory))
            for target in ("127.0.0.1", "192.168.56.0/24"):
                with self.subTest(target=target):
                    with self.assertRaises(LabVerificationError):
                        service._private_host(target)

            manifest = SimpleNamespace(
                profile="metasploitable2",
                provider="virtualbox",
                target="192.168.56.101",
            )
            scan = SimpleNamespace(
                target=SimpleNamespace(target_value="192.168.56.101")
            )
            findings = [SimpleNamespace(port=22), SimpleNamespace(port=80)]
            with self.assertRaises(LabVerificationError):
                service.verify_scan(manifest, scan, findings)

    def test_metasploitable_profile_builds_only_exercises_for_observed_ports(self):
        """Verify that metasploitable profile builds only exercises for observed ports.

        This regression test fails if a future change breaks the described contract.
        """
        exercises = Metasploitable2LabService.exercises(
            "192.168.56.101", {21, 22, 80}
        )

        self.assertEqual({21, 22}, {item.port for item in exercises})
        self.assertTrue(all("192.168.56.101" in item.command for item in exercises))
        self.assertTrue(all("msfadmin:msfadmin" not in item.command for item in exercises))

    def test_metasploitable_registration_rejects_nat_even_with_hostonly_adapter(self):
        """Verify that metasploitable registration rejects nat even with hostonly adapter.

        This regression test fails if a future change breaks the described contract.
        """
        machine_info = "\n".join(
            [
                'UUID="vm-uuid"',
                'nic1="hostonly"',
                'macaddress1="080027AABBCC"',
                'nic2="nat"',
            ]
        )
        with TemporaryDirectory() as directory:
            service = Metasploitable2LabService(Path(directory))
            with patch(
                "Backend.services.lab_profile_service.shutil.which",
                return_value="/usr/bin/VBoxManage",
            ), patch.object(service, "_run", return_value=machine_info):
                with self.assertRaises(LabVerificationError):
                    service.register_virtualbox(
                        "msf2", "192.168.56.101", "Metasploitable2"
                    )

    def test_vmware_registration_requires_hostonly_route_and_adapter(self):
        """Verify that vmware registration requires hostonly route and adapter.

        This regression test fails if a future change breaks the described contract.
        """
        with TemporaryDirectory() as directory:
            vmx = Path(directory) / "Metasploitable.vmx"
            vmx.write_text(
                "\n".join(
                    [
                        'uuid.bios = "56 4d aa bb cc dd ee ff-00 11 22 33 44 55 66 77"',
                        'ethernet0.connectionType = "hostonly"',
                        'ethernet0.generatedAddress = "00:0c:29:aa:bb:cc"',
                    ]
                ),
                encoding="utf-8",
            )
            service = Metasploitable2LabService(Path(directory))
            with patch.object(
                service,
                "_route_to_target",
                return_value=("vmnet1", "192.168.178.129"),
            ), patch.object(service, "verify_neighbor"):
                manifest = service.register_vmware(
                    "msf2",
                    "192.168.178.128",
                    str(vmx),
                    "vmnet1",
                    "192.168.178.129",
                )

        self.assertEqual("vmware", manifest.provider)
        self.assertEqual("192.168.178.128", manifest.target)
        self.assertEqual("00:0c:29:aa:bb:cc", manifest.expected_mac)

    def test_vmware_registration_rejects_bridged_adapter(self):
        """Verify that vmware registration rejects bridged adapter.

        This regression test fails if a future change breaks the described contract.
        """
        with TemporaryDirectory() as directory:
            vmx = Path(directory) / "Metasploitable.vmx"
            vmx.write_text(
                "\n".join(
                    [
                        'uuid.bios = "vm-uuid"',
                        'ethernet0.connectionType = "hostonly"',
                        'ethernet0.generatedAddress = "00:0c:29:aa:bb:cc"',
                        'ethernet1.connectionType = "bridged"',
                    ]
                ),
                encoding="utf-8",
            )
            service = Metasploitable2LabService(Path(directory))
            with patch.object(
                service,
                "_route_to_target",
                return_value=("vmnet1", "192.168.178.129"),
            ):
                with self.assertRaises(LabVerificationError):
                    service.register_vmware("msf2", "192.168.178.128", str(vmx))

    def test_vmware_network_registration_uses_ip_without_vmx_path(self):
        """Register two VMware guests using their isolated network identity."""

        with TemporaryDirectory() as directory:
            service = Metasploitable2LabService(Path(directory))
            with patch.object(
                service,
                "_route_to_target",
                return_value=("eth1", "192.168.121.129"),
            ), patch.object(
                service,
                "_default_route_interface",
                return_value="eth0",
            ), patch.object(
                service,
                "_neighbor_mac",
                return_value="00:0c:29:55:bc:f0",
            ):
                manifest = service.register_vmware_network(
                    "msf2-network",
                    "192.168.121.130",
                )

        self.assertEqual("vmware-network", manifest.provider)
        self.assertEqual("192.168.121.130", manifest.target)
        self.assertEqual("eth1", manifest.interface)
        self.assertEqual("00:0c:29:55:bc:f0", manifest.expected_mac)

    def test_vmware_network_registration_rejects_default_route(self):
        """Do not treat Kali's internet-facing/default interface as lab isolation."""

        with TemporaryDirectory() as directory:
            service = Metasploitable2LabService(Path(directory))
            with patch.object(
                service,
                "_route_to_target",
                return_value=("eth0", "192.168.121.129"),
            ), patch.object(
                service,
                "_default_route_interface",
                return_value="eth0",
            ):
                with self.assertRaisesRegex(
                    LabVerificationError,
                    "default network interface",
                ):
                    service.register_vmware_network(
                        "msf2-network",
                        "192.168.121.130",
                    )

    def test_ai_recommendations_exclude_exploit_dos_and_persistence_language(self):
        """Verify that ai recommendations exclude exploit dos and persistence language.

        This regression test fails if a future change breaks the described contract.
        """
        recommendation = AIRecommendationEngine().generate_recommendations(
            {"service": "smb", "port": 445, "severity": "HIGH"}
        )[0]

        combined = " ".join(str(value) for value in recommendation.values()).lower()
        forbidden = (
            "brute force",
            "eternalblue",
            "metasploit",
            "payload",
            "dos",
            "flood",
            "persistence",
            "pivot",
            "backdoor",
            "privilege escalation",
        )
        self.assertEqual("Realtime guided validation", recommendation["attack_technique"])
        self.assertFalse(any(term in combined for term in forbidden))

    def test_scan_stages_progress_from_quick_to_detailed(self):
        """Verify that scan stages progress from quick to detailed.

        This regression test fails if a future change breaks the described contract.
        """
        self.assertEqual(("QUICK", "FULL"), tuple(stage[0] for stage in SCAN_STAGES))
        self.assertEqual("VULNERABILITY", CVE_SCAN_STAGE[0])

    def test_failed_scan_response_becomes_a_readable_terminal_error(self):
        """Verify failed response data is reported without a missing-key traceback."""

        with self.assertRaisesRegex(
            RuntimeError,
            "VULNERABILITY scan failed: Scan timeout after 300 seconds",
        ):
            _completed_finding_count(
                "VULNERABILITY",
                {
                    "status": "FAILED",
                    "error": "Scan timeout after 300 seconds",
                },
            )

    def test_terminal_process_registers_all_sqlalchemy_relationships(self):
        """Verify a fresh terminal-only process can query without importing main.py."""

        project_root = Path(__file__).resolve().parents[1]
        code = """
from Backend.database import Base, SessionLocal, engine
import Backend.terminal_workflow
from Backend.repositories.vulnerability_repository import VulnerabilityRepository

Base.metadata.create_all(bind=engine)
with SessionLocal() as session:
    assert VulnerabilityRepository(session).get_vulnerabilities_by_scan_id(1) == []
"""
        environment = {
            **os.environ,
            "DATABASE_URL": "sqlite:///:memory:",
        }

        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=project_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )

        self.assertEqual(0, result.returncode, result.stderr)

    def test_vulnerability_stage_uses_safe_external_vulners_script(self):
        """Verify CVE correlation uses one bounded script and the fast port set."""

        command = NmapService()._build_command(
            "10.10.10.20", "VULNERABILITY", None, "/tmp/result.xml"
        )

        self.assertIn("vulners", command)
        self.assertNotIn("(vuln and safe)", command)
        self.assertIn("-F", command)
        self.assertIn("-T4", command)
        self.assertEqual(
            "30s",
            command[command.index("--script-timeout") + 1],
        )

    def test_terminal_labels_observations_and_cve_candidates_differently(self):
        """Verify terminal output does not present every observation as proven."""

        observed = _finding_display_label(
            {"vulnerability_type": "EXPOSED_SERVICE", "severity": "MEDIUM"}
        )
        candidate = _finding_display_label(
            {"vulnerability_type": "CVE_CANDIDATE", "severity": "INFO"}
        )

        self.assertEqual("[OBSERVED SERVICE] [REVIEW: MEDIUM]", observed)
        self.assertEqual("[CVE CANDIDATE] [REVIEW: INFO]", candidate)

    def test_cve_correlation_is_candidate_unless_explicitly_vulnerable(self):
        """Verify that cve correlation is candidate unless explicitly vulnerable.

        This regression test fails if a future change breaks the described contract.
        """
        base_port = {
            "port": 443,
            "state": "open",
            "service": "https",
            "version": "1.0",
        }
        correlated = {
            **base_port,
            "scripts": [
                {"id": "vulners", "output": "CVE-2024-12345 9.8 example"}
            ],
        }
        explicit = {
            **base_port,
            "scripts": [
                {
                    "id": "http-vuln-cve-test",
                    "output": "State: VULNERABLE\nIDs: CVE-2024-54321",
                }
            ],
        }
        parser = VulnerabilityParser()

        candidate_findings = parser._parse_host_vulnerabilities(
            {"host_ip": "10.10.10.20", "ports": [correlated]}
        )
        confirmed_findings = parser._parse_host_vulnerabilities(
            {"host_ip": "10.10.10.20", "ports": [explicit]}
        )

        self.assertTrue(
            any(item["type"] == "CVE_CANDIDATE" for item in candidate_findings)
        )
        self.assertTrue(
            any(item["type"] == "CONFIRMED_CVE" for item in confirmed_findings)
        )

    def test_exploitdb_enrichment_returns_multiple_cve_references(self):
        """Verify that exploitdb enrichment returns multiple cve references.

        This regression test fails if a future change breaks the described contract.
        """
        payload = {
            "RESULTS_EXPLOIT": [
                {
                    "Title": "Example one",
                    "EDB-ID": "10001",
                    "Verified": "1",
                    "Codes": "CVE-2024-10001;CVE-2024-10002",
                    "Type": "remote",
                    "Platform": "linux",
                    "Path": "/local/10001.py",
                },
                {
                    "Title": "Example two",
                    "EDB-ID": "10002",
                    "Verified": "0",
                    "Codes": "CVE-2024-10003",
                    "Type": "webapps",
                    "Platform": "multiple",
                    "Path": "/local/10002.txt",
                },
            ]
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=__import__("json").dumps(payload),
        )
        service = ExploitDbService(executable="searchsploit")

        with patch("Backend.services.exploitdb_service.subprocess.run", return_value=completed):
            references = service.search("Example Server", "1.2.3")

        self.assertEqual(2, len(references))
        self.assertEqual(
            ["CVE-2024-10001", "CVE-2024-10002"], references[0]["cves"]
        )
        self.assertTrue(references[0]["verified"])

    def test_exploitdb_enrichment_requires_a_detected_version(self):
        """Verify that exploitdb enrichment requires a detected version.

        This regression test fails if a future change breaks the described contract.
        """
        service = ExploitDbService(executable="searchsploit")

        with patch("Backend.services.exploitdb_service.subprocess.run") as run:
            self.assertEqual([], service.search("mysql", None))

        run.assert_not_called()

    def test_service_scanner_selects_tools_by_detected_service(self):
        """Verify that service scanner selects tools by detected service.

        This regression test fails if a future change breaks the described contract.
        """
        findings = [
            SimpleNamespace(
                port=443,
                service="https",
                vulnerability_type="EXPOSED_SERVICE",
            ),
            SimpleNamespace(
                port=445,
                service="microsoft-ds",
                vulnerability_type="EXPOSED_SERVICE",
            ),
            SimpleNamespace(
                port=3306,
                service="mysql",
                vulnerability_type="EXPOSED_SERVICE",
            ),
            SimpleNamespace(
                port=5432,
                service="postgresql",
                vulnerability_type="EXPOSED_SERVICE",
            ),
            SimpleNamespace(
                port=6379,
                service="redis",
                vulnerability_type="EXPOSED_SERVICE",
            ),
        ]
        scanner = ServiceScanService()

        with patch.object(scanner, "_available", side_effect=lambda tool: f"/tools/{tool}"):
            checks = scanner.build_checks("10.10.10.20", findings)

        selected = {check.tool for check in checks}
        self.assertTrue({"whatweb", "curl", "nikto", "sslscan"}.issubset(selected))
        self.assertIn("enum4linux-ng", selected)
        self.assertTrue({"mysqladmin", "pg_isready", "redis-cli"}.issubset(selected))
        self.assertNotIn("nuclei", selected)
        self.assertNotIn("ffuf", selected)

    def test_service_scanner_does_not_guess_from_unrelated_findings(self):
        """Verify that service scanner does not guess from unrelated findings.

        This regression test fails if a future change breaks the described contract.
        """
        findings = [
            SimpleNamespace(
                port=None,
                service="OS",
                vulnerability_type="OS_DETECTION",
            )
        ]
        scanner = ServiceScanService()

        with patch.object(scanner, "_available", return_value="/tools/example"):
            checks = scanner.build_checks("10.10.10.20", findings)

        self.assertEqual([], checks)

    def test_html_report_is_standalone_escaped_and_print_friendly(self):
        """Verify that html report is standalone escaped and print friendly.

        This regression test fails if a future change breaks the described contract.
        """
        report = {
            "report_metadata": {
                "title": "Lab <Assessment>",
                "description": "Authorized training report",
                "scan_id": 22,
                "scan_type": "FULL",
                "scan_status": "COMPLETED",
                "generated_at": "2026-08-19T00:00:00Z",
            },
            "vulnerabilities": [
                {
                    "host": "10.10.10.20",
                    "port": 443,
                    "service": "https",
                    "type": "CVE_CANDIDATE",
                    "severity": "HIGH",
                    "description": "Candidate <script>",
                    "version": "Example 1.2.3",
                    "cves": "CVE-2024-12345",
                    "remediation": "Verify vendor advisory",
                    "status": "OPEN",
                    "recommendations": [
                        {
                            "attack_technique": "Guided validation",
                            "exploitation_method": "Review configuration",
                            "risk_level": "LOW",
                            "priority": 3,
                            "status": "PENDING_APPROVAL",
                            "execution_steps": "curl -I https://10.10.10.20/",
                        }
                    ],
                }
            ],
        }

        rendered = HtmlReportRenderer.render(report)

        self.assertIn("<!doctype html>", rendered.lower())
        self.assertIn("Lab &lt;Assessment&gt;", rendered)
        self.assertNotIn("Candidate <script>", rendered)
        self.assertIn("CVE-2024-12345", rendered)
        self.assertIn("@media print", rendered)
        self.assertIn("curl -I", rendered)

        with TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            json_path.write_text(__import__("json").dumps(report), encoding="utf-8")

            self.assertEqual(0, render_existing_report(json_path))
            self.assertTrue(json_path.with_suffix(".html").is_file())

    def test_realtime_fallback_suggestions_are_non_destructive_and_deduplicated(self):
        """Verify that realtime fallback suggestions are non destructive and deduplicated.

        This regression test fails if a future change breaks the described contract.
        """
        findings = [
            SimpleNamespace(id=1, port=80, service="http"),
            SimpleNamespace(id=2, port=80, service="http"),
            SimpleNamespace(id=3, port=22, service="ssh"),
        ]

        suggestions = validation_suggestions(findings, "10.10.10.20")
        steps = [item["purpose"] for item in suggestions]
        commands = [item["command"] for item in suggestions]

        self.assertEqual(2, len(suggestions))
        self.assertTrue(all(command.startswith("nmap ") for command in commands))
        self.assertTrue(all("10.10.10.20" in command for command in commands))
        self.assertTrue(any("http-title,http-headers" in command for command in commands))
        self.assertTrue(any("ssh2-enum-algos,ssh-hostkey" in command for command in commands))
        self.assertTrue(any("10.10.10.20:80" in step for step in steps))
        self.assertTrue(any("10.10.10.20:22" in step for step in steps))
        self.assertTrue(all("record the evidence" in step for step in steps))
        self.assertTrue(all("stop before credential" not in step for step in steps))
        self.assertIn("gated access-test workflow", RECOMMENDATION_SAFETY_NOTICE)
        combined = " ".join(steps + commands).lower()
        forbidden = ("hydra", "password", "metasploit", "exploit", "--script vuln")
        self.assertFalse(any(term in combined for term in forbidden))

    def test_only_allowlisted_scoped_steps_are_treated_as_manual_commands(self):
        """Verify old prose and unsafe/out-of-scope steps are not shown as commands."""

        target = "10.10.10.20"

        self.assertTrue(
            _is_manual_validation_command(
                "nmap -Pn -sV -p 23 --script banner 10.10.10.20",
                target,
            )
        )
        self.assertFalse(
            _is_manual_validation_command(
                "Review the current evidence and document it.",
                target,
            )
        )
        self.assertFalse(
            _is_manual_validation_command(
                "nmap -sV 203.0.113.10",
                target,
            )
        )

    def test_realtime_model_suggestions_are_filtered_before_persistence(self):
        """Verify that realtime model suggestions are filtered before persistence.

        This regression test fails if a future change breaks the described contract.
        """
        class StubAdvisor:
            """Provide the StubAdvisor test double used by this test module.

            It records or returns deterministic data so the tests do not require an
            external process.
            """
            def advise_commands(self, *_args, **_kwargs):
                """Support the test scenario by providing structured commands.

                The deterministic implementation keeps the test focused on PTAS rather
                than external systems.
                """
                return [
                    {
                        "purpose": "Record the observed HTTP service.",
                        "command": "nmap -sV -p 80 10.10.10.20",
                    },
                    {
                        "purpose": "Attempt exploitation.",
                        "command": "msfconsole 10.10.10.20",
                    },
                    {
                        "purpose": "Inspect another host.",
                        "command": "curl -I http://203.0.113.10/",
                    },
                ]

        findings = [SimpleNamespace(id=1, port=80, service="http", severity="INFO")]

        suggestions = validation_suggestions(
            findings,
            "10.10.10.20",
            advisor=StubAdvisor(),
            scan_id=42,
            lab_name="msf2",
        )

        self.assertEqual(1, len(suggestions))
        self.assertIn("nmap -sV", suggestions[0]["command"])
        self.assertEqual("realtime-ollama", suggestions[0]["source"])

    def test_suggestions_are_persisted_for_report_generation(self):
        """Verify that suggestions are persisted for report generation.

        This regression test fails if a future change breaks the described contract.
        """
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        try:
            user = User(full_name="Student", email="student@example.test", password_hash="x")
            db.add(user)
            db.flush()
            project = Project(user_id=user.id, project_name="Lab")
            db.add(project)
            db.flush()
            target = Target(
                project_id=project.id,
                target_name="Target",
                target_type="HOST",
                target_value="10.10.10.20",
            )
            db.add(target)
            db.flush()
            scan = Scan(target_id=target.id, scan_name="Full", scan_type="FULL")
            db.add(scan)
            db.flush()
            finding = Vulnerability(
                scan_id=scan.id,
                host="10.10.10.20",
                port=80,
                service="http",
                vulnerability_type="EXPOSED_SERVICE",
                severity="INFO",
                description="HTTP service exposed",
            )
            db.add(finding)
            db.commit()

            suggestions = validation_suggestions([finding], target.target_value)
            self.assertEqual(1, persist_validation_suggestions(db, suggestions))
            self.assertEqual(0, persist_validation_suggestions(db, suggestions))

            saved = db.query(Recommendation).filter_by(vulnerability_id=finding.id).all()
            self.assertEqual(1, len(saved))
            self.assertTrue(saved[0].execution_steps.startswith("nmap "))
            self.assertIn("http-title,http-headers", saved[0].execution_steps)
        finally:
            db.close()
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
