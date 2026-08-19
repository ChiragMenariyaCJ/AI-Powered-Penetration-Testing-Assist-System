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
from Backend.terminal_workflow import (
    CVE_SCAN_STAGE,
    SHELL_READY_PATTERN,
    SCAN_STAGES,
    persist_validation_suggestions,
    select_next_recommendation,
    render_existing_report,
    select_next_access_exercise,
    validation_suggestions,
)


class TerminalWorkflowTests(unittest.TestCase):
    def test_start_and_report_commands_are_available(self):
        parser = build_parser()

        start = parser.parse_args(["start", "--no-tmux"])
        report = parser.parse_args(
            ["report", "--scan-id", "7", "--output", "reports/test.json"]
        )

        self.assertTrue(start.no_tmux)
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

    def test_recommendation_sequence_skips_previously_shown_items(self):
        recommendations = [SimpleNamespace(id=10), SimpleNamespace(id=11)]

        selected = select_next_recommendation(recommendations, {10})
        exhausted = select_next_recommendation(recommendations, {10, 11})

        self.assertEqual(11, selected.id)
        self.assertIsNone(exhausted)

    def test_shell_ready_detection_waits_for_command_completion_prompt(self):
        running = "kali@kali:~$ nmap -sV 10.10.10.20\nStarting Nmap"
        completed = running + "\nNmap done\n└─$ "

        self.assertIsNone(SHELL_READY_PATTERN.search(running))
        self.assertIsNotNone(SHELL_READY_PATTERN.search(completed))

    def test_access_sequence_skips_previously_shown_exercises(self):
        exercises = [
            AccessExercise("ssh", "SSH", 22, "SSH", "Purpose", "ssh host", "Prompt"),
            AccessExercise("ftp", "FTP", 21, "FTP", "Purpose", "ftp host", "Prompt"),
        ]

        selected = select_next_access_exercise(exercises, {"ssh"})

        self.assertEqual("ftp", selected.key)
        self.assertIsNone(select_next_access_exercise(exercises, {"ssh", "ftp"}))

    def test_metasploitable_profile_rejects_loopback_cidr_and_weak_fingerprint(self):
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
        exercises = Metasploitable2LabService.exercises(
            "192.168.56.101", {21, 22, 80}
        )

        self.assertEqual({21, 22}, {item.port for item in exercises})
        self.assertTrue(all("192.168.56.101" in item.command for item in exercises))
        self.assertTrue(all("msfadmin:msfadmin" not in item.command for item in exercises))

    def test_metasploitable_registration_rejects_nat_even_with_hostonly_adapter(self):
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

    def test_ai_recommendations_exclude_exploit_dos_and_persistence_language(self):
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
        self.assertEqual(("QUICK", "FULL"), tuple(stage[0] for stage in SCAN_STAGES))
        self.assertEqual("VULNERABILITY", CVE_SCAN_STAGE[0])

    def test_vulnerability_stage_uses_safe_external_vulners_script(self):
        command = NmapService()._build_command(
            "10.10.10.20", "VULNERABILITY", None, "/tmp/result.xml"
        )

        self.assertIn("(vuln and safe)", command)
        self.assertNotIn("vuln", command)

    def test_cve_correlation_is_candidate_unless_explicitly_vulnerable(self):
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
        service = ExploitDbService(executable="searchsploit")

        with patch("Backend.services.exploitdb_service.subprocess.run") as run:
            self.assertEqual([], service.search("mysql", None))

        run.assert_not_called()

    def test_service_scanner_selects_tools_by_detected_service(self):
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
        findings = [
            SimpleNamespace(id=1, port=80, service="http"),
            SimpleNamespace(id=2, port=80, service="http"),
            SimpleNamespace(id=3, port=22, service="ssh"),
        ]

        suggestions = validation_suggestions(findings, "10.10.10.20")
        steps = [item["purpose"] for item in suggestions]

        self.assertEqual(2, len(suggestions))
        self.assertTrue(all(item["command"] is None for item in suggestions))
        self.assertTrue(any("10.10.10.20:80" in step for step in steps))
        self.assertTrue(any("10.10.10.20:22" in step for step in steps))
        forbidden = ("hydra", "password", "metasploit", "exploit", "--script vuln")
        self.assertFalse(any(term in " ".join(steps).lower() for term in forbidden))

    def test_realtime_model_suggestions_are_filtered_before_persistence(self):
        class StubAdvisor:
            def advise_prompt(self, *_args, **_kwargs):
                return [
                    "Run nmap -sV -p 80 10.10.10.20 and record the observed service.",
                    "Run msfconsole against 10.10.10.20",
                    "Run curl -I http://203.0.113.10/",
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
        self.assertIn("nmap -sV", suggestions[0]["purpose"])
        self.assertEqual("realtime-ollama", suggestions[0]["source"])

    def test_suggestions_are_persisted_for_report_generation(self):
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
            self.assertIn("non-destructive", saved[0].execution_steps)
        finally:
            db.close()
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
