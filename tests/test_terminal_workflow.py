import unittest
from types import SimpleNamespace
from unittest.mock import patch

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
from Backend.services.vulnerability_parser import VulnerabilityParser
from Backend.terminal_workflow import (
    CVE_SCAN_STAGE,
    SCAN_STAGES,
    persist_validation_suggestions,
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

    def test_hard_coded_suggestions_are_non_destructive_and_deduplicated(self):
        findings = [
            SimpleNamespace(id=1, port=80, service="http"),
            SimpleNamespace(id=2, port=80, service="http"),
            SimpleNamespace(id=3, port=22, service="ssh"),
        ]

        suggestions = validation_suggestions(findings, "10.10.10.20")
        commands = [item["command"] for item in suggestions]

        self.assertEqual(2, len(suggestions))
        self.assertTrue(any(command.startswith("curl -k -I") for command in commands))
        self.assertTrue(any("ssh2-enum-algos" in command for command in commands))
        forbidden = ("hydra", "password", "metasploit", "exploit", "--script vuln")
        self.assertFalse(any(term in " ".join(commands).lower() for term in forbidden))

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
            self.assertIn("curl", saved[0].execution_steps)
        finally:
            db.close()
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
