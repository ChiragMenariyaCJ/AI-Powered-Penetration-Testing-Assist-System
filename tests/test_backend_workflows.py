import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from Backend.database import Base
from Backend.models.project_model import Project
from Backend.models.recommendation_model import Recommendation  # noqa: F401
from Backend.models.report_model import Report  # noqa: F401
from Backend.models.scan_model import Scan
from Backend.models.scope_validation_model import ScopeValidation
from Backend.models.target_model import Target
from Backend.models.user_model import User
from Backend.models.vulnerability_model import Vulnerability  # noqa: F401
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.scope_validation_repository import ScopeValidationRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.schemas.report_schema import ReportResponse
from Backend.usecases.report_usecase import ReportUseCase
from Backend.usecases.scan_execution_usecase import ScanExecutionUseCase
from Backend.utils.password_utils import hash_password, verify_password


class FakeNmapService:
    def execute_scan(self, target: str, scan_type: str) -> dict:
        return {
            "status": "COMPLETED",
            "started_at": "2026-01-01T00:00:00",
            "hosts": [
                {
                    "host_ip": target,
                    "ports": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "version": "test-version",
                        }
                    ],
                    "open_ports": 1,
                    "status": "UP",
                    "os_detection": None,
                }
            ],
        }


class BackendWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine)()

        user = User(
            full_name="Terminal Tester",
            email="terminal@example.test",
            password_hash=hash_password("safe-test-password"),
        )
        self.session.add(user)
        self.session.flush()

        self.project = Project(user_id=user.id, project_name="Authorized lab")
        self.session.add(self.project)
        self.session.flush()

        self.target = Target(
            project_id=self.project.id,
            target_name="Lab host",
            target_type="HOST",
            target_value="10.10.10.20",
        )
        self.session.add(self.target)
        self.session.flush()

        self.scan = Scan(
            target_id=self.target.id,
            scan_name="Safe discovery",
            scan_type="QUICK",
        )
        self.scope = ScopeValidation(
            project_id=self.project.id,
            scope_rule_name="Lab subnet",
            scope_type="CIDR",
            scope_value="10.10.10.0/24",
            is_inclusive=True,
        )
        self.session.add_all([self.scan, self.scope])
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_password_hashing_works_with_supported_bcrypt(self):
        hashed = hash_password("safe-test-password")
        self.assertTrue(verify_password("safe-test-password", hashed))
        self.assertFalse(verify_password("wrong-password", hashed))

    def test_scan_execution_uses_project_repository_for_scope(self):
        usecase = ScanExecutionUseCase(
            ScanRepository(self.session),
            TargetRepository(self.session),
            ScopeValidationRepository(self.session),
            ProjectRepository(self.session),
            VulnerabilityRepository(self.session),
        )
        usecase.nmap_service = FakeNmapService()

        result = usecase.execute_scan_on_target(self.scan.id, self.project.id)

        self.assertEqual("COMPLETED", result["status"])
        self.assertEqual(1, result["findings_persisted"])
        self.session.refresh(self.scan)
        self.assertEqual("COMPLETED", self.scan.status)
        persisted = VulnerabilityRepository(
            self.session
        ).get_vulnerabilities_by_scan_id(self.scan.id)
        self.assertEqual(1, len(persisted))

    def test_scan_rejects_mismatched_project(self):
        other_project = Project(
            user_id=self.project.user_id,
            project_name="Different project",
        )
        self.session.add(other_project)
        self.session.commit()
        usecase = ScanExecutionUseCase(
            ScanRepository(self.session),
            TargetRepository(self.session),
            ScopeValidationRepository(self.session),
            ProjectRepository(self.session),
            VulnerabilityRepository(self.session),
        )

        with self.assertRaises(HTTPException) as raised:
            usecase.execute_scan_on_target(self.scan.id, other_project.id)

        self.assertEqual(400, raised.exception.status_code)

    def test_report_generation_and_response_schema(self):
        generated = ReportUseCase.generate_report(
            self.session,
            self.scan.id,
            "Terminal assessment",
        )
        self.assertEqual("success", generated["status"])

        payload = ReportUseCase.get_report(self.session, generated["id"])
        response = ReportResponse.model_validate(payload)

        self.assertEqual(self.scan.id, response.scan_id)
        self.assertEqual(self.scan.id, response.scan_metadata.scan_id)


if __name__ == "__main__":
    unittest.main()
