"""Exercise backend layers, logging decorators, and database-backed workflows."""

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, Request, Response
from fastapi.routing import APIRoute
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from Backend.api_logging import (
    LoggedRoute,
    trace_controller,
    trace_repository,
    trace_usecase,
)
from Backend.database import Base
from Backend.main import ROUTERS
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
from Backend.repositories.user_repository import UserRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.schemas.report_schema import ReportResponse
from Backend.usecases.auth_usecase import AuthUseCase
from Backend.usecases.report_usecase import ReportUseCase
from Backend.usecases.scan_execution_usecase import ScanExecutionUseCase
from Backend.utils.password_utils import hash_password, verify_password


class FakeNmapService:
    """Provide the FakeNmapService test double used by this test module.

    It records or returns deterministic data so the tests do not require an external
    process.
    """
    def execute_scan(self, target: str, scan_type: str) -> dict:
        """Support the test scenario by providing the execute scan behavior.

        The deterministic implementation keeps the test focused on PTAS rather than
        external systems.
        """
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


class TimedOutNmapService:
    """Return the same controlled timeout result produced by the real Nmap adapter."""

    def execute_scan(self, target: str, scan_type: str) -> dict:
        """Simulate Nmap reaching its configured execution deadline."""

        return {
            "status": "FAILED",
            "error": "Scan timeout after 300 seconds",
        }


class BackendWorkflowTests(unittest.TestCase):
    """Group regression tests for BackendWorkflow.

    Each test documents one externally observable behavior that future changes must
    preserve.
    """
    def setUp(self):
        """Create the isolated records and collaborators required by each test.

        A fresh setup prevents state from one regression scenario affecting another.
        """
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
        """Release database and temporary resources created for the completed test.

        Cleanup keeps later tests independent and avoids leaked connections or files.
        """
        self.session.close()
        self.engine.dispose()

    def test_password_hashing_works_with_supported_bcrypt(self):
        """Verify that password hashing works with supported bcrypt.

        This regression test fails if a future change breaks the described contract.
        """
        hashed = hash_password("safe-test-password")
        self.assertTrue(verify_password("safe-test-password", hashed))
        self.assertFalse(verify_password("wrong-password", hashed))

    def test_login_returns_user_identity_for_the_terminal_api_client(self):
        """Verify that login returns user identity for the terminal api client.

        This regression test fails if a future change breaks the described contract.
        """
        request = SimpleNamespace(
            email="terminal@example.test",
            password="safe-test-password",
        )

        result = AuthUseCase(UserRepository(self.session)).login(request)

        self.assertEqual("terminal@example.test", result["user"]["email"])
        self.assertEqual("Terminal Tester", result["user"]["full_name"])
        self.assertIn("access_token", result)

    def test_every_feature_endpoint_uses_controller_logging(self):
        """Verify that every feature endpoint uses controller logging.

        This regression test fails if a future change breaks the described contract.
        """
        routes = [
            route
            for router, _, _ in ROUTERS
            for route in router.routes
            if isinstance(route, APIRoute)
        ]

        self.assertGreater(len(routes), 0)
        self.assertTrue(all(isinstance(route, LoggedRoute) for route in routes))

    def test_request_logger_reports_handler_status_and_duration(self):
        """Verify that request logger reports handler status and duration.

        This regression test fails if a future change breaks the described contract.
        """
        async def endpoint():
            return {"ok": True}

        async def fake_handler(_: Request):
            return Response(status_code=201)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/demo",
            "scheme": "http",
            "server": ("test", 80),
            "client": ("test", 1),
            "root_path": "",
            "query_string": b"",
            "headers": [],
        }
        with patch.object(APIRoute, "get_route_handler", return_value=fake_handler):
            route = LoggedRoute("/demo", endpoint=endpoint, methods=["POST"])
            with self.assertLogs("uvicorn.error", level="INFO") as captured:
                response = asyncio.run(route.get_route_handler()(Request(scope)))

        output = "\n".join(captured.output)
        self.assertEqual(201, response.status_code)
        self.assertIn("API request started", output)
        self.assertIn("BackendWorkflowTests", output)
        self.assertIn("status=201", output)
        self.assertIn("duration=", output)

    def test_controller_decorator_reports_called_method(self):
        """Verify that controller decorator reports called method.

        This regression test fails if a future change breaks the described contract.
        """
        @trace_controller
        class DemoController:
            """Provide the DemoController test double used by this test module.

            It records or returns deterministic data so the tests do not require an
            external process.
            """
            def load_record(self):
                """Support the test scenario by providing the load record behavior.

                The deterministic implementation keeps the test focused on PTAS rather
                than external systems.
                """
                return {"id": 7}

        with self.assertLogs("uvicorn.error", level="INFO") as captured:
            result = DemoController().load_record()

        output = "\n".join(captured.output)
        self.assertEqual({"id": 7}, result)
        self.assertIn("API controller calling", output)
        self.assertIn("DemoController.load_record", output)
        self.assertIn("API controller returned", output)
        self.assertIn("duration=", output)

    def test_usecase_and_repository_decorators_report_each_layer(self):
        """Verify that usecase and repository decorators report each layer.

        This regression test fails if a future change breaks the described contract.
        """
        @trace_repository
        class DemoRepository:
            """Provide the DemoRepository test double used by this test module.

            It records or returns deterministic data so the tests do not require an
            external process.
            """
            def load_record(self):
                """Support the test scenario by providing the load record behavior.

                The deterministic implementation keeps the test focused on PTAS rather
                than external systems.
                """
                return {"id": 7}

        @trace_usecase
        class DemoUseCase:
            """Provide the DemoUseCase test double used by this test module.

            It records or returns deterministic data so the tests do not require an
            external process.
            """
            def __init__(self):
                """Support the test scenario by providing the init behavior.

                The deterministic implementation keeps the test focused on PTAS rather
                than external systems.
                """
                self.repository = DemoRepository()

            def get_record(self):
                """Support the test scenario by providing the get record behavior.

                The deterministic implementation keeps the test focused on PTAS rather
                than external systems.
                """
                return self.repository.load_record()

        with self.assertLogs("uvicorn.error", level="INFO") as captured:
            result = DemoUseCase().get_record()

        output = "\n".join(captured.output)
        self.assertEqual({"id": 7}, result)
        self.assertIn("API usecase calling", output)
        self.assertIn("DemoUseCase.get_record", output)
        self.assertIn("API repository calling", output)
        self.assertIn("DemoRepository.load_record", output)
        self.assertIn("API repository returned", output)
        self.assertIn("API usecase returned", output)

    def test_scan_execution_uses_project_repository_for_scope(self):
        """Verify that scan execution uses project repository for scope.

        This regression test fails if a future change breaks the described contract.
        """
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

    def test_scan_timeout_returns_gateway_timeout_and_persists_the_error(self):
        """Verify a subprocess timeout becomes HTTP 504 instead of a false 200 OK."""

        usecase = ScanExecutionUseCase(
            ScanRepository(self.session),
            TargetRepository(self.session),
            ScopeValidationRepository(self.session),
            ProjectRepository(self.session),
            VulnerabilityRepository(self.session),
        )
        usecase.nmap_service = TimedOutNmapService()

        with self.assertRaises(HTTPException) as raised:
            usecase.execute_scan_on_target(self.scan.id, self.project.id)

        self.assertEqual(504, raised.exception.status_code)
        self.assertEqual(
            "Scan timeout after 300 seconds",
            raised.exception.detail,
        )
        self.session.refresh(self.scan)
        self.assertEqual("FAILED", self.scan.status)
        self.assertEqual("Scan timeout after 300 seconds", self.scan.scan_result)

    def test_scan_rejects_mismatched_project(self):
        """Verify that scan rejects mismatched project.

        This regression test fails if a future change breaks the described contract.
        """
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
        """Verify that report generation and response schema.

        This regression test fails if a future change breaks the described contract.
        """
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
