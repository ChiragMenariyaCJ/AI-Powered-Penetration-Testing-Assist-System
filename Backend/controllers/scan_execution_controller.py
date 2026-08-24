"""Translate authorized scan-execution routes into use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scope_validation_repository import (
    ScopeValidationRepository,
)
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.usecases.scan_execution_usecase import ScanExecutionUseCase


@trace_controller
class ScanExecutionController:
    """Connect scan execution HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        scan_repository = ScanRepository(db)
        target_repository = TargetRepository(db)
        scope_validation_repository = ScopeValidationRepository(db)
        project_repository = ProjectRepository(db)
        vulnerability_repository = VulnerabilityRepository(db)

        self.scan_execution_usecase = ScanExecutionUseCase(
            scan_repository,
            target_repository,
            scope_validation_repository,
            project_repository,
            vulnerability_repository,
        )

    # Forward execute scan to the scan execution use case so this controller contains no business or SQL logic.
    def execute_scan(self, scan_id: int, project_id: int):
        """Delegate the request to execute scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_execution_usecase.execute_scan_on_target(
            scan_id, project_id
        )

    # Forward get scan results to the scan execution use case so this controller contains no business or SQL logic.
    def get_scan_results(self, scan_id: int):
        """Delegate the request to get scan results through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_execution_usecase.get_scan_results(scan_id)

    # Forward validate nmap availability to the scan execution use case so this controller contains no business or SQL logic.
    def validate_nmap_availability(self):
        """Delegate the request to validate nmap availability through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_execution_usecase.validate_nmap_availability()
