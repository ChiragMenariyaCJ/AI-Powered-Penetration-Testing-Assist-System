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
    """Connect scan execution handlers to scoped Nmap orchestration."""

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

    def execute_scan(self, scan_id: int, project_id: int):
        return self.scan_execution_usecase.execute_scan_on_target(
            scan_id, project_id
        )

    def get_scan_results(self, scan_id: int):
        return self.scan_execution_usecase.get_scan_results(scan_id)

    def validate_nmap_availability(self):
        return self.scan_execution_usecase.validate_nmap_availability()
