"""Translate scan-record routes into scan use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.usecases.scan_usecase import ScanUseCase


@trace_controller
class ScanController:
    """Connect scan HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        scan_repository = ScanRepository(db)
        target_repository = TargetRepository(db)

        self.scan_usecase = ScanUseCase(
            scan_repository,
            target_repository,
        )

    def create_scan(self, request):
        """Delegate the request to create scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.create_scan(request)

    def get_all_scans(self, target_id: int | None = None):
        """Delegate the request to get all scans through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.get_all_scans(target_id)

    def get_scan_by_id(self, scan_id: int):
        """Delegate the request to get scan by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.get_scan_by_id(scan_id)

    def update_scan(self, scan_id: int, request):
        """Delegate the request to update scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.update_scan(scan_id, request)

    def delete_scan(self, scan_id: int):
        """Delegate the request to delete scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.delete_scan(scan_id)
