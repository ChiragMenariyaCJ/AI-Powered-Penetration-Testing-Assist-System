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

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        scan_repository = ScanRepository(db)
        target_repository = TargetRepository(db)

        self.scan_usecase = ScanUseCase(
            scan_repository,
            target_repository,
        )

    # Forward create scan to the scan use case so this controller contains no business or SQL logic.
    def create_scan(self, request):
        """Delegate the request to create scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.create_scan(request)

    # Forward get all scans to the scan use case so this controller contains no business or SQL logic.
    def get_all_scans(self, target_id: int | None = None):
        """Delegate the request to get all scans through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.get_all_scans(target_id)

    # Forward get scan by id to the scan use case so this controller contains no business or SQL logic.
    def get_scan_by_id(self, scan_id: int):
        """Delegate the request to get scan by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.get_scan_by_id(scan_id)

    # Forward update scan to the scan use case so this controller contains no business or SQL logic.
    def update_scan(self, scan_id: int, request):
        """Delegate the request to update scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.update_scan(scan_id, request)

    # Forward delete scan to the scan use case so this controller contains no business or SQL logic.
    def delete_scan(self, scan_id: int):
        """Delegate the request to delete scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.scan_usecase.delete_scan(scan_id)
