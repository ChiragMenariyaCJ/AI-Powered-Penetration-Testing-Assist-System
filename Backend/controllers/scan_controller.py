
# This file handles scan controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.usecases.scan_usecase import ScanUseCase


# Handle the scan controller.
@trace_controller
class ScanController:

    # Set up this object.
    def __init__(self, db: Session):
        scan_repository = ScanRepository(db)
        target_repository = TargetRepository(db)

        self.scan_usecase = ScanUseCase(
            scan_repository,
            target_repository,
        )

    # Create scan.
    def create_scan(self, request):
        return self.scan_usecase.create_scan(request)

    # Get all scans.
    def get_all_scans(self, target_id: int | None = None):
        return self.scan_usecase.get_all_scans(target_id)

    # Get scan by ID.
    def get_scan_by_id(self, scan_id: int):
        return self.scan_usecase.get_scan_by_id(scan_id)

    # Update scan.
    def update_scan(self, scan_id: int, request):
        return self.scan_usecase.update_scan(scan_id, request)

    # Delete scan.
    def delete_scan(self, scan_id: int):
        return self.scan_usecase.delete_scan(scan_id)
