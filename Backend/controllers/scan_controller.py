from sqlalchemy.orm import Session

from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.usecases.scan_usecase import ScanUseCase


class ScanController:

    def __init__(self, db: Session):
        scan_repository = ScanRepository(db)
        target_repository = TargetRepository(db)

        self.scan_usecase = ScanUseCase(
            scan_repository,
            target_repository,
        )

    def create_scan(self, request):
        return self.scan_usecase.create_scan(request)

    def get_all_scans(self, target_id: int | None = None):
        return self.scan_usecase.get_all_scans(target_id)

    def get_scan_by_id(self, scan_id: int):
        return self.scan_usecase.get_scan_by_id(scan_id)

    def update_scan(self, scan_id: int, request):
        return self.scan_usecase.update_scan(scan_id, request)

    def delete_scan(self, scan_id: int):
        return self.scan_usecase.delete_scan(scan_id)
