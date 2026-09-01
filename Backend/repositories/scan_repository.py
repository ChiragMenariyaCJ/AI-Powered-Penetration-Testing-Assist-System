
# This file handles scan repository.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.scan_model import Scan


# Handle the scan repository.
@trace_repository
class ScanRepository:

    # Set up this object.
    def __init__(self, db: Session):
        self.db = db

    # Create scan.
    def create_scan(
        self,
        target_id: int,
        scan_name: str,
        scan_type: str,
        status: str,
    ) -> Scan:
        scan = Scan(
            target_id=target_id,
            scan_name=scan_name,
            scan_type=scan_type,
            status=status,
        )

        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        return scan

    # Get all scans.
    def get_all_scans(self) -> list[Scan]:
        return self.db.query(Scan).order_by(Scan.id.desc()).all()

    # Get scans by target ID.
    def get_scans_by_target_id(self, target_id: int) -> list[Scan]:
        return (
            self.db.query(Scan)
            .filter(Scan.target_id == target_id)
            .order_by(Scan.id.desc())
            .all()
        )

    # Get scan by ID.
    def get_scan_by_id(self, scan_id: int) -> Scan | None:
        return (
            self.db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

    # Update scan.
    def update_scan(
        self,
        scan: Scan,
        update_data: dict,
    ) -> Scan:
        for field, value in update_data.items():
            setattr(scan, field, value)

        self.db.commit()
        self.db.refresh(scan)

        return scan

    # Delete scan.
    def delete_scan(self, scan: Scan) -> None:
        self.db.delete(scan)
        self.db.commit()
