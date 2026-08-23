"""Database operations for scan records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.scan_model import Scan


@trace_repository
class ScanRepository:

    def __init__(self, db: Session):
        self.db = db

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

    def get_all_scans(self) -> list[Scan]:
        return self.db.query(Scan).order_by(Scan.id.desc()).all()

    def get_scans_by_target_id(self, target_id: int) -> list[Scan]:
        return (
            self.db.query(Scan)
            .filter(Scan.target_id == target_id)
            .order_by(Scan.id.desc())
            .all()
        )

    def get_scan_by_id(self, scan_id: int) -> Scan | None:
        return (
            self.db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

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

    def delete_scan(self, scan: Scan) -> None:
        self.db.delete(scan)
        self.db.commit()
