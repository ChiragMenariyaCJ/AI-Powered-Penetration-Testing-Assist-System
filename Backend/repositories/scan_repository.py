"""Database operations for scan records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.scan_model import Scan


@trace_repository
class ScanRepository:

    """Provide database operations for scan records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    # Store the request-scoped SQLAlchemy session used by this repository’s queries.
    def __init__(self, db: Session):
        self.db = db

    # Create and commit the requested scan record.
    def create_scan(
        self,
        target_id: int,
        scan_name: str,
        scan_type: str,
        status: str,
    ) -> Scan:
        """Create and commit the requested scan record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
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

    # Query all scans with SQLAlchemy without changing stored database state.
    def get_all_scans(self) -> list[Scan]:
        """Query scan data for get all scans.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(Scan).order_by(Scan.id.desc()).all()

    # Query scans by target id with SQLAlchemy without changing stored database state.
    def get_scans_by_target_id(self, target_id: int) -> list[Scan]:
        """Query scan data for get scans by target id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Scan)
            .filter(Scan.target_id == target_id)
            .order_by(Scan.id.desc())
            .all()
        )

    # Query scan by id with SQLAlchemy without changing stored database state.
    def get_scan_by_id(self, scan_id: int) -> Scan | None:
        """Query scan data for get scan by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

    # Persist the state change required to update scan.
    def update_scan(
        self,
        scan: Scan,
        update_data: dict,
    ) -> Scan:
        """Persist the state change required to update scan.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        for field, value in update_data.items():
            setattr(scan, field, value)

        self.db.commit()
        self.db.refresh(scan)

        return scan

    # Delete the supplied scan record and commit the transaction.
    def delete_scan(self, scan: Scan) -> None:
        """Delete the supplied scan record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(scan)
        self.db.commit()
