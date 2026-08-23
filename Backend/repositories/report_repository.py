"""Database operations for generated report records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.report_model import Report


@trace_repository
class ReportRepository:
    """Provide database operations for report records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    @staticmethod
    def create_report(db: Session, report_data: dict) -> Report:
        """Create and commit the requested report record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
        report = Report(**report_data)
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    @staticmethod
    def get_report_by_id(db: Session, report_id: int) -> Report | None:
        """Query report data for get report by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return db.query(Report).filter(Report.id == report_id).first()

    @staticmethod
    def get_reports_by_scan_id(db: Session, scan_id: int) -> list[Report]:
        """Query report data for get reports by scan id.

        This read operation returns matching model instances without changing database
        state.
        """
        return db.query(Report).filter(Report.scan_id == scan_id).all()

    @staticmethod
    def get_all_reports(db: Session, skip: int = 0, limit: int = 10) -> list[Report]:
        """Query report data for get all reports.

        This read operation returns matching model instances without changing database
        state.
        """
        return db.query(Report).offset(skip).limit(limit).all()

    @staticmethod
    def get_reports_by_status(db: Session, status: str) -> list[Report]:
        """Query report data for get reports by status.

        This read operation returns matching model instances without changing database
        state.
        """
        return db.query(Report).filter(Report.status == status).all()

    @staticmethod
    def update_report(db: Session, report_id: int, report_data: dict) -> Report | None:
        """Persist the state change required to update report.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        report = ReportRepository.get_report_by_id(db, report_id)
        if report:
            for key, value in report_data.items():
                if value is not None:
                    setattr(report, key, value)
            db.commit()
            db.refresh(report)
        return report

    @staticmethod
    def delete_report(db: Session, report_id: int) -> bool:
        """Delete the supplied report record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        report = ReportRepository.get_report_by_id(db, report_id)
        if report:
            db.delete(report)
            db.commit()
            return True
        return False

    @staticmethod
    def count_reports(db: Session) -> int:
        """Query report data for count reports.

        This read operation returns matching model instances without changing database
        state.
        """
        return db.query(Report).count()

    @staticmethod
    def get_latest_report_for_scan(db: Session, scan_id: int) -> Report | None:
        """Query report data for get latest report for scan.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            db.query(Report)
            .filter(Report.scan_id == scan_id)
            .order_by(Report.created_at.desc())
            .first()
        )
