
# This file handles report repository.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.report_model import Report


# Handle the report repository.
@trace_repository
class ReportRepository:
    # Create report.
    @staticmethod
    def create_report(db: Session, report_data: dict) -> Report:
        report = Report(**report_data)
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    # Get report by ID.
    @staticmethod
    def get_report_by_id(db: Session, report_id: int) -> Report | None:
        return db.query(Report).filter(Report.id == report_id).first()

    # Get reports by scan ID.
    @staticmethod
    def get_reports_by_scan_id(db: Session, scan_id: int) -> list[Report]:
        return db.query(Report).filter(Report.scan_id == scan_id).all()

    # Get all reports.
    @staticmethod
    def get_all_reports(db: Session, skip: int = 0, limit: int = 10) -> list[Report]:
        return db.query(Report).offset(skip).limit(limit).all()

    # Get reports by status.
    @staticmethod
    def get_reports_by_status(db: Session, status: str) -> list[Report]:
        return db.query(Report).filter(Report.status == status).all()

    # Update report.
    @staticmethod
    def update_report(db: Session, report_id: int, report_data: dict) -> Report | None:
        report = ReportRepository.get_report_by_id(db, report_id)
        if report:
            for key, value in report_data.items():
                if value is not None:
                    setattr(report, key, value)
            db.commit()
            db.refresh(report)
        return report

    # Delete report.
    @staticmethod
    def delete_report(db: Session, report_id: int) -> bool:
        report = ReportRepository.get_report_by_id(db, report_id)
        if report:
            db.delete(report)
            db.commit()
            return True
        return False

    # Work with count reports.
    @staticmethod
    def count_reports(db: Session) -> int:
        return db.query(Report).count()

    # Get latest report for scan.
    @staticmethod
    def get_latest_report_for_scan(db: Session, scan_id: int) -> Report | None:
        return (
            db.query(Report)
            .filter(Report.scan_id == scan_id)
            .order_by(Report.created_at.desc())
            .first()
        )
