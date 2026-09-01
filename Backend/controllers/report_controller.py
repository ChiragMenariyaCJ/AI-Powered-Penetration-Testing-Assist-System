
# This file handles report controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.usecases.report_usecase import ReportUseCase


# Handle the report controller.
@trace_controller
class ReportController:
    # Generate report.
    @staticmethod
    def generate_report(
        db: Session, scan_id: int, title: str, description: str = None, generated_by: str = None
    ):
        return ReportUseCase.generate_report(db, scan_id, title, description, generated_by)

    # Get report.
    @staticmethod
    def get_report(db: Session, report_id: int):
        return ReportUseCase.get_report(db, report_id)

    # Get reports by scan.
    @staticmethod
    def get_reports_by_scan(db: Session, scan_id: int):
        return ReportUseCase.get_reports_by_scan(db, scan_id)

    # Export report.
    @staticmethod
    def export_report(db: Session, report_id: int, format_type: str, exported_by: str = None):
        return ReportUseCase.export_report(db, report_id, format_type, exported_by)

    # List all reports.
    @staticmethod
    def list_all_reports(db: Session, skip: int = 0, limit: int = 10):
        return ReportUseCase.list_all_reports(db, skip, limit)
