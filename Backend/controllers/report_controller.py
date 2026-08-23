"""Translate report routes into report-generation use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.usecases.report_usecase import ReportUseCase


@trace_controller
class ReportController:
    """Connect report HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """
    @staticmethod
    def generate_report(
        db: Session, scan_id: int, title: str, description: str = None, generated_by: str = None
    ):
        """Delegate the request to generate report through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return ReportUseCase.generate_report(db, scan_id, title, description, generated_by)

    @staticmethod
    def get_report(db: Session, report_id: int):
        """Delegate the request to get report through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return ReportUseCase.get_report(db, report_id)

    @staticmethod
    def get_reports_by_scan(db: Session, scan_id: int):
        """Delegate the request to get reports by scan through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return ReportUseCase.get_reports_by_scan(db, scan_id)

    @staticmethod
    def export_report(db: Session, report_id: int, format_type: str, exported_by: str = None):
        """Delegate the request to export report through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return ReportUseCase.export_report(db, report_id, format_type, exported_by)

    @staticmethod
    def list_all_reports(db: Session, skip: int = 0, limit: int = 10):
        """Delegate the request to list all reports through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return ReportUseCase.list_all_reports(db, skip, limit)
