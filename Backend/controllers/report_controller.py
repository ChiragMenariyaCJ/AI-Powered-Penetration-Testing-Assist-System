from sqlalchemy.orm import Session

from Backend.usecases.report_usecase import ReportUseCase


class ReportController:
    @staticmethod
    def generate_report(
        db: Session, scan_id: int, title: str, description: str = None, generated_by: str = None
    ):
        """Controller to generate report"""
        return ReportUseCase.generate_report(db, scan_id, title, description, generated_by)

    @staticmethod
    def get_report(db: Session, report_id: int):
        """Controller to get report"""
        return ReportUseCase.get_report(db, report_id)

    @staticmethod
    def get_reports_by_scan(db: Session, scan_id: int):
        """Controller to get reports for a scan"""
        return ReportUseCase.get_reports_by_scan(db, scan_id)

    @staticmethod
    def export_report(db: Session, report_id: int, format_type: str, exported_by: str = None):
        """Controller to export report"""
        return ReportUseCase.export_report(db, report_id, format_type, exported_by)

    @staticmethod
    def list_all_reports(db: Session, skip: int = 0, limit: int = 10):
        """Controller to list all reports"""
        return ReportUseCase.list_all_reports(db, skip, limit)
