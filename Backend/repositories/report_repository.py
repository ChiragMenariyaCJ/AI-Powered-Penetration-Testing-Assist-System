from sqlalchemy.orm import Session

from Backend.models.report_model import Report


class ReportRepository:
    @staticmethod
    def create_report(db: Session, report_data: dict) -> Report:
        """Create a new report"""
        report = Report(**report_data)
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    @staticmethod
    def get_report_by_id(db: Session, report_id: int) -> Report | None:
        """Get report by ID"""
        return db.query(Report).filter(Report.id == report_id).first()

    @staticmethod
    def get_reports_by_scan_id(db: Session, scan_id: int) -> list[Report]:
        """Get all reports for a specific scan"""
        return db.query(Report).filter(Report.scan_id == scan_id).all()

    @staticmethod
    def get_all_reports(db: Session, skip: int = 0, limit: int = 10) -> list[Report]:
        """Get all reports with pagination"""
        return db.query(Report).offset(skip).limit(limit).all()

    @staticmethod
    def get_reports_by_status(db: Session, status: str) -> list[Report]:
        """Get reports filtered by status"""
        return db.query(Report).filter(Report.status == status).all()

    @staticmethod
    def update_report(db: Session, report_id: int, report_data: dict) -> Report | None:
        """Update report"""
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
        """Delete report"""
        report = ReportRepository.get_report_by_id(db, report_id)
        if report:
            db.delete(report)
            db.commit()
            return True
        return False

    @staticmethod
    def count_reports(db: Session) -> int:
        """Get total report count"""
        return db.query(Report).count()

    @staticmethod
    def get_latest_report_for_scan(db: Session, scan_id: int) -> Report | None:
        """Get the most recent report for a scan"""
        return (
            db.query(Report)
            .filter(Report.scan_id == scan_id)
            .order_by(Report.created_at.desc())
            .first()
        )
