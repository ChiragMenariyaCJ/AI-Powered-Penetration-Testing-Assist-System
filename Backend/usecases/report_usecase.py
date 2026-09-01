
# This file handles report usecase.
import json
from datetime import UTC, datetime
from sqlalchemy.orm import Session

from Backend.api_logging import trace_usecase
from Backend.models.scan_model import Scan
from Backend.models.vulnerability_model import Vulnerability
from Backend.models.recommendation_model import Recommendation
from Backend.models.report_model import Report
from Backend.repositories.report_repository import ReportRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository


# Handle the report use case.
@trace_usecase
class ReportUseCase:
    # Generate report.
    @staticmethod
    def generate_report(
        db: Session, scan_id: int, title: str, description: str = None, generated_by: str = None
    ) -> dict:
        # Validate scan exists.
        scan = ScanRepository(db).get_scan_by_id(scan_id)
        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        # Get all vulnerabilities for this scan.
        vulnerabilities = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id
        ).all()

        # Calculate vulnerability summary.
        vuln_summary = ReportUseCase._calculate_vulnerability_summary(vulnerabilities)

        report_recommendations = ReportUseCase._recommendations_for_report(
            db, vulnerabilities
        )
        recommendation_summary = ReportUseCase._calculate_recommendation_summary(
            report_recommendations
        )

        # Gather scan metadata.
        scan_metadata = ReportUseCase._gather_scan_metadata(db, scan)

        # Generate report content.
        report_content = ReportUseCase._generate_report_content(
            scan,
            vulnerabilities,
            report_recommendations,
            title,
            description,
        )

        # Create report in database.
        report_data = {
            "scan_id": scan_id,
            "title": title,
            "description": description,
            "total_vulnerabilities": vuln_summary["total"],
            "critical_count": vuln_summary["critical"],
            "high_count": vuln_summary["high"],
            "medium_count": vuln_summary["medium"],
            "low_count": vuln_summary["low"],
            "info_count": vuln_summary["info"],
            "total_recommendations": recommendation_summary["total"],
            "approved_recommendations": recommendation_summary["approved"],
            "pending_recommendations": recommendation_summary["pending"],
            "rejected_recommendations": recommendation_summary["rejected"],
            "target_count": scan_metadata.get("target_count"),
            "scan_duration_seconds": scan_metadata.get("duration_seconds"),
            "scan_start_time": scan_metadata.get("start_time"),
            "scan_end_time": scan_metadata.get("end_time"),
            "status": "COMPLETED",
            "format_type": "JSON",
            "generated_by": generated_by,
            "report_content": report_content,
        }

        report = ReportRepository.create_report(db, report_data)

        return {
            "id": report.id,
            "status": "success",
            "message": f"Report generated successfully with {len(vulnerabilities)} vulnerabilities",
            "report": {
                "id": report.id,
                "scan_id": report.scan_id,
                "title": report.title,
                "vulnerability_summary": vuln_summary,
                "recommendation_summary": recommendation_summary,
            },
        }

    # Calculate vulnerability summary.
    @staticmethod
    def _calculate_vulnerability_summary(vulnerabilities: list[Vulnerability]) -> dict:
        severity_map = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for vuln in vulnerabilities:
            severity = vuln.severity.upper()
            if severity in severity_map:
                severity_map[severity] += 1

        return {
            "total": len(vulnerabilities),
            "critical": severity_map["CRITICAL"],
            "high": severity_map["HIGH"],
            "medium": severity_map["MEDIUM"],
            "low": severity_map["LOW"],
            "info": severity_map["INFO"],
        }

    # Calculate recommendation summary.
    @staticmethod
    def _calculate_recommendation_summary(
        recommendations: list[Recommendation],
    ) -> dict:
        if not recommendations:
            return {
                "total": 0,
                "approved": 0,
                "pending": 0,
                "rejected": 0,
            }

        status_count = {
            "total": len(recommendations),
            "approved": 0,
            "pending": 0,
            "rejected": 0,
        }

        for rec in recommendations:
            if rec.status == "APPROVED":
                status_count["approved"] += 1
            elif rec.status == "PENDING_APPROVAL":
                status_count["pending"] += 1
            elif rec.status == "REJECTED":
                status_count["rejected"] += 1

        return status_count

    # Work with recommendation provider.
    @staticmethod
    def _recommendation_provider(recommendation: Recommendation) -> str:
        source = str(recommendation.tools_required or "").lower()
        if source == "realtime-ollama":
            return "OLLAMA"
        return "UNSPECIFIED"

    # Work with recommendations for report.
    @staticmethod
    def _recommendations_for_report(
        db: Session,
        vulnerabilities: list[Vulnerability],
    ) -> list[Recommendation]:
        vulnerability_ids = [vulnerability.id for vulnerability in vulnerabilities]
        if not vulnerability_ids:
            return []
        recommendations = (
            db.query(Recommendation)
            .filter(Recommendation.vulnerability_id.in_(vulnerability_ids))
            .order_by(Recommendation.priority.desc(), Recommendation.id.asc())
            .all()
        )
        return [
            recommendation
            for recommendation in recommendations
            if ReportUseCase._recommendation_provider(recommendation) == "OLLAMA"
            and recommendation.status != "REJECTED"
        ]

    # Work with gather scan metadata.
    @staticmethod
    def _gather_scan_metadata(db: Session, scan: Scan) -> dict:
        # Count unique targets in scan.
        targets = db.query(Vulnerability.host).filter(
            Vulnerability.scan_id == scan.id
        ).distinct().count()

        duration = None
        if scan.started_at and scan.completed_at:
            duration = int((scan.completed_at - scan.started_at).total_seconds())

        return {
            "scan_id": scan.id,
            "target_count": targets if targets > 0 else None,
            "duration_seconds": duration,
            "start_time": scan.started_at,
            "end_time": scan.completed_at,
        }

    # Generate report content.
    @staticmethod
    def _generate_report_content(
        scan: Scan,
        vulnerabilities: list[Vulnerability],
        recommendations: list[Recommendation],
        title: str,
        description: str = None,
    ) -> str:
        vuln_list = []
        recommendations_by_vulnerability: dict[int, list[Recommendation]] = {}
        for recommendation in recommendations:
            recommendations_by_vulnerability.setdefault(
                recommendation.vulnerability_id, []
            ).append(recommendation)

        for vuln in vulnerabilities:
            rec_list = []
            for rec in recommendations_by_vulnerability.get(vuln.id, []):
                rec_list.append(
                    {
                        "id": rec.id,
                        "attack_technique": rec.attack_technique,
                        "mitre_technique_id": rec.mitre_technique_id,
                        "exploitation_method": rec.exploitation_method,
                        "risk_level": rec.risk_level,
                        "priority": rec.priority,
                        "status": rec.status,
                        "provider": ReportUseCase._recommendation_provider(rec),
                        "tools_required": rec.tools_required,
                        "execution_steps": rec.execution_steps,
                    }
                )

            vuln_list.append(
                {
                    "id": vuln.id,
                    "host": vuln.host,
                    "port": vuln.port,
                    "service": vuln.service,
                    "type": vuln.vulnerability_type,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "version": vuln.version,
                    "cves": vuln.cves,
                    "remediation": vuln.remediation,
                    "status": vuln.status,
                    "recommendations": rec_list,
                }
            )

        report_data = {
            "report_metadata": {
                "title": title,
                "description": description,
                "generated_at": datetime.now(UTC).isoformat(),
                "scan_id": scan.id,
                "scan_type": scan.scan_type,
                "scan_status": scan.status,
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "total_recommendations": sum(len(v["recommendations"]) for v in vuln_list),
                "recommendation_provider": (
                    "OLLAMA"
                    if recommendations
                    else "NONE"
                ),
            },
            "vulnerabilities": vuln_list,
        }

        return json.dumps(report_data, indent=2)

    # Get report.
    @staticmethod
    def get_report(db: Session, report_id: int) -> dict:
        report = ReportRepository.get_report_by_id(db, report_id)
        if not report:
            return {"error": f"Report {report_id} not found"}

        return {
            "id": report.id,
            "scan_id": report.scan_id,
            "title": report.title,
            "description": report.description,
            "vulnerability_summary": {
                "total": report.total_vulnerabilities,
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count,
                "info": report.info_count,
            },
            "recommendation_summary": {
                "total": report.total_recommendations,
                "approved": report.approved_recommendations,
                "pending": report.pending_recommendations,
                "rejected": report.rejected_recommendations,
            },
            "status": report.status,
            "format_type": report.format_type,
            "generated_by": report.generated_by,
            "created_at": report.created_at,
            "updated_at": report.updated_at,
            "exported_at": report.exported_at,
            "scan_metadata": {
                "scan_id": report.scan_id,
                "target_count": report.target_count,
                "duration_seconds": report.scan_duration_seconds,
                "start_time": report.scan_start_time,
                "end_time": report.scan_end_time,
            },
        }

    # Get reports by scan.
    @staticmethod
    def get_reports_by_scan(db: Session, scan_id: int) -> dict:
        reports = ReportRepository.get_reports_by_scan_id(db, scan_id)
        return {
            "scan_id": scan_id,
            "reports": [
                {
                    "id": r.id,
                    "title": r.title,
                    "status": r.status,
                    "created_at": r.created_at,
                }
                for r in reports
            ],
            "total": len(reports),
        }

    # Export report.
    @staticmethod
    def export_report(db: Session, report_id: int, format_type: str, exported_by: str = None) -> dict:
        report = ReportRepository.get_report_by_id(db, report_id)
        if not report:
            return {"error": f"Report {report_id} not found"}

        if format_type not in ["JSON", "PDF", "HTML"]:
            return {"error": f"Invalid format type: {format_type}. Supported: JSON, PDF, HTML"}

        # Update report with export info.
        update_data = {
            "format_type": format_type,
            "exported_at": datetime.now(UTC),
        }
        ReportRepository.update_report(db, report_id, update_data)

        return {
            "id": report.id,
            "status": "exported",
            "format_type": format_type,
            "message": f"Report {report_id} exported as {format_type}",
            "exported_at": datetime.now(UTC),
        }

    # List all reports.
    @staticmethod
    def list_all_reports(db: Session, skip: int = 0, limit: int = 10) -> dict:
        reports = ReportRepository.get_all_reports(db, skip, limit)
        total = ReportRepository.count_reports(db)

        return {
            "reports": [
                {
                    "id": r.id,
                    "scan_id": r.scan_id,
                    "title": r.title,
                    "status": r.status,
                    "created_at": r.created_at,
                }
                for r in reports
            ],
            "total": total,
            "skip": skip,
            "limit": limit,
        }
