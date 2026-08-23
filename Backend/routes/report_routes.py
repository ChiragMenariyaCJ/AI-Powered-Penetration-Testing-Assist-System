"""Report generation, retrieval, export, and deletion endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.database import get_db
from Backend.controllers.report_controller import ReportController
from Backend.schemas.report_schema import (
    ReportCreateRequest,
    ReportUpdateRequest,
    ReportResponse,
    ReportListResponse,
    ReportExportRequest,
    ReportExportResponse,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


@router.post("/generate/{scan_id}")
def generate_report(
    scan_id: int,
    request: ReportCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Generate a comprehensive penetration test report for a scan
    
    - **scan_id**: ID of the scan to generate report for
    - **title**: Report title
    - **description**: Optional report description
    - **generated_by**: User who generated the report
    """
    result = ReportController.generate_report(
        db,
        scan_id,
        request.title,
        request.description,
        request.generated_by,
    )

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


@router.get("/{report_id}", response_model=ReportResponse)
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific report by ID"""
    result = ReportController.get_report(db, report_id)

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


@router.get("/scan/{scan_id}")
def get_reports_by_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get all reports generated for a specific scan"""
    return ReportController.get_reports_by_scan(db, scan_id)


@router.get("/")
def list_reports(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """List all reports with pagination"""
    return ReportController.list_all_reports(db, skip, limit)


@router.post("/{report_id}/export", response_model=ReportExportResponse)
def export_report(
    report_id: int,
    request: ReportExportRequest,
    db: Session = Depends(get_db),
):
    """
    Export report in specified format (JSON, PDF, HTML)
    
    - **report_id**: ID of the report to export
    - **format_type**: Export format (JSON, PDF, HTML)
    - **exported_by**: User who exported the report
    """
    result = ReportController.export_report(
        db,
        report_id,
        request.format_type,
        request.exported_by,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.post("/{report_id}/regenerate")
def regenerate_report(report_id: int, db: Session = Depends(get_db)):
    """Regenerate a report"""
    # This would fetch the original report, get the scan, and regenerate
    # Implementation depends on your specific requirements
    return {"message": "Report regeneration not yet implemented"}


@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    """Delete a report"""
    from Backend.repositories.report_repository import ReportRepository

    success = ReportRepository.delete_report(db, report_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    return {"message": f"Report {report_id} deleted successfully"}
