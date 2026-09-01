
# This file handles report routes.
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

router = APIRouter(route_class=LoggedRoute)


# Generate report.
@router.post("/generate/{scan_id}")
def generate_report(
    scan_id: int,
    request: ReportCreateRequest,
    db: Session = Depends(get_db),
):
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


# Get report.
@router.get("/{report_id}", response_model=ReportResponse)
def get_report(report_id: int, db: Session = Depends(get_db)):
    result = ReportController.get_report(db, report_id)

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


# Get reports by scan.
@router.get("/scan/{scan_id}")
def get_reports_by_scan(scan_id: int, db: Session = Depends(get_db)):
    return ReportController.get_reports_by_scan(db, scan_id)


# List reports.
@router.get("/")
def list_reports(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    return ReportController.list_all_reports(db, skip, limit)


# Export report.
@router.post("/{report_id}/export", response_model=ReportExportResponse)
def export_report(
    report_id: int,
    request: ReportExportRequest,
    db: Session = Depends(get_db),
):
    result = ReportController.export_report(
        db,
        report_id,
        request.format_type,
        request.exported_by,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


# Work with regenerate report.
@router.post("/{report_id}/regenerate")
def regenerate_report(report_id: int, db: Session = Depends(get_db)):
    # Regenerate the report from its saved scan.
    return {"message": "Report regeneration not yet implemented"}


# Delete report.
@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    from Backend.repositories.report_repository import ReportRepository

    success = ReportRepository.delete_report(db, report_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    return {"message": f"Report {report_id} deleted successfully"}
