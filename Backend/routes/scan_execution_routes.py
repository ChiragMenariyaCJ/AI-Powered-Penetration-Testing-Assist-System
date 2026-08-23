"""Authorized Nmap execution and scan-result endpoints."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.scan_execution_controller import ScanExecutionController
from Backend.database import get_db

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


@router.post("/execute/{scan_id}")
def execute_scan(
    scan_id: int,
    project_id: int = Query(gt=0),
    db: Session = Depends(get_db),
):
    """
    Execute a pending scan using Nmap
    
    Args:
        scan_id: ID of the scan to execute
        project_id: ID of the project (for scope validation)
    """
    controller = ScanExecutionController(db)
    return controller.execute_scan(scan_id, project_id)


@router.get("/results/{scan_id}")
def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get scan results.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanExecutionController(db)
    return controller.get_scan_results(scan_id)


@router.get("/status/nmap-availability")
def check_nmap_availability(db: Session = Depends(get_db)):
    """Handle the HTTP request that asks PTAS to check nmap availability.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanExecutionController(db)
    return controller.validate_nmap_availability()
