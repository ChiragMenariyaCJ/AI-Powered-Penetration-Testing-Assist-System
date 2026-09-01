
# This file handles scan execution routes.
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.scan_execution_controller import ScanExecutionController
from Backend.database import get_db

router = APIRouter(route_class=LoggedRoute)


# Run scan.
@router.post("/execute/{scan_id}")
def execute_scan(
    scan_id: int,
    project_id: int = Query(gt=0),
    db: Session = Depends(get_db),
):
    controller = ScanExecutionController(db)
    return controller.execute_scan(scan_id, project_id)


# Get scan results.
@router.get("/results/{scan_id}")
def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
):
    controller = ScanExecutionController(db)
    return controller.get_scan_results(scan_id)


# Check nmap availability.
@router.get("/status/nmap-availability")
def check_nmap_availability(db: Session = Depends(get_db)):
    controller = ScanExecutionController(db)
    return controller.validate_nmap_availability()
