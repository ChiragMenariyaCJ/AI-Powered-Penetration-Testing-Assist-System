"""Scan record creation, lookup, update, and deletion endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.scan_controller import ScanController
from Backend.database import get_db
from Backend.schemas.scan_schema import (
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
    ScanUpdateRequest,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    request: ScanCreateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to create scan.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanController(db)
    return controller.create_scan(request)


@router.get("/", response_model=ScanListResponse)
def get_all_scans(
    target_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get all scans.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanController(db)
    return controller.get_all_scans(target_id)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get scan by id.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanController(db)
    return controller.get_scan_by_id(scan_id)


@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(
    scan_id: int,
    request: ScanUpdateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to update scan.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanController(db)
    return controller.update_scan(scan_id, request)


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to delete scan.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ScanController(db)
    return controller.delete_scan(scan_id)
