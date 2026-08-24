"""Assessment-target creation, lookup, update, and deletion endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.target_controller import TargetController
from Backend.database import get_db
from Backend.schemas.target_schema import (
    TargetCreateRequest,
    TargetListResponse,
    TargetResponse,
    TargetUpdateRequest,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


# Validate HTTP inputs and delegate the create target request to the target controller.
@router.post(
    "/",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    request: TargetCreateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to create target.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = TargetController(db)
    return controller.create_target(request)


# Validate HTTP inputs and delegate the get all targets request to the target controller.
@router.get("/", response_model=TargetListResponse)
def get_all_targets(
    project_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get all targets.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = TargetController(db)
    return controller.get_all_targets(project_id)


# Validate HTTP inputs and delegate the get target by id request to the target controller.
@router.get("/{target_id}", response_model=TargetResponse)
def get_target_by_id(
    target_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get target by id.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = TargetController(db)
    return controller.get_target_by_id(target_id)


# Validate HTTP inputs and delegate the update target request to the target controller.
@router.put("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: int,
    request: TargetUpdateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to update target.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = TargetController(db)
    return controller.update_target(target_id, request)


# Validate HTTP inputs and delegate the delete target request to the target controller.
@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to delete target.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = TargetController(db)
    return controller.delete_target(target_id)
