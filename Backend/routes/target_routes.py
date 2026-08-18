from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.controllers.target_controller import TargetController
from Backend.database import get_db
from Backend.schemas.target_schema import (
    TargetCreateRequest,
    TargetListResponse,
    TargetResponse,
    TargetUpdateRequest,
)

router = APIRouter()


@router.post(
    "/",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_target(
    request: TargetCreateRequest,
    db: Session = Depends(get_db),
):
    controller = TargetController(db)
    return controller.create_target(request)


@router.get("/", response_model=TargetListResponse)
def get_all_targets(
    project_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    controller = TargetController(db)
    return controller.get_all_targets(project_id)


@router.get("/{target_id}", response_model=TargetResponse)
def get_target_by_id(
    target_id: int,
    db: Session = Depends(get_db),
):
    controller = TargetController(db)
    return controller.get_target_by_id(target_id)


@router.put("/{target_id}", response_model=TargetResponse)
def update_target(
    target_id: int,
    request: TargetUpdateRequest,
    db: Session = Depends(get_db),
):
    controller = TargetController(db)
    return controller.update_target(target_id, request)


@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
):
    controller = TargetController(db)
    return controller.delete_target(target_id)
