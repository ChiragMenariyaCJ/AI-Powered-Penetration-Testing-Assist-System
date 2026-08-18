from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.controllers.scope_validation_controller import (
    ScopeValidationController,
)
from Backend.database import get_db
from Backend.schemas.scope_validation_schema import (
    ScopeValidationCreateRequest,
    ScopeValidationListResponse,
    ScopeValidationResponse,
    ScopeValidationUpdateRequest,
    ScopeCheckRequest,
    ScopeCheckResponse,
)

router = APIRouter()


@router.post(
    "/",
    response_model=ScopeValidationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scope_validation(
    request: ScopeValidationCreateRequest,
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.create_scope_validation(request)


@router.get("/", response_model=ScopeValidationListResponse)
def get_all_scope_validations(
    project_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.get_all_scope_validations(project_id)


@router.get("/{scope_validation_id}", response_model=ScopeValidationResponse)
def get_scope_validation_by_id(
    scope_validation_id: int,
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.get_scope_validation_by_id(scope_validation_id)


@router.put("/{scope_validation_id}", response_model=ScopeValidationResponse)
def update_scope_validation(
    scope_validation_id: int,
    request: ScopeValidationUpdateRequest,
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.update_scope_validation(scope_validation_id, request)


@router.delete("/{scope_validation_id}")
def delete_scope_validation(
    scope_validation_id: int,
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.delete_scope_validation(scope_validation_id)


@router.post("/check-target-scope", response_model=ScopeCheckResponse)
def check_target_scope(
    request: ScopeCheckRequest,
    db: Session = Depends(get_db),
):
    controller = ScopeValidationController(db)
    return controller.check_target_in_scope(request.project_id, request.target_value)
