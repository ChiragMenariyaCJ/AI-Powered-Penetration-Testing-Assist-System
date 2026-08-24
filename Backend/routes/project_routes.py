"""Project creation, lookup, update, and deletion endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.project_controller import ProjectController
from Backend.database import get_db
from Backend.schemas.project_schema import (
    ProjectCreateRequest,
    ProjectResponse,
    ProjectUpdateRequest,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


# Validate HTTP inputs and delegate the create project request to the project controller.
@router.post(
    "/",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    request: ProjectCreateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to create project.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ProjectController(db)
    return controller.create_project(request)


# Validate HTTP inputs and delegate the get all projects request to the project controller.
@router.get("/")
def get_all_projects(
    user_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get all projects.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ProjectController(db)
    return controller.get_all_projects(user_id)


# Validate HTTP inputs and delegate the get project by id request to the project controller.
@router.get("/{project_id}", response_model=ProjectResponse)
def get_project_by_id(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get project by id.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ProjectController(db)
    return controller.get_project_by_id(project_id)


# Validate HTTP inputs and delegate the update project request to the project controller.
@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    request: ProjectUpdateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to update project.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ProjectController(db)
    return controller.update_project(project_id, request)


# Validate HTTP inputs and delegate the delete project request to the project controller.
@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to delete project.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = ProjectController(db)
    return controller.delete_project(project_id)
