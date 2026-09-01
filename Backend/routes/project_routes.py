
# This file handles project routes.
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

router = APIRouter(route_class=LoggedRoute)


# Create project.
@router.post(
    "/",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_project(
    request: ProjectCreateRequest,
    db: Session = Depends(get_db),
):
    controller = ProjectController(db)
    return controller.create_project(request)


# Get all projects.
@router.get("/")
def get_all_projects(
    user_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    controller = ProjectController(db)
    return controller.get_all_projects(user_id)


# Get project by ID.
@router.get("/{project_id}", response_model=ProjectResponse)
def get_project_by_id(
    project_id: int,
    db: Session = Depends(get_db),
):
    controller = ProjectController(db)
    return controller.get_project_by_id(project_id)


# Update project.
@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    request: ProjectUpdateRequest,
    db: Session = Depends(get_db),
):
    controller = ProjectController(db)
    return controller.update_project(project_id, request)


# Delete project.
@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
):
    controller = ProjectController(db)
    return controller.delete_project(project_id)
