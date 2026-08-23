"""Translate project route requests into project use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.project_usecase import ProjectUseCase


@trace_controller
class ProjectController:
    """Connect project HTTP handlers to project business rules."""

    def __init__(self, db: Session):
        project_repository = ProjectRepository(db)
        user_repository = UserRepository(db)

        self.project_usecase = ProjectUseCase(
            project_repository,
            user_repository,
        )

    def create_project(self, request):
        return self.project_usecase.create_project(request)

    def get_all_projects(self, user_id: int | None = None):
        return self.project_usecase.get_all_projects(user_id)

    def get_project_by_id(self, project_id: int):
        return self.project_usecase.get_project_by_id(project_id)

    def update_project(self, project_id: int, request):
        return self.project_usecase.update_project(
            project_id,
            request,
        )

    def delete_project(self, project_id: int):
        return self.project_usecase.delete_project(project_id)
