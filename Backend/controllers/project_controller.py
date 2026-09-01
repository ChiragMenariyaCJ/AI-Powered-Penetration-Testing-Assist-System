
# This file handles project controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.project_usecase import ProjectUseCase


# Handle the project controller.
@trace_controller
class ProjectController:

    # Set up this object.
    def __init__(self, db: Session):
        project_repository = ProjectRepository(db)
        user_repository = UserRepository(db)

        self.project_usecase = ProjectUseCase(
            project_repository,
            user_repository,
        )

    # Create project.
    def create_project(self, request):
        return self.project_usecase.create_project(request)

    # Get all projects.
    def get_all_projects(self, user_id: int | None = None):
        return self.project_usecase.get_all_projects(user_id)

    # Get project by ID.
    def get_project_by_id(self, project_id: int):
        return self.project_usecase.get_project_by_id(project_id)

    # Update project.
    def update_project(self, project_id: int, request):
        return self.project_usecase.update_project(
            project_id,
            request,
        )

    # Delete project.
    def delete_project(self, project_id: int):
        return self.project_usecase.delete_project(project_id)
