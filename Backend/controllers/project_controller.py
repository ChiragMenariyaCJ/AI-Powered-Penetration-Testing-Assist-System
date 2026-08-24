"""Translate project route requests into project use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.project_usecase import ProjectUseCase


@trace_controller
class ProjectController:
    """Connect project HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        project_repository = ProjectRepository(db)
        user_repository = UserRepository(db)

        self.project_usecase = ProjectUseCase(
            project_repository,
            user_repository,
        )

    # Forward create project to the project use case so this controller contains no business or SQL logic.
    def create_project(self, request):
        """Delegate the request to create project through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.project_usecase.create_project(request)

    # Forward get all projects to the project use case so this controller contains no business or SQL logic.
    def get_all_projects(self, user_id: int | None = None):
        """Delegate the request to get all projects through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.project_usecase.get_all_projects(user_id)

    # Forward get project by id to the project use case so this controller contains no business or SQL logic.
    def get_project_by_id(self, project_id: int):
        """Delegate the request to get project by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.project_usecase.get_project_by_id(project_id)

    # Forward update project to the project use case so this controller contains no business or SQL logic.
    def update_project(self, project_id: int, request):
        """Delegate the request to update project through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.project_usecase.update_project(
            project_id,
            request,
        )

    # Forward delete project to the project use case so this controller contains no business or SQL logic.
    def delete_project(self, project_id: int):
        """Delegate the request to delete project through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.project_usecase.delete_project(project_id)
