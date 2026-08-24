"""Business rules for creating and managing student projects."""

from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.user_repository import UserRepository


@trace_usecase
class ProjectUseCase:

    """Apply project business rules between controllers and persistence.

    The use case validates related state and coordinates repositories or services.
    """
    # Store the repositories and services used to enforce this feature’s business rules.
    def __init__(
        self,
        project_repository: ProjectRepository,
        user_repository: UserRepository,
    ):
        self.project_repository = project_repository
        self.user_repository = user_repository

    # Validate related records and coordinate repositories to create project.
    def create_project(self, request):
        """Apply business validation and orchestration needed to create project.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        user = self.user_repository.get_user_by_id(request.user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return self.project_repository.create_project(
            user_id=request.user_id,
            project_name=request.project_name,
            description=request.description,
            status=request.status,
        )

    # Validate related records and coordinate repositories to get all projects.
    def get_all_projects(self, user_id: int | None = None):
        """Apply business validation and orchestration needed to get all projects.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        if user_id is not None:
            user = self.user_repository.get_user_by_id(user_id)

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found",
                )

            projects = self.project_repository.get_projects_by_user_id(
                user_id
            )
        else:
            projects = self.project_repository.get_all_projects()

        return {
            "count": len(projects),
            "projects": projects,
        }

    # Validate related records and coordinate repositories to get project by id.
    def get_project_by_id(self, project_id: int):
        """Apply business validation and orchestration needed to get project by id.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        project = self.project_repository.get_project_by_id(project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        return project

    # Validate related records and coordinate repositories to update project.
    def update_project(self, project_id: int, request):
        """Apply business validation and orchestration needed to update project.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        project = self.project_repository.get_project_by_id(project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        update_data = request.model_dump(exclude_unset=True)

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update",
            )

        return self.project_repository.update_project(
            project,
            update_data,
        )

    # Validate related records and coordinate repositories to delete project.
    def delete_project(self, project_id: int):
        """Apply business validation and orchestration needed to delete project.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        project = self.project_repository.get_project_by_id(project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        deleted_project = {
            "id": project.id,
            "user_id": project.user_id,
            "project_name": project.project_name,
        }

        self.project_repository.delete_project(project)

        return {
            "message": "Project deleted successfully",
            "project": deleted_project,
        }
