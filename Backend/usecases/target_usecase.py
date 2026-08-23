"""Business rules for creating and managing assessment targets."""

from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.target_repository import TargetRepository


@trace_usecase
class TargetUseCase:

    """Apply target business rules between controllers and persistence.

    The use case validates related state and coordinates repositories or services.
    """
    def __init__(
        self,
        target_repository: TargetRepository,
        project_repository: ProjectRepository,
    ):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.target_repository = target_repository
        self.project_repository = project_repository

    def create_target(self, request):
        """Apply business validation and orchestration needed to create target.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        project = self.project_repository.get_project_by_id(request.project_id)

        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found",
            )

        return self.target_repository.create_target(
            project_id=request.project_id,
            target_name=request.target_name,
            target_type=request.target_type,
            target_value=request.target_value,
            scope=request.scope,
            status=request.status,
        )

    def get_all_targets(self, project_id: int | None = None):
        """Apply business validation and orchestration needed to get all targets.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        if project_id is not None:
            project = self.project_repository.get_project_by_id(project_id)

            if not project:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Project not found",
                )

            targets = self.target_repository.get_targets_by_project_id(
                project_id
            )
        else:
            targets = self.target_repository.get_all_targets()

        return {
            "count": len(targets),
            "targets": targets,
        }

    def get_target_by_id(self, target_id: int):
        """Apply business validation and orchestration needed to get target by id.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        target = self.target_repository.get_target_by_id(target_id)

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        return target

    def update_target(self, target_id: int, request):
        """Apply business validation and orchestration needed to update target.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        target = self.target_repository.get_target_by_id(target_id)

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        update_data = request.model_dump(exclude_unset=True)

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update",
            )

        return self.target_repository.update_target(
            target,
            update_data,
        )

    def delete_target(self, target_id: int):
        """Apply business validation and orchestration needed to delete target.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        target = self.target_repository.get_target_by_id(target_id)

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        deleted_target = {
            "id": target.id,
            "project_id": target.project_id,
            "target_name": target.target_name,
        }

        self.target_repository.delete_target(target)

        return {
            "message": "Target deleted successfully",
            "target": deleted_target,
        }
