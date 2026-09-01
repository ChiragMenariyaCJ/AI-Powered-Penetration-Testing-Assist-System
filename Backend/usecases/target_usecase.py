
# This file handles target usecase.
from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.target_repository import TargetRepository


# Handle the target use case.
@trace_usecase
class TargetUseCase:

    # Set up this object.
    def __init__(
        self,
        target_repository: TargetRepository,
        project_repository: ProjectRepository,
    ):
        self.target_repository = target_repository
        self.project_repository = project_repository

    # Create target.
    def create_target(self, request):
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

    # Get all targets.
    def get_all_targets(self, project_id: int | None = None):
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

    # Get target by ID.
    def get_target_by_id(self, target_id: int):
        target = self.target_repository.get_target_by_id(target_id)

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        return target

    # Update target.
    def update_target(self, target_id: int, request):
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

    # Delete target.
    def delete_target(self, target_id: int):
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
