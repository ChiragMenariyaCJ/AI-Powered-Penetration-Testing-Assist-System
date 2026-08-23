"""Translate target route requests into target use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.usecases.target_usecase import TargetUseCase


@trace_controller
class TargetController:
    """Connect target HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        target_repository = TargetRepository(db)
        project_repository = ProjectRepository(db)

        self.target_usecase = TargetUseCase(
            target_repository,
            project_repository,
        )

    def create_target(self, request):
        """Delegate the request to create target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.create_target(request)

    def get_all_targets(self, project_id: int | None = None):
        """Delegate the request to get all targets through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.get_all_targets(project_id)

    def get_target_by_id(self, target_id: int):
        """Delegate the request to get target by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.get_target_by_id(target_id)

    def update_target(self, target_id: int, request):
        """Delegate the request to update target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.update_target(target_id, request)

    def delete_target(self, target_id: int):
        """Delegate the request to delete target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.delete_target(target_id)
