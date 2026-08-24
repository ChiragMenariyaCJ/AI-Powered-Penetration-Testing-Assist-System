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

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        target_repository = TargetRepository(db)
        project_repository = ProjectRepository(db)

        self.target_usecase = TargetUseCase(
            target_repository,
            project_repository,
        )

    # Forward create target to the target use case so this controller contains no business or SQL logic.
    def create_target(self, request):
        """Delegate the request to create target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.create_target(request)

    # Forward get all targets to the target use case so this controller contains no business or SQL logic.
    def get_all_targets(self, project_id: int | None = None):
        """Delegate the request to get all targets through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.get_all_targets(project_id)

    # Forward get target by id to the target use case so this controller contains no business or SQL logic.
    def get_target_by_id(self, target_id: int):
        """Delegate the request to get target by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.get_target_by_id(target_id)

    # Forward update target to the target use case so this controller contains no business or SQL logic.
    def update_target(self, target_id: int, request):
        """Delegate the request to update target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.update_target(target_id, request)

    # Forward delete target to the target use case so this controller contains no business or SQL logic.
    def delete_target(self, target_id: int):
        """Delegate the request to delete target through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.target_usecase.delete_target(target_id)
