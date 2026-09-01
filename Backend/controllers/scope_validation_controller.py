
# This file handles scope validation controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.scope_validation_repository import (
    ScopeValidationRepository,
)
from Backend.usecases.scope_validation_usecase import ScopeValidationUseCase


# Handle the scope validation controller.
@trace_controller
class ScopeValidationController:

    # Set up this object.
    def __init__(self, db: Session):
        scope_validation_repository = ScopeValidationRepository(db)
        project_repository = ProjectRepository(db)

        self.scope_validation_usecase = ScopeValidationUseCase(
            scope_validation_repository,
            project_repository,
        )

    # Create scope validation.
    def create_scope_validation(self, request):
        return self.scope_validation_usecase.create_scope_validation(request)

    # Get all scope validations.
    def get_all_scope_validations(self, project_id: int | None = None):
        return self.scope_validation_usecase.get_all_scope_validations(project_id)

    # Get scope validation by ID.
    def get_scope_validation_by_id(self, scope_validation_id: int):
        return self.scope_validation_usecase.get_scope_validation_by_id(
            scope_validation_id
        )

    # Update scope validation.
    def update_scope_validation(self, scope_validation_id: int, request):
        return self.scope_validation_usecase.update_scope_validation(
            scope_validation_id, request
        )

    # Delete scope validation.
    def delete_scope_validation(self, scope_validation_id: int):
        return self.scope_validation_usecase.delete_scope_validation(
            scope_validation_id
        )

    # Check target in scope.
    def check_target_in_scope(self, project_id: int, target_value: str):
        return self.scope_validation_usecase.check_target_in_scope(
            project_id, target_value
        )
