"""Translate authentication route requests into authentication use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.auth_usecase import AuthUseCase


@trace_controller
class AuthController:
    """Connect auth HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        repository = UserRepository(db)
        self.auth_usecase = AuthUseCase(repository)

    def register(self, request):
        """Delegate the request to register through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.auth_usecase.register(request)

    def login(self, request):
        """Delegate the request to login through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.auth_usecase.login(request)
