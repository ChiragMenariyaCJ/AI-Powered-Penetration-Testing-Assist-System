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

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.auth_usecase = AuthUseCase(repository)

    # Forward register to the auth use case so this controller contains no business or SQL logic.
    def register(self, request):
        """Delegate the request to register through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.auth_usecase.register(request)

    # Forward login to the auth use case so this controller contains no business or SQL logic.
    def login(self, request):
        """Delegate the request to login through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.auth_usecase.login(request)
