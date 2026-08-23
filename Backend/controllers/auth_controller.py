"""Translate authentication route requests into authentication use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.auth_usecase import AuthUseCase


@trace_controller
class AuthController:
    """Connect authentication HTTP handlers to the business layer."""

    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.auth_usecase = AuthUseCase(repository)

    def register(self, request):
        return self.auth_usecase.register(request)

    def login(self, request):
        return self.auth_usecase.login(request)
