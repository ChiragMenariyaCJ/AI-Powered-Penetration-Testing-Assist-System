
# This file handles auth controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.auth_usecase import AuthUseCase


# Handle the auth controller.
@trace_controller
class AuthController:

    # Set up this object.
    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.auth_usecase = AuthUseCase(repository)

    # Register register.
    def register(self, request):
        return self.auth_usecase.register(request)

    # Work with login.
    def login(self, request):
        return self.auth_usecase.login(request)
