from sqlalchemy.orm import Session

from Backend.repositories.user_repository import UserRepository
from Backend.usecases.auth_usecase import AuthUseCase


class AuthController:

    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.auth_usecase = AuthUseCase(repository)

    def register(self, request):
        return self.auth_usecase.register(request)

    def login(self, request):
        return self.auth_usecase.login(request)