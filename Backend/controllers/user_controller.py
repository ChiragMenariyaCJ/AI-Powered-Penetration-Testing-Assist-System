from sqlalchemy.orm import Session

from Backend.repositories.user_repository import UserRepository
from Backend.usecases.user_usecase import UserUseCase


class UserController:

    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.user_usecase = UserUseCase(repository)

    def get_all_users(self):
        return self.user_usecase.get_all_users()

    def get_user_by_id(self, user_id: int):
        return self.user_usecase.get_user_by_id(user_id)

    def delete_user(self, user_id: int):
        return self.user_usecase.delete_user(user_id)