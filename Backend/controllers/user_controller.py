
# This file handles user controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.user_usecase import UserUseCase


# Handle the user controller.
@trace_controller
class UserController:

    # Set up this object.
    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.user_usecase = UserUseCase(repository)

    # Get all users.
    def get_all_users(self):
        return self.user_usecase.get_all_users()

    # Get user by ID.
    def get_user_by_id(self, user_id: int):
        return self.user_usecase.get_user_by_id(user_id)

    # Delete user.
    def delete_user(self, user_id: int):
        return self.user_usecase.delete_user(user_id)
