"""Translate user route requests into user use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.user_repository import UserRepository
from Backend.usecases.user_usecase import UserUseCase


@trace_controller
class UserController:
    """Connect user HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        repository = UserRepository(db)
        self.user_usecase = UserUseCase(repository)

    # Forward get all users to the user use case so this controller contains no business or SQL logic.
    def get_all_users(self):
        """Delegate the request to get all users through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.get_all_users()

    # Forward get user by id to the user use case so this controller contains no business or SQL logic.
    def get_user_by_id(self, user_id: int):
        """Delegate the request to get user by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.get_user_by_id(user_id)

    # Forward delete user to the user use case so this controller contains no business or SQL logic.
    def delete_user(self, user_id: int):
        """Delegate the request to delete user through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.delete_user(user_id)
