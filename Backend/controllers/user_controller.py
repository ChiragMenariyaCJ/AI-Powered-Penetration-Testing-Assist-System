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

    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        repository = UserRepository(db)
        self.user_usecase = UserUseCase(repository)

    def get_all_users(self):
        """Delegate the request to get all users through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.get_all_users()

    def get_user_by_id(self, user_id: int):
        """Delegate the request to get user by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.get_user_by_id(user_id)

    def delete_user(self, user_id: int):
        """Delegate the request to delete user through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.user_usecase.delete_user(user_id)
