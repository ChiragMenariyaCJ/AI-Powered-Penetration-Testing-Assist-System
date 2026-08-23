"""Business rules for retrieving and deleting user accounts."""

from fastapi import HTTPException

from Backend.api_logging import trace_usecase

@trace_usecase
class UserUseCase:

    """Apply user business rules between controllers and persistence.

    The use case validates related state and coordinates repositories or services.
    """
    def __init__(self, user_repository):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.user_repository = user_repository

    def get_all_users(self):
        """Apply business validation and orchestration needed to get all users.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        users = self.user_repository.get_all_users()

        return {
            "count": len(users),
            "users": [
                {
                    "id": user.id,
                    "full_name": user.full_name,
                    "email": user.email
                }
                for user in users
            ]
        }

    def get_user_by_id(self, user_id: int):
        """Apply business validation and orchestration needed to get user by id.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        user = self.user_repository.get_user_by_id(user_id)

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        return {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email
        }

    def delete_user(self, user_id: int):
        """Apply business validation and orchestration needed to delete user.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        user = self.user_repository.get_user_by_id(user_id)

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        deleted_user = {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email
        }

        self.user_repository.delete_user(user)

        return {
            "message": "User deleted successfully",
            "user": deleted_user
        }
