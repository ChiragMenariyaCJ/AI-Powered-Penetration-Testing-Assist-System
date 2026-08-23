"""Business rules for retrieving and deleting user accounts."""

from fastapi import HTTPException

from Backend.api_logging import trace_usecase

@trace_usecase
class UserUseCase:

    def __init__(self, user_repository):
        self.user_repository = user_repository

    def get_all_users(self):
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
