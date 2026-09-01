
# This file handles auth usecase.
from fastapi import HTTPException

from Backend.api_logging import trace_usecase
from Backend.utils.password_utils import (
    hash_password,
    verify_password,
)

from Backend.utils.jwt_utils import create_access_token


# Handle the auth use case.
@trace_usecase
class AuthUseCase:

    # Set up this object.
    def __init__(self, user_repository):
        self.user_repository = user_repository

    # Register register.
    def register(self, request):

        existing_user = self.user_repository.get_user_by_email(
            request.email
        )

        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already exists."
            )

        try:
            password_hash = hash_password(request.password)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

        user = self.user_repository.create_user(
            full_name=request.full_name,
            email=request.email,
            password_hash=password_hash,
        )

        return {
            "message": "User registered successfully.",
            "user_id": user.id,
        }

    # Work with login.
    def login(self, request):

        user = self.user_repository.get_user_by_email(
            request.email
        )

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )

        if not verify_password(
            request.password,
            user.password_hash,
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )

        token = create_access_token(
            {
                "user_id": user.id,
                "email": user.email,
            }
        )

        return {
            "message": "Login successful.",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "full_name": user.full_name,
                "email": user.email,
            },
        }
