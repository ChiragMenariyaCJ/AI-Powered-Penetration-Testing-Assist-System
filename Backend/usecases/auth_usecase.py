"""Authentication business rules for registration, login, and token creation."""

from fastapi import HTTPException

from Backend.api_logging import trace_usecase
from Backend.utils.password_utils import (
    hash_password,
    verify_password,
)

from Backend.utils.jwt_utils import create_access_token


@trace_usecase
class AuthUseCase:

    """Apply auth business rules between controllers and persistence.

    The use case validates related state and coordinates repositories or services.
    """
    def __init__(self, user_repository):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.user_repository = user_repository

    def register(self, request):

        """Apply business validation and orchestration needed to register.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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

    def login(self, request):

        """Apply business validation and orchestration needed to login.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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
