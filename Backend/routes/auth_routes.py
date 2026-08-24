"""Authentication HTTP endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.database import get_db
from Backend.controllers.auth_controller import AuthController
from Backend.schemas.auth_schema import (
    UserRegisterRequest,
    UserLoginRequest,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


# Validate HTTP inputs and delegate the register request to the auth controller.
@router.post("/register")
def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """Handle the HTTP request that asks PTAS to register.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = AuthController(db)
    return controller.register(request)


# Validate HTTP inputs and delegate the login request to the auth controller.
@router.post("/login")
def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db)
):
    """Handle the HTTP request that asks PTAS to login.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = AuthController(db)
    return controller.login(request)
