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


@router.post("/register")
def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    controller = AuthController(db)
    return controller.register(request)


@router.post("/login")
def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db)
):
    controller = AuthController(db)
    return controller.login(request)
