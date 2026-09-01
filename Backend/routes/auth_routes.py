
# This file handles auth routes.
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.database import get_db
from Backend.controllers.auth_controller import AuthController
from Backend.schemas.auth_schema import (
    UserRegisterRequest,
    UserLoginRequest,
)

router = APIRouter(route_class=LoggedRoute)


# Register register.
@router.post("/register")
def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    controller = AuthController(db)
    return controller.register(request)


# Work with login.
@router.post("/login")
def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db)
):
    controller = AuthController(db)
    return controller.login(request)
