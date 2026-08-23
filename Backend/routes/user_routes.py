"""User lookup and deletion endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.database import get_db
from Backend.controllers.user_controller import UserController

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


@router.get("/")
def get_all_users(db: Session = Depends(get_db)):
    """Handle the HTTP request that asks PTAS to get all users.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = UserController(db)
    return controller.get_all_users()


@router.get("/{user_id}")
def get_user_by_id(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Handle the HTTP request that asks PTAS to get user by id.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = UserController(db)
    return controller.get_user_by_id(user_id)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    """Handle the HTTP request that asks PTAS to delete user.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = UserController(db)
    return controller.delete_user(user_id)
