from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from Backend.database import get_db
from Backend.controllers.user_controller import UserController

router = APIRouter()


@router.get("/")
def get_all_users(db: Session = Depends(get_db)):
    controller = UserController(db)
    return controller.get_all_users()


@router.get("/{user_id}")
def get_user_by_id(
    user_id: int,
    db: Session = Depends(get_db)
):
    controller = UserController(db)
    return controller.get_user_by_id(user_id)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db)
):
    controller = UserController(db)
    return controller.delete_user(user_id)