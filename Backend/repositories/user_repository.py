"""Database operations for PTAS user accounts."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.user_model import User


@trace_repository
class UserRepository:

    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self,
        full_name: str,
        email: str,
        password_hash: str
    ) -> User:
        user = User(
            full_name=full_name,
            email=email,
            password_hash=password_hash
        )

        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        return user

    def get_user_by_email(self, email: str):
        return self.db.query(User).filter(
            User.email == email
        ).first()

    def get_user_by_id(self, user_id: int):
        return self.db.query(User).filter(
            User.id == user_id
        ).first()

    def get_all_users(self):
        return self.db.query(User).all()

    def delete_user(self, user: User):
        self.db.delete(user)
        self.db.commit()
