
# This file handles user repository.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.user_model import User


# Handle the user repository.
@trace_repository
class UserRepository:

    # Set up this object.
    def __init__(self, db: Session):
        self.db = db

    # Create user.
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

    # Get user by email.
    def get_user_by_email(self, email: str):
        return self.db.query(User).filter(
            User.email == email
        ).first()

    # Get user by ID.
    def get_user_by_id(self, user_id: int):
        return self.db.query(User).filter(
            User.id == user_id
        ).first()

    # Get all users.
    def get_all_users(self):
        return self.db.query(User).all()

    # Delete user.
    def delete_user(self, user: User):
        self.db.delete(user)
        self.db.commit()
