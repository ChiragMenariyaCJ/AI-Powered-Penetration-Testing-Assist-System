"""Database operations for PTAS user accounts."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.user_model import User


@trace_repository
class UserRepository:

    """Provide database operations for user records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.db = db

    def create_user(
        self,
        full_name: str,
        email: str,
        password_hash: str
    ) -> User:
        """Create and commit the requested user record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
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
        """Query user data for get user by email.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(User).filter(
            User.email == email
        ).first()

    def get_user_by_id(self, user_id: int):
        """Query user data for get user by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(User).filter(
            User.id == user_id
        ).first()

    def get_all_users(self):
        """Query user data for get all users.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(User).all()

    def delete_user(self, user: User):
        """Delete the supplied user record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(user)
        self.db.commit()
