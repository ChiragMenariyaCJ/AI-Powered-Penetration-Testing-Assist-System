"""Database operations for assessment-target records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.target_model import Target


@trace_repository
class TargetRepository:

    """Provide database operations for target records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    # Store the request-scoped SQLAlchemy session used by this repository’s queries.
    def __init__(self, db: Session):
        self.db = db

    # Create and commit the requested target record.
    def create_target(
        self,
        project_id: int,
        target_name: str,
        target_type: str,
        target_value: str,
        scope: str | None,
        status: str,
    ) -> Target:
        """Create and commit the requested target record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
        target = Target(
            project_id=project_id,
            target_name=target_name,
            target_type=target_type,
            target_value=target_value,
            scope=scope,
            status=status,
        )

        self.db.add(target)
        self.db.commit()
        self.db.refresh(target)

        return target

    # Query all targets with SQLAlchemy without changing stored database state.
    def get_all_targets(self) -> list[Target]:
        """Query target data for get all targets.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(Target).order_by(Target.id.desc()).all()

    # Query targets by project id with SQLAlchemy without changing stored database state.
    def get_targets_by_project_id(self, project_id: int) -> list[Target]:
        """Query target data for get targets by project id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Target)
            .filter(Target.project_id == project_id)
            .order_by(Target.id.desc())
            .all()
        )

    # Query target by id with SQLAlchemy without changing stored database state.
    def get_target_by_id(self, target_id: int) -> Target | None:
        """Query target data for get target by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Target)
            .filter(Target.id == target_id)
            .first()
        )

    # Persist the state change required to update target.
    def update_target(
        self,
        target: Target,
        update_data: dict,
    ) -> Target:
        """Persist the state change required to update target.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        for field, value in update_data.items():
            setattr(target, field, value)

        self.db.commit()
        self.db.refresh(target)

        return target

    # Delete the supplied target record and commit the transaction.
    def delete_target(self, target: Target) -> None:
        """Delete the supplied target record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(target)
        self.db.commit()
