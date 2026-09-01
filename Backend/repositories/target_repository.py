
# This file handles target repository.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.target_model import Target


# Handle the target repository.
@trace_repository
class TargetRepository:

    # Set up this object.
    def __init__(self, db: Session):
        self.db = db

    # Create target.
    def create_target(
        self,
        project_id: int,
        target_name: str,
        target_type: str,
        target_value: str,
        scope: str | None,
        status: str,
    ) -> Target:
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

    # Get all targets.
    def get_all_targets(self) -> list[Target]:
        return self.db.query(Target).order_by(Target.id.desc()).all()

    # Get targets by project ID.
    def get_targets_by_project_id(self, project_id: int) -> list[Target]:
        return (
            self.db.query(Target)
            .filter(Target.project_id == project_id)
            .order_by(Target.id.desc())
            .all()
        )

    # Get target by ID.
    def get_target_by_id(self, target_id: int) -> Target | None:
        return (
            self.db.query(Target)
            .filter(Target.id == target_id)
            .first()
        )

    # Update target.
    def update_target(
        self,
        target: Target,
        update_data: dict,
    ) -> Target:
        for field, value in update_data.items():
            setattr(target, field, value)

        self.db.commit()
        self.db.refresh(target)

        return target

    # Delete target.
    def delete_target(self, target: Target) -> None:
        self.db.delete(target)
        self.db.commit()
