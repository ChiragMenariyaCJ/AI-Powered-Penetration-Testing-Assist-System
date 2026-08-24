"""Database operations for authorized-scope records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.scope_validation_model import ScopeValidation


@trace_repository
class ScopeValidationRepository:

    """Provide database operations for scope validation records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    # Store the request-scoped SQLAlchemy session used by this repository’s queries.
    def __init__(self, db: Session):
        self.db = db

    # Create and commit the requested scope validation record.
    def create_scope_validation(
        self,
        project_id: int,
        scope_rule_name: str,
        scope_type: str,
        scope_value: str,
        description: str | None,
        is_inclusive: bool,
        status: str,
    ) -> ScopeValidation:
        """Create and commit the requested scope validation record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
        scope_validation = ScopeValidation(
            project_id=project_id,
            scope_rule_name=scope_rule_name,
            scope_type=scope_type,
            scope_value=scope_value,
            description=description,
            is_inclusive=is_inclusive,
            status=status,
        )

        self.db.add(scope_validation)
        self.db.commit()
        self.db.refresh(scope_validation)

        return scope_validation

    # Query all scope validations with SQLAlchemy without changing stored database state.
    def get_all_scope_validations(self) -> list[ScopeValidation]:
        """Query scope validation data for get all scope validations.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(ScopeValidation)
            .order_by(ScopeValidation.id.desc())
            .all()
        )

    # Query scope validations by project id with SQLAlchemy without changing stored database state.
    def get_scope_validations_by_project_id(
        self, project_id: int
    ) -> list[ScopeValidation]:
        """Query scope validation data for get scope validations by project id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(ScopeValidation)
            .filter(ScopeValidation.project_id == project_id)
            .filter(ScopeValidation.status == "ACTIVE")
            .order_by(ScopeValidation.id.desc())
            .all()
        )

    # Query scope validation by id with SQLAlchemy without changing stored database state.
    def get_scope_validation_by_id(
        self, scope_validation_id: int
    ) -> ScopeValidation | None:
        """Query scope validation data for get scope validation by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(ScopeValidation)
            .filter(ScopeValidation.id == scope_validation_id)
            .first()
        )

    # Persist the state change required to update scope validation.
    def update_scope_validation(
        self,
        scope_validation: ScopeValidation,
        update_data: dict,
    ) -> ScopeValidation:
        """Persist the state change required to update scope validation.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        for field, value in update_data.items():
            setattr(scope_validation, field, value)

        self.db.commit()
        self.db.refresh(scope_validation)

        return scope_validation

    # Delete the supplied scope validation record and commit the transaction.
    def delete_scope_validation(self, scope_validation: ScopeValidation) -> None:
        """Delete the supplied scope validation record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(scope_validation)
        self.db.commit()
