from sqlalchemy.orm import Session

from Backend.models.scope_validation_model import ScopeValidation


class ScopeValidationRepository:

    def __init__(self, db: Session):
        self.db = db

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

    def get_all_scope_validations(self) -> list[ScopeValidation]:
        return (
            self.db.query(ScopeValidation)
            .order_by(ScopeValidation.id.desc())
            .all()
        )

    def get_scope_validations_by_project_id(
        self, project_id: int
    ) -> list[ScopeValidation]:
        return (
            self.db.query(ScopeValidation)
            .filter(ScopeValidation.project_id == project_id)
            .filter(ScopeValidation.status == "ACTIVE")
            .order_by(ScopeValidation.id.desc())
            .all()
        )

    def get_scope_validation_by_id(
        self, scope_validation_id: int
    ) -> ScopeValidation | None:
        return (
            self.db.query(ScopeValidation)
            .filter(ScopeValidation.id == scope_validation_id)
            .first()
        )

    def update_scope_validation(
        self,
        scope_validation: ScopeValidation,
        update_data: dict,
    ) -> ScopeValidation:
        for field, value in update_data.items():
            setattr(scope_validation, field, value)

        self.db.commit()
        self.db.refresh(scope_validation)

        return scope_validation

    def delete_scope_validation(self, scope_validation: ScopeValidation) -> None:
        self.db.delete(scope_validation)
        self.db.commit()
