"""Database operations for recommendation records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.recommendation_model import Recommendation


@trace_repository
class RecommendationRepository:

    """Provide database operations for recommendation records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    # Store the request-scoped SQLAlchemy session used by this repository’s queries.
    def __init__(self, db: Session):
        self.db = db

    # Create and commit the requested recommendation record.
    def create_recommendation(
        self,
        vulnerability_id: int,
        attack_technique: str,
        mitre_technique_id: str | None,
        exploitation_method: str,
        risk_level: str,
        priority: int,
        likelihood: int,
        impact: int,
        prerequisites: str | None,
        tools_required: str | None,
        execution_steps: str | None,
        post_exploitation: str | None,
        confidence_score: int,
        status: str = "PENDING_APPROVAL",
    ) -> Recommendation:
        """Create and commit the requested recommendation record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
        recommendation = Recommendation(
            vulnerability_id=vulnerability_id,
            attack_technique=attack_technique,
            mitre_technique_id=mitre_technique_id,
            exploitation_method=exploitation_method,
            risk_level=risk_level,
            priority=priority,
            likelihood=likelihood,
            impact=impact,
            prerequisites=prerequisites,
            tools_required=tools_required,
            execution_steps=execution_steps,
            post_exploitation=post_exploitation,
            confidence_score=confidence_score,
            status=status,
        )

        self.db.add(recommendation)
        self.db.commit()
        self.db.refresh(recommendation)

        return recommendation

    # Query all recommendations with SQLAlchemy without changing stored database state.
    def get_all_recommendations(self) -> list[Recommendation]:
        """Query recommendation data for get all recommendations.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Recommendation)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Query recommendations by vulnerability id with SQLAlchemy without changing stored database state.
    def get_recommendations_by_vulnerability_id(
        self, vulnerability_id: int
    ) -> list[Recommendation]:
        """Query recommendation data for get recommendations by vulnerability id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.vulnerability_id == vulnerability_id)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Query recommendations by status with SQLAlchemy without changing stored database state.
    def get_recommendations_by_status(self, status: str) -> list[Recommendation]:
        """Query recommendation data for get recommendations by status.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.status == status)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Query recommendation by id with SQLAlchemy without changing stored database state.
    def get_recommendation_by_id(self, recommendation_id: int) -> Recommendation | None:
        """Query recommendation data for get recommendation by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.id == recommendation_id)
            .first()
        )

    # Persist the state change required to update recommendation.
    def update_recommendation(
        self,
        recommendation: Recommendation,
        update_data: dict,
    ) -> Recommendation:
        """Persist the state change required to update recommendation.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        for field, value in update_data.items():
            setattr(recommendation, field, value)

        self.db.commit()
        self.db.refresh(recommendation)

        return recommendation

    # Delete the supplied recommendation record and commit the transaction.
    def delete_recommendation(self, recommendation: Recommendation) -> None:
        """Delete the supplied recommendation record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(recommendation)
        self.db.commit()

    # Query recommendations by risk level with SQLAlchemy without changing stored database state.
    def get_recommendations_by_risk_level(self, risk_level: str) -> list[Recommendation]:
        """Query recommendation data for get recommendations by risk level.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.risk_level == risk_level)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Persist the state change required to approve recommendation.
    def approve_recommendation(
        self, recommendation: Recommendation, approved_by: str
    ) -> Recommendation:
        """Persist the state change required to approve recommendation.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        recommendation.status = "APPROVED"
        recommendation.approved_by = approved_by
        self.db.commit()
        self.db.refresh(recommendation)
        return recommendation

    # Persist the state change required to reject recommendation.
    def reject_recommendation(self, recommendation: Recommendation) -> Recommendation:
        """Persist the state change required to reject recommendation.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        recommendation.status = "REJECTED"
        self.db.commit()
        self.db.refresh(recommendation)
        return recommendation
