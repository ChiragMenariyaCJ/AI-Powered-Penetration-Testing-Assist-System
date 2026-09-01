
# This file handles recommendation repository.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.recommendation_model import Recommendation


# Handle the recommendation repository.
@trace_repository
class RecommendationRepository:

    # Set up this object.
    def __init__(self, db: Session):
        self.db = db

    # Create recommendation.
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

    # Get all recommendations.
    def get_all_recommendations(self) -> list[Recommendation]:
        return (
            self.db.query(Recommendation)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Get recommendations by vulnerability ID.
    def get_recommendations_by_vulnerability_id(
        self, vulnerability_id: int
    ) -> list[Recommendation]:
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.vulnerability_id == vulnerability_id)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Get recommendations by status.
    def get_recommendations_by_status(self, status: str) -> list[Recommendation]:
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.status == status)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Get recommendation by ID.
    def get_recommendation_by_id(self, recommendation_id: int) -> Recommendation | None:
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.id == recommendation_id)
            .first()
        )

    # Update recommendation.
    def update_recommendation(
        self,
        recommendation: Recommendation,
        update_data: dict,
    ) -> Recommendation:
        for field, value in update_data.items():
            setattr(recommendation, field, value)

        self.db.commit()
        self.db.refresh(recommendation)

        return recommendation

    # Delete recommendation.
    def delete_recommendation(self, recommendation: Recommendation) -> None:
        self.db.delete(recommendation)
        self.db.commit()

    # Get recommendations by risk level.
    def get_recommendations_by_risk_level(self, risk_level: str) -> list[Recommendation]:
        return (
            self.db.query(Recommendation)
            .filter(Recommendation.risk_level == risk_level)
            .order_by(Recommendation.priority.desc())
            .all()
        )

    # Approve recommendation.
    def approve_recommendation(
        self, recommendation: Recommendation, approved_by: str
    ) -> Recommendation:
        recommendation.status = "APPROVED"
        recommendation.approved_by = approved_by
        self.db.commit()
        self.db.refresh(recommendation)
        return recommendation

    # Reject recommendation.
    def reject_recommendation(self, recommendation: Recommendation) -> Recommendation:
        recommendation.status = "REJECTED"
        self.db.commit()
        self.db.refresh(recommendation)
        return recommendation
