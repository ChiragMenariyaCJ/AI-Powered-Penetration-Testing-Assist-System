
# This file handles recommendation controller.
from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.repositories.recommendation_repository import RecommendationRepository
from Backend.usecases.recommendation_usecase import RecommendationUseCase


# Handle the recommendation controller.
@trace_controller
class RecommendationController:

    # Set up this object.
    def __init__(self, db: Session):
        recommendation_repository = RecommendationRepository(db)
        vulnerability_repository = VulnerabilityRepository(db)

        self.recommendation_usecase = RecommendationUseCase(
            recommendation_repository,
            vulnerability_repository,
        )

    # Generate recommendations.
    def generate_recommendations(self, vulnerability_id: int):
        return self.recommendation_usecase.generate_recommendations_for_vulnerability(
            vulnerability_id
        )

    # Get recommendation by ID.
    def get_recommendation_by_id(self, recommendation_id: int):
        return self.recommendation_usecase.get_recommendation_by_id(
            recommendation_id
        )

    # Get all recommendations.
    def get_all_recommendations(self, vulnerability_id: int | None = None):
        return self.recommendation_usecase.get_all_recommendations(vulnerability_id)

    # Update recommendation.
    def update_recommendation(self, recommendation_id: int, request):
        return self.recommendation_usecase.update_recommendation(
            recommendation_id, request
        )

    # Delete recommendation.
    def delete_recommendation(self, recommendation_id: int):
        return self.recommendation_usecase.delete_recommendation(
            recommendation_id
        )

    # Approve recommendation.
    def approve_recommendation(self, recommendation_id: int, approved_by: str):
        return self.recommendation_usecase.approve_recommendation(
            recommendation_id, approved_by
        )

    # Reject recommendation.
    def reject_recommendation(self, recommendation_id: int):
        return self.recommendation_usecase.reject_recommendation(recommendation_id)

    # Get recommendations by status.
    def get_recommendations_by_status(self, status: str):
        return self.recommendation_usecase.get_recommendations_by_status(status)

    # Get attack score.
    def get_attack_score(self, vulnerability_id: int):
        return self.recommendation_usecase.get_attack_score(vulnerability_id)
