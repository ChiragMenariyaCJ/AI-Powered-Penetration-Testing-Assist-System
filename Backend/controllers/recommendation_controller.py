"""Translate recommendation routes into recommendation use-case calls."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_controller
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.repositories.recommendation_repository import RecommendationRepository
from Backend.usecases.recommendation_usecase import RecommendationUseCase


@trace_controller
class RecommendationController:
    """Connect recommendation HTTP handlers to the business layer.

    The controller constructs dependencies and delegates without performing SQL itself.
    """

    def __init__(self, db: Session):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        recommendation_repository = RecommendationRepository(db)
        vulnerability_repository = VulnerabilityRepository(db)

        self.recommendation_usecase = RecommendationUseCase(
            recommendation_repository,
            vulnerability_repository,
        )

    def generate_recommendations(self, vulnerability_id: int):
        """Delegate the request to generate recommendations through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.generate_recommendations_for_vulnerability(
            vulnerability_id
        )

    def get_recommendation_by_id(self, recommendation_id: int):
        """Delegate the request to get recommendation by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_recommendation_by_id(
            recommendation_id
        )

    def get_all_recommendations(self, vulnerability_id: int | None = None):
        """Delegate the request to get all recommendations through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_all_recommendations(vulnerability_id)

    def update_recommendation(self, recommendation_id: int, request):
        """Delegate the request to update recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.update_recommendation(
            recommendation_id, request
        )

    def delete_recommendation(self, recommendation_id: int):
        """Delegate the request to delete recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.delete_recommendation(
            recommendation_id
        )

    def approve_recommendation(self, recommendation_id: int, approved_by: str):
        """Delegate the request to approve recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.approve_recommendation(
            recommendation_id, approved_by
        )

    def reject_recommendation(self, recommendation_id: int):
        """Delegate the request to reject recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.reject_recommendation(recommendation_id)

    def get_recommendations_by_status(self, status: str):
        """Delegate the request to get recommendations by status through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_recommendations_by_status(status)

    def get_attack_score(self, vulnerability_id: int):
        """Delegate the request to get attack score through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_attack_score(vulnerability_id)
