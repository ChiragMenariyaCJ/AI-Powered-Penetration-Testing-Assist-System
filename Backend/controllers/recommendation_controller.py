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

    # Build the repositories and use case this controller delegates to for one API request.
    def __init__(self, db: Session):
        recommendation_repository = RecommendationRepository(db)
        vulnerability_repository = VulnerabilityRepository(db)

        self.recommendation_usecase = RecommendationUseCase(
            recommendation_repository,
            vulnerability_repository,
        )

    # Forward generate recommendations to the recommendation use case so this controller contains no business or SQL logic.
    def generate_recommendations(self, vulnerability_id: int):
        """Delegate the request to generate recommendations through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.generate_recommendations_for_vulnerability(
            vulnerability_id
        )

    # Forward get recommendation by id to the recommendation use case so this controller contains no business or SQL logic.
    def get_recommendation_by_id(self, recommendation_id: int):
        """Delegate the request to get recommendation by id through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_recommendation_by_id(
            recommendation_id
        )

    # Forward get all recommendations to the recommendation use case so this controller contains no business or SQL logic.
    def get_all_recommendations(self, vulnerability_id: int | None = None):
        """Delegate the request to get all recommendations through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_all_recommendations(vulnerability_id)

    # Forward update recommendation to the recommendation use case so this controller contains no business or SQL logic.
    def update_recommendation(self, recommendation_id: int, request):
        """Delegate the request to update recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.update_recommendation(
            recommendation_id, request
        )

    # Forward delete recommendation to the recommendation use case so this controller contains no business or SQL logic.
    def delete_recommendation(self, recommendation_id: int):
        """Delegate the request to delete recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.delete_recommendation(
            recommendation_id
        )

    # Forward approve recommendation to the recommendation use case so this controller contains no business or SQL logic.
    def approve_recommendation(self, recommendation_id: int, approved_by: str):
        """Delegate the request to approve recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.approve_recommendation(
            recommendation_id, approved_by
        )

    # Forward reject recommendation to the recommendation use case so this controller contains no business or SQL logic.
    def reject_recommendation(self, recommendation_id: int):
        """Delegate the request to reject recommendation through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.reject_recommendation(recommendation_id)

    # Forward get recommendations by status to the recommendation use case so this controller contains no business or SQL logic.
    def get_recommendations_by_status(self, status: str):
        """Delegate the request to get recommendations by status through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_recommendations_by_status(status)

    # Forward get attack score to the recommendation use case so this controller contains no business or SQL logic.
    def get_attack_score(self, vulnerability_id: int):
        """Delegate the request to get attack score through the configured use case.

        The controller keeps transport concerns separate from validation and persistence
        rules.
        """
        return self.recommendation_usecase.get_attack_score(vulnerability_id)
