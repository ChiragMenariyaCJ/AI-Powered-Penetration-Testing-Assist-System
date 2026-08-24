"""Recommendation generation and review endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.api_logging import LoggedRoute
from Backend.controllers.recommendation_controller import RecommendationController
from Backend.database import get_db
from Backend.schemas.recommendation_schema import (
    RecommendationCreateRequest,
    RecommendationListResponse,
    RecommendationResponse,
    RecommendationUpdateRequest,
    RecommendationScore,
)

# Every route uses the shared terminal request logger.
router = APIRouter(route_class=LoggedRoute)


# Validate HTTP inputs and delegate the generate recommendations request to the recommendation controller.
@router.post(
    "/generate/{vulnerability_id}",
    response_model=RecommendationListResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_recommendations(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to generate recommendations.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    result = controller.generate_recommendations(vulnerability_id)
    return {
        "count": result.get("recommendations_count", 0),
        "recommendations": result.get("recommendations", []),
    }


# Validate HTTP inputs and delegate the get all recommendations request to the recommendation controller.
@router.get("/", response_model=RecommendationListResponse)
def get_all_recommendations(
    vulnerability_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get all recommendations.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.get_all_recommendations(vulnerability_id)


# Validate HTTP inputs and delegate the get recommendation by id request to the recommendation controller.
@router.get("/{recommendation_id}", response_model=RecommendationResponse)
def get_recommendation_by_id(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get recommendation by id.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.get_recommendation_by_id(recommendation_id)


# Validate HTTP inputs and delegate the update recommendation request to the recommendation controller.
@router.put("/{recommendation_id}", response_model=RecommendationResponse)
def update_recommendation(
    recommendation_id: int,
    request: RecommendationUpdateRequest,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to update recommendation.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.update_recommendation(recommendation_id, request)


# Validate HTTP inputs and delegate the delete recommendation request to the recommendation controller.
@router.delete("/{recommendation_id}")
def delete_recommendation(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to delete recommendation.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.delete_recommendation(recommendation_id)


# Validate HTTP inputs and delegate the approve recommendation request to the recommendation controller.
@router.post("/{recommendation_id}/approve")
def approve_recommendation(
    recommendation_id: int,
    approved_by: str = Query(min_length=1, max_length=100),
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to approve recommendation.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.approve_recommendation(recommendation_id, approved_by)


# Validate HTTP inputs and delegate the reject recommendation request to the recommendation controller.
@router.post("/{recommendation_id}/reject")
def reject_recommendation(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to reject recommendation.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.reject_recommendation(recommendation_id)


# Validate HTTP inputs and delegate the get recommendations by status request to the recommendation controller.
@router.get("/status/{status_filter}", response_model=RecommendationListResponse)
def get_recommendations_by_status(
    status_filter: str,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get recommendations by status.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.get_recommendations_by_status(status_filter)


# Validate HTTP inputs and delegate the get attack score request to the recommendation controller.
@router.get("/attack-score/{vulnerability_id}", response_model=RecommendationScore)
def get_attack_score(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    """Handle the HTTP request that asks PTAS to get attack score.

    FastAPI validates inputs and supplies a database session before this endpoint
    delegates to its controller.
    """
    controller = RecommendationController(db)
    return controller.get_attack_score(vulnerability_id)
