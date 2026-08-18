from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from Backend.controllers.recommendation_controller import RecommendationController
from Backend.database import get_db
from Backend.schemas.recommendation_schema import (
    RecommendationCreateRequest,
    RecommendationListResponse,
    RecommendationResponse,
    RecommendationUpdateRequest,
    RecommendationScore,
)

router = APIRouter()


@router.post(
    "/generate/{vulnerability_id}",
    response_model=RecommendationListResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_recommendations(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    """Generate AI recommendations for a vulnerability"""
    controller = RecommendationController(db)
    result = controller.generate_recommendations(vulnerability_id)
    return {
        "count": result.get("recommendations_count", 0),
        "recommendations": result.get("recommendations", []),
    }


@router.get("/", response_model=RecommendationListResponse)
def get_all_recommendations(
    vulnerability_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
):
    controller = RecommendationController(db)
    return controller.get_all_recommendations(vulnerability_id)


@router.get("/{recommendation_id}", response_model=RecommendationResponse)
def get_recommendation_by_id(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    controller = RecommendationController(db)
    return controller.get_recommendation_by_id(recommendation_id)


@router.put("/{recommendation_id}", response_model=RecommendationResponse)
def update_recommendation(
    recommendation_id: int,
    request: RecommendationUpdateRequest,
    db: Session = Depends(get_db),
):
    controller = RecommendationController(db)
    return controller.update_recommendation(recommendation_id, request)


@router.delete("/{recommendation_id}")
def delete_recommendation(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    controller = RecommendationController(db)
    return controller.delete_recommendation(recommendation_id)


@router.post("/{recommendation_id}/approve")
def approve_recommendation(
    recommendation_id: int,
    approved_by: str = Query(min_length=1, max_length=100),
    db: Session = Depends(get_db),
):
    """Approve a recommendation for execution"""
    controller = RecommendationController(db)
    return controller.approve_recommendation(recommendation_id, approved_by)


@router.post("/{recommendation_id}/reject")
def reject_recommendation(
    recommendation_id: int,
    db: Session = Depends(get_db),
):
    """Reject a recommendation"""
    controller = RecommendationController(db)
    return controller.reject_recommendation(recommendation_id)


@router.get("/status/{status_filter}", response_model=RecommendationListResponse)
def get_recommendations_by_status(
    status_filter: str,
    db: Session = Depends(get_db),
):
    controller = RecommendationController(db)
    return controller.get_recommendations_by_status(status_filter)


@router.get("/attack-score/{vulnerability_id}", response_model=RecommendationScore)
def get_attack_score(
    vulnerability_id: int,
    db: Session = Depends(get_db),
):
    """Calculate attack score for a vulnerability"""
    controller = RecommendationController(db)
    return controller.get_attack_score(vulnerability_id)
