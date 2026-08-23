"""Validated API shapes for recommendations and attack scores."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RecommendationStatus = Literal["PENDING_APPROVAL", "APPROVED", "REJECTED", "EXECUTED"]


class RecommendationCreateRequest(BaseModel):
    vulnerability_id: int = Field(gt=0)
    attack_technique: str = Field(min_length=3, max_length=255)
    mitre_technique_id: str | None = Field(default=None, max_length=50)
    exploitation_method: str = Field(min_length=10, max_length=3000)
    risk_level: RiskLevel = "MEDIUM"
    priority: int = Field(default=1, ge=1, le=10)
    likelihood: int = Field(default=50, ge=0, le=100)
    impact: int = Field(default=50, ge=0, le=100)
    prerequisites: str | None = Field(default=None, max_length=1000)
    tools_required: str | None = Field(default=None, max_length=1000)
    execution_steps: str | None = Field(default=None, max_length=3000)
    post_exploitation: str | None = Field(default=None, max_length=2000)
    confidence_score: int = Field(default=80, ge=0, le=100)


class RecommendationUpdateRequest(BaseModel):
    attack_technique: str | None = Field(default=None, min_length=3, max_length=255)
    exploitation_method: str | None = Field(default=None, min_length=10, max_length=3000)
    risk_level: RiskLevel | None = None
    priority: int | None = Field(default=None, ge=1, le=10)
    status: RecommendationStatus | None = None
    approved_by: str | None = Field(default=None, max_length=100)


class RecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vulnerability_id: int
    attack_technique: str
    mitre_technique_id: str | None
    exploitation_method: str
    risk_level: str
    priority: int
    likelihood: int
    impact: int
    prerequisites: str | None
    tools_required: str | None
    execution_steps: str | None
    post_exploitation: str | None
    confidence_score: int
    status: str
    approved_by: str | None
    created_at: datetime
    updated_at: datetime


class RecommendationListResponse(BaseModel):
    count: int
    recommendations: list[RecommendationResponse]


class AIRecommendationRequest(BaseModel):
    vulnerability_id: int = Field(gt=0)


class RecommendationScore(BaseModel):
    risk_score: int  # 0-100
    attack_complexity: str  # LOW, MEDIUM, HIGH
    required_privileges: str  # NONE, LOW, HIGH
    success_probability: int  # 0-100
