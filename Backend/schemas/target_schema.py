
# This file handles target schema.
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


TargetType = Literal["HOST", "NETWORK", "WEBSITE", "API"]
TargetStatus = Literal["ACTIVE", "INACTIVE", "ARCHIVED"]


# Handle the target create request.
class TargetCreateRequest(BaseModel):
    project_id: int = Field(gt=0)
    target_name: str = Field(min_length=2, max_length=150)
    target_type: TargetType = "HOST"
    target_value: str = Field(min_length=3, max_length=255)
    scope: str | None = Field(default=None, max_length=2000)
    status: TargetStatus = "ACTIVE"


# Handle the target update request.
class TargetUpdateRequest(BaseModel):
    target_name: str | None = Field(default=None, min_length=2, max_length=150)
    target_type: TargetType | None = None
    target_value: str | None = Field(default=None, min_length=3, max_length=255)
    scope: str | None = Field(default=None, max_length=2000)
    status: TargetStatus | None = None


# Handle the target response.
class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    target_name: str
    target_type: str
    target_value: str
    scope: str | None
    status: str
    created_at: datetime
    updated_at: datetime


# Handle the target list response.
class TargetListResponse(BaseModel):
    count: int
    targets: list[TargetResponse]
