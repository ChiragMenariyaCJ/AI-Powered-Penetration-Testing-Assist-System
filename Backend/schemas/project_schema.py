
# This file handles project schema.
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ProjectStatus = Literal["ACTIVE", "COMPLETED", "ARCHIVED"]


# Handle the project create request.
class ProjectCreateRequest(BaseModel):
    user_id: int = Field(gt=0)
    project_name: str = Field(min_length=2, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    status: ProjectStatus = "ACTIVE"


# Handle the project update request.
class ProjectUpdateRequest(BaseModel):
    project_name: str | None = Field(
        default=None,
        min_length=2,
        max_length=150,
    )
    description: str | None = Field(default=None, max_length=2000)
    status: ProjectStatus | None = None


# Handle the project response.
class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    project_name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
