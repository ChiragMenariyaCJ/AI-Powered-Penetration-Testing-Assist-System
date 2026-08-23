"""Validated API request and response shapes for projects."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ProjectStatus = Literal["ACTIVE", "COMPLETED", "ARCHIVED"]


class ProjectCreateRequest(BaseModel):
    """Validate the fields used when creating a new record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    user_id: int = Field(gt=0)
    project_name: str = Field(min_length=2, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    status: ProjectStatus = "ACTIVE"


class ProjectUpdateRequest(BaseModel):
    """Validate the fields used when updating an existing record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    project_name: str | None = Field(
        default=None,
        min_length=2,
        max_length=150,
    )
    description: str | None = Field(default=None, max_length=2000)
    status: ProjectStatus | None = None


class ProjectResponse(BaseModel):
    """Validate the fields used when serializing a successful API response.

    Pydantic applies the declared types and constraints before application code runs.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    project_name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
