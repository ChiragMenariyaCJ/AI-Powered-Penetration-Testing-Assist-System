from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ScopeType = Literal["CIDR", "DOMAIN", "IP_RANGE", "HOSTNAME", "WILDCARD"]
ScopeStatus = Literal["ACTIVE", "INACTIVE", "ARCHIVED"]


class ScopeValidationCreateRequest(BaseModel):
    project_id: int = Field(gt=0)
    scope_rule_name: str = Field(min_length=2, max_length=150)
    scope_type: ScopeType = "CIDR"
    scope_value: str = Field(min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    is_inclusive: bool = True
    status: ScopeStatus = "ACTIVE"


class ScopeValidationUpdateRequest(BaseModel):
    scope_rule_name: str | None = Field(default=None, min_length=2, max_length=150)
    scope_type: ScopeType | None = None
    scope_value: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    is_inclusive: bool | None = None
    status: ScopeStatus | None = None


class ScopeValidationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    scope_rule_name: str
    scope_type: str
    scope_value: str
    description: str | None
    is_inclusive: bool
    status: str
    created_at: datetime
    updated_at: datetime


class ScopeValidationListResponse(BaseModel):
    count: int
    scope_validations: list[ScopeValidationResponse]


class ScopeCheckRequest(BaseModel):
    project_id: int = Field(gt=0)
    target_value: str = Field(min_length=3, max_length=255)


class ScopeCheckResponse(BaseModel):
    is_in_scope: bool
    matching_rules: list[str] = []
    blocked_by_rules: list[str] = []
