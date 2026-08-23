"""Validated API request and response shapes for scans."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ScanType = Literal["FULL", "QUICK", "CUSTOM", "VULNERABILITY", "PORT_SCAN"]
ScanStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "STOPPED"]


class ScanCreateRequest(BaseModel):
    """Validate the fields used when creating a new record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    target_id: int = Field(gt=0)
    scan_name: str = Field(min_length=2, max_length=150)
    scan_type: ScanType = "FULL"
    status: ScanStatus = "PENDING"


class ScanUpdateRequest(BaseModel):
    """Validate the fields used when updating an existing record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    scan_name: str | None = Field(default=None, min_length=2, max_length=150)
    scan_type: ScanType | None = None
    status: ScanStatus | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    scan_result: str | None = Field(default=None, max_length=10000)


class ScanResponse(BaseModel):
    """Validate the fields used when serializing a successful API response.

    Pydantic applies the declared types and constraints before application code runs.
    """
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    scan_name: str
    scan_type: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    scan_result: str | None
    created_at: datetime
    updated_at: datetime


class ScanListResponse(BaseModel):
    """Validate the fields used when returning a collection and its metadata.

    Pydantic applies the declared types and constraints before application code runs.
    """
    count: int
    scans: list[ScanResponse]
