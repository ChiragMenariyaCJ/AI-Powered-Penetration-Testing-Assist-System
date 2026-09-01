
# This file handles scan schema.
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ScanType = Literal["FULL", "QUICK", "CUSTOM", "VULNERABILITY", "PORT_SCAN"]
ScanStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "STOPPED"]


# Handle the scan create request.
class ScanCreateRequest(BaseModel):
    target_id: int = Field(gt=0)
    scan_name: str = Field(min_length=2, max_length=150)
    scan_type: ScanType = "FULL"
    status: ScanStatus = "PENDING"


# Handle the scan update request.
class ScanUpdateRequest(BaseModel):
    scan_name: str | None = Field(default=None, min_length=2, max_length=150)
    scan_type: ScanType | None = None
    status: ScanStatus | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    scan_result: str | None = Field(default=None, max_length=10000)


# Handle the scan response.
class ScanResponse(BaseModel):
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


# Handle the scan list response.
class ScanListResponse(BaseModel):
    count: int
    scans: list[ScanResponse]
