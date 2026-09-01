
# This file handles report schema.
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


# Handle the report create request.
class ReportCreateRequest(BaseModel):
    scan_id: int
    title: str
    description: Optional[str] = None
    generated_by: Optional[str] = None


# Handle the report update request.
class ReportUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    format_type: Optional[str] = None


# Handle the vulnerability summary.
class VulnerabilitySummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# Handle the recommendation summary.
class RecommendationSummary(BaseModel):
    total: int
    approved: int
    pending: int
    rejected: int


# Handle the scan metadata.
class ScanMetadata(BaseModel):
    scan_id: int
    target_count: Optional[int] = None
    duration_seconds: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


# Handle the report response.
class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    title: str
    description: Optional[str] = None
    vulnerability_summary: VulnerabilitySummary
    recommendation_summary: RecommendationSummary
    scan_metadata: ScanMetadata
    status: str
    format_type: str
    generated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    exported_at: Optional[datetime] = None

# Handle the report list response.
class ReportListResponse(BaseModel):
    reports: list[ReportResponse]
    total: int


# Handle the report export request.
class ReportExportRequest(BaseModel):
    format_type: str  # JSON, PDF, HTML
    exported_by: Optional[str] = None


# Handle the report export response.
class ReportExportResponse(BaseModel):
    id: int
    status: str
    format_type: str
    message: str
    exported_at: Optional[datetime] = None
