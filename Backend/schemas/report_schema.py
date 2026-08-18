from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ReportCreateRequest(BaseModel):
    scan_id: int
    title: str
    description: Optional[str] = None
    generated_by: Optional[str] = None


class ReportUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    format_type: Optional[str] = None


class VulnerabilitySummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class RecommendationSummary(BaseModel):
    total: int
    approved: int
    pending: int
    rejected: int


class ScanMetadata(BaseModel):
    scan_id: int
    target_count: Optional[int] = None
    duration_seconds: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


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

class ReportListResponse(BaseModel):
    reports: list[ReportResponse]
    total: int


class ReportExportRequest(BaseModel):
    format_type: str  # JSON, PDF, HTML
    exported_by: Optional[str] = None


class ReportExportResponse(BaseModel):
    id: int
    status: str
    format_type: str
    message: str
    exported_at: Optional[datetime] = None
