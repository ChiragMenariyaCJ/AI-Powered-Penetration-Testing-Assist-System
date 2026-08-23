"""Validated API shapes for report creation, export, and retrieval."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ReportCreateRequest(BaseModel):
    """Validate the fields used when creating a new record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    scan_id: int
    title: str
    description: Optional[str] = None
    generated_by: Optional[str] = None


class ReportUpdateRequest(BaseModel):
    """Validate the fields used when updating an existing record.

    Pydantic applies the declared types and constraints before application code runs.
    """
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    format_type: Optional[str] = None


class VulnerabilitySummary(BaseModel):
    """Validate the fields used when exchanging VulnerabilitySummary data through the API.

    Pydantic applies the declared types and constraints before application code runs.
    """
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class RecommendationSummary(BaseModel):
    """Validate the fields used when exchanging RecommendationSummary data through the API.

    Pydantic applies the declared types and constraints before application code runs.
    """
    total: int
    approved: int
    pending: int
    rejected: int


class ScanMetadata(BaseModel):
    """Validate the fields used when exchanging ScanMetadata data through the API.

    Pydantic applies the declared types and constraints before application code runs.
    """
    scan_id: int
    target_count: Optional[int] = None
    duration_seconds: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class ReportResponse(BaseModel):
    """Validate the fields used when serializing a successful API response.

    Pydantic applies the declared types and constraints before application code runs.
    """
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
    """Validate the fields used when returning a collection and its metadata.

    Pydantic applies the declared types and constraints before application code runs.
    """
    reports: list[ReportResponse]
    total: int


class ReportExportRequest(BaseModel):
    """Validate the fields used when exchanging ReportExportRequest data through the API.

    Pydantic applies the declared types and constraints before application code runs.
    """
    format_type: str  # JSON, PDF, HTML
    exported_by: Optional[str] = None


class ReportExportResponse(BaseModel):
    """Validate the fields used when serializing a successful API response.

    Pydantic applies the declared types and constraints before application code runs.
    """
    id: int
    status: str
    format_type: str
    message: str
    exported_at: Optional[datetime] = None
