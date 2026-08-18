from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from Backend.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Summary statistics
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Recommendations summary
    total_recommendations = Column(Integer, default=0)
    approved_recommendations = Column(Integer, default=0)
    pending_recommendations = Column(Integer, default=0)
    rejected_recommendations = Column(Integer, default=0)
    
    # Scan details
    target_count = Column(Integer, nullable=True)
    scan_duration_seconds = Column(Integer, nullable=True)
    scan_start_time = Column(DateTime, nullable=True)
    scan_end_time = Column(DateTime, nullable=True)
    
    # Report metadata
    status = Column(
        String(20),
        nullable=False,
        default="DRAFT"
    )  # DRAFT, COMPLETED, EXPORTED
    format_type = Column(String(20), nullable=False, default="JSON")  # JSON, PDF, HTML
    generated_by = Column(String(255), nullable=True)
    report_content = Column(Text, nullable=True)  # Stores JSON/HTML content
    
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    exported_at = Column(DateTime, nullable=True)

    # Relationships
    scan = relationship("Scan", back_populates="reports")
