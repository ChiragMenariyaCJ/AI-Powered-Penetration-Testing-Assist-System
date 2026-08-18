from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from Backend.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_name = Column(String(150), nullable=False)
    scan_type = Column(String(50), nullable=False, default="FULL")
    status = Column(String(20), nullable=False, default="PENDING")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    scan_result = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
