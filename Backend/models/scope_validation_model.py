"""SQLAlchemy model for explicit project authorization boundaries."""

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import relationship

from Backend.database import Base


class ScopeValidation(Base):
    __tablename__ = "scope_validations"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scope_rule_name = Column(String(150), nullable=False)
    scope_type = Column(String(50), nullable=False, default="CIDR")
    scope_value = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_inclusive = Column(Boolean, nullable=False, default=True)
    status = Column(String(20), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    project = relationship("Project", back_populates="scope_validations")
