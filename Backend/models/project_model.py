"""SQLAlchemy model for student assessment projects."""

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from Backend.database import Base


class Project(Base):
    """Represent the project table in the application database.

    SQLAlchemy maps these attributes and relationships to persisted records.
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="ACTIVE")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    user = relationship("User", back_populates="projects")
    targets = relationship(
        "Target",
        back_populates="project",
        cascade="all, delete-orphan",
    )
    scope_validations = relationship(
        "ScopeValidation",
        back_populates="project",
        cascade="all, delete-orphan",
    )
