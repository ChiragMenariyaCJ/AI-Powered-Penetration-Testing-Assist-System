from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from Backend.database import Base


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attack_technique = Column(String(255), nullable=False)
    mitre_technique_id = Column(String(50), nullable=True)
    exploitation_method = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False, default="MEDIUM")
    priority = Column(Integer, nullable=False, default=1)
    likelihood = Column(Integer, nullable=False, default=50)
    impact = Column(Integer, nullable=False, default=50)
    prerequisites = Column(Text, nullable=True)
    tools_required = Column(Text, nullable=True)
    execution_steps = Column(Text, nullable=True)
    post_exploitation = Column(Text, nullable=True)
    confidence_score = Column(Integer, nullable=False, default=80)
    status = Column(String(20), nullable=False, default="PENDING_APPROVAL")
    approved_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    vulnerability = relationship("Vulnerability", back_populates="recommendations")
