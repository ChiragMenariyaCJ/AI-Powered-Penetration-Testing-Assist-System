"""Register and export every SQLAlchemy model used by PTAS.

SQLAlchemy relationships in this project use string class names such as
``relationship("Target")``. Importing this package loads every mapped class into
the shared declarative registry before a query asks SQLAlchemy to resolve those
relationships. Both the API process and standalone terminal process must import
this package during startup.
"""

from Backend.models.project_model import Project
from Backend.models.recommendation_model import Recommendation
from Backend.models.report_model import Report
from Backend.models.scan_model import Scan
from Backend.models.scope_validation_model import ScopeValidation
from Backend.models.target_model import Target
from Backend.models.user_model import User
from Backend.models.vulnerability_model import Vulnerability


__all__ = (
    "Project",
    "Recommendation",
    "Report",
    "Scan",
    "ScopeValidation",
    "Target",
    "User",
    "Vulnerability",
)
