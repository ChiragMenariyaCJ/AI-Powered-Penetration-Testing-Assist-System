"""Data objects shared by terminal analysis and rendering."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json


@dataclass(frozen=True)
class Finding:
    """Represent or coordinate Finding in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """
    kind: str
    summary: str
    evidence: str
    severity: str = "INFO"


@dataclass
class AnalysisResult:
    """Represent or coordinate AnalysisResult in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """
    command: str | None
    tool: str | None
    targets: list[str] = field(default_factory=list)
    scope_allowed: bool | None = None
    blocked_targets: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Perform the to dict step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        return asdict(self)

    def fingerprint(self) -> str:
        """Perform the fingerprint step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        stable_data = {
            "command": self.command,
            "targets": self.targets,
            "scope_allowed": self.scope_allowed,
            "findings": [asdict(finding) for finding in self.findings],
            "suggestions": self.suggestions,
        }
        payload = json.dumps(stable_data, sort_keys=True).encode("utf-8")
        return sha256(payload).hexdigest()
