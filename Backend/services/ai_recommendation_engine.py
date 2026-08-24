"""Generate deterministic recommendations from vulnerability evidence."""

from __future__ import annotations

import os

from Backend.terminal_assistant.advisor import AdvisorError, OllamaAdvisor
from Backend.terminal_assistant.safety import filter_safe_recommendations


class AIRecommendationEngine:

    MITRE_TECHNIQUES = {
        "Discovery": {
            "T1046": {"name": "Network Service Discovery", "risk": "LOW"},
        }
    }

    CRITICAL_SERVICES = {
        "SMB": "HIGH",
        "MYSQL": "HIGH",
        "POSTGRESQL": "HIGH",
        "SSH": "MEDIUM",
        "HTTP": "MEDIUM",
        "HTTPS": "MEDIUM",
    }

    # Store the vulnerability repository and optional advisor used to build recommendations.
    def __init__(self, advisor: OllamaAdvisor | None = None):
        self.advisor = advisor or self._advisor_from_environment()

    # Combine vulnerability evidence, model suggestions, and fallback scoring into stored advice.
    def generate_recommendations(self, vulnerability: dict) -> list[dict]:
        host = vulnerability.get("host") or "the authorized target"
        port = vulnerability.get("port")
        service = vulnerability.get("service") or "unknown"
        severity = (vulnerability.get("severity") or "MEDIUM").upper()
        suggestions = self._model_suggestions(vulnerability)
        if not suggestions:
            suggestions = [self._fallback_suggestion(vulnerability)]

        return [
            self._format_recommendation(suggestion, host, port, service, severity)
            for suggestion in suggestions
        ]

    # Ask the configured advisor for suggestions and return an empty list when no model is enabled.
    def _model_suggestions(self, vulnerability: dict) -> list[str]:
        if not self.advisor:
            return []
        host = vulnerability.get("host") or ""
        target_scope = [host] if host else None
        try:
            return self.advisor.advise_prompt(
                self._prompt(vulnerability),
                authorized_targets=target_scope,
                limit=3,
            )
        except AdvisorError:
            return []

    # Build the bounded evidence prompt supplied to the recommendation model.
    @staticmethod
    def _prompt(vulnerability: dict) -> str:
        return f"""You are a real-time classroom penetration-testing coach.
Use only the evidence below. Return up to three concise next-step recommendations, one per line. Keep them scoped to the authorized target. Prefer evidence collection, configuration review, and non-destructive validation. Do not suggest credential guessing, destructive actions, evasion, service stress, automatic access, or access chaining.
If the next useful teaching step would require access, say only: STOP: use the gated access-test command and wait for instructor confirmation.

Current evidence:
- Host: {vulnerability.get("host") or "unknown"}
- Port: {vulnerability.get("port") or "unknown"}
- Service: {vulnerability.get("service") or "unknown"}
- Severity: {vulnerability.get("severity") or "unknown"}
- Type: {vulnerability.get("vulnerability_type") or "unknown"}
- Description: {vulnerability.get("description") or "unknown"}
"""

    # Create deterministic evidence-based guidance when the model returns no usable suggestion.
    @staticmethod
    def _fallback_suggestion(vulnerability: dict) -> str:
        host = vulnerability.get("host") or "the authorized target"
        port = vulnerability.get("port")
        service = vulnerability.get("service") or "unknown service"
        endpoint = f"{host}:{port}" if port else host
        return (
            f"Review the current evidence for {service} on {endpoint}, collect "
            "non-destructive configuration details, document the result, and stop "
            "before any access activity."
        )

    # Normalise one suggestion into the database fields required by the recommendation model.
    def _format_recommendation(
        self,
        suggestion: str,
        host: str,
        port: int | None,
        service: str,
        severity: str,
    ) -> dict:
        safe = filter_safe_recommendations([suggestion], [host] if host else None, 1)
        step = safe[0] if safe else self._fallback_suggestion(
            {"host": host, "port": port, "service": service}
        )
        return {
            "attack_technique": "Realtime guided validation",
            "mitre_technique_id": "T1046",
            "exploitation_method": step,
            "risk_level": self._calculate_risk_level(severity),
            "priority": self._calculate_priority(severity, port or 0),
            "likelihood": self._calculate_likelihood(severity),
            "impact": self._calculate_impact(severity),
            "prerequisites": (
                "Explicit authorization, in-scope target, and operator approval "
                "before any suggested step is run manually"
            ),
            "tools_required": "realtime-advisor",
            "execution_steps": step,
            "post_exploitation": (
                "Not applicable. Stop after validation and keep the activity inside "
                "the registered lab boundary."
            ),
            "confidence_score": self._calculate_confidence(severity),
        }

    # Create the optional local Ollama advisor from environment configuration.
    @staticmethod
    def _advisor_from_environment() -> OllamaAdvisor | None:
        provider = os.getenv("PTAS_LLM_PROVIDER", "rules").lower()
        if provider != "ollama":
            return None
        model = os.getenv("PTAS_LLM_MODEL") or os.getenv("OLLAMA_MODEL")
        if not model:
            return None
        allow_remote = os.getenv("PTAS_ALLOW_REMOTE_LLM", "").lower() in {"1", "true", "yes"}
        return OllamaAdvisor(
            model=model,
            base_url=os.getenv("OLLAMA_BASE_URL"),
            allow_remote=allow_remote,
        )

    # Map severity and exploitability evidence to the displayed recommendation risk level.
    def _calculate_risk_level(self, severity: str) -> str:
        return {
            "CRITICAL": "MEDIUM",
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "LOW",
            "INFO": "LOW",
        }.get(severity, "LOW")

    # Convert risk and confidence evidence into a sortable recommendation priority.
    def _calculate_priority(self, severity: str, port: int) -> int:
        priority = {
            "CRITICAL": 6,
            "HIGH": 5,
            "MEDIUM": 4,
            "LOW": 3,
            "INFO": 2,
        }.get(severity, 3)
        if port:
            priority += 1
        return min(priority, 7)

    # Estimate how likely the candidate issue is from its severity and evidence quality.
    def _calculate_likelihood(self, severity: str) -> int:
        return {
            "CRITICAL": 70,
            "HIGH": 60,
            "MEDIUM": 50,
            "LOW": 40,
            "INFO": 30,
        }.get(severity, 40)

    # Estimate potential impact from the stored vulnerability severity.
    def _calculate_impact(self, severity: str) -> int:
        return {
            "CRITICAL": 60,
            "HIGH": 50,
            "MEDIUM": 35,
            "LOW": 20,
            "INFO": 10,
        }.get(severity, 20)

    # Calculate confidence from the amount and quality of observed scan evidence.
    def _calculate_confidence(self, severity: str) -> int:
        return {
            "CRITICAL": 90,
            "HIGH": 85,
            "MEDIUM": 75,
            "LOW": 65,
            "INFO": 55,
        }.get(severity, 70)

    # Return the combined likelihood, impact, confidence, and priority score for one finding.
    def calculate_attack_score(self, vulnerability: dict) -> dict:
        severity = (vulnerability.get("severity") or "MEDIUM").upper()
        service = (vulnerability.get("service") or "UNKNOWN").upper()
        risk_score = {
            "CRITICAL": 60,
            "HIGH": 50,
            "MEDIUM": 35,
            "LOW": 20,
            "INFO": 10,
        }.get(severity, 20)
        if service.upper() in self.CRITICAL_SERVICES:
            risk_score = min(70, risk_score + 10)
        return {
            "risk_score": risk_score,
            "attack_complexity": "LOW",
            "required_privileges": "NONE",
            "success_probability": self._calculate_likelihood(severity),
        }
