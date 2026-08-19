import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from Backend.terminal_assistant.models import AnalysisResult
from Backend.terminal_assistant.safety import filter_safe_recommendations


class AdvisorError(RuntimeError):
    pass


class OllamaAdvisor:
    """Optional local-model advisor. Terminal content stays local by default."""

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        allow_remote: bool = False,
        timeout: int = 20,
    ):
        if not model:
            raise ValueError("An Ollama model name is required")
        self.model = model
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")
        self.timeout = timeout

        hostname = (urlparse(self.base_url).hostname or "").lower()
        local_hosts = {"127.0.0.1", "::1", "localhost"}
        if hostname not in local_hosts and not allow_remote:
            raise ValueError(
                "Refusing to send terminal data to a remote model. "
                "Use --allow-remote-llm only after reviewing the privacy impact."
            )

    def advise(self, result: AnalysisResult, excerpt: str) -> list[str]:
        if result.scope_allowed is False:
            return []

        prompt = self._prompt(result, excerpt)
        return self.advise_prompt(prompt, result.targets)

    def advise_prompt(
        self,
        prompt: str,
        authorized_targets: list[str] | None = None,
        limit: int = 5,
    ) -> list[str]:
        response_text = self.complete(prompt)
        suggestions = self._parse_suggestions(response_text, limit=limit * 2)
        return filter_safe_recommendations(suggestions, authorized_targets, limit)

    def complete(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            }
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AdvisorError(f"Ollama request failed: {exc}") from exc

        return str(body.get("response", "")).strip()

    @staticmethod
    def _parse_suggestions(response_text: str, limit: int = 5) -> list[str]:
        suggestions: list[str] = []
        for line in response_text.splitlines():
            cleaned = line.strip().lstrip("-*•0123456789. ").strip()
            if cleaned and cleaned not in suggestions:
                suggestions.append(cleaned)
            if len(suggestions) == limit:
                break
        return suggestions

    @staticmethod
    def _prompt(result: AnalysisResult, excerpt: str) -> str:
        findings = "\n".join(
            f"- {finding.summary}: {finding.evidence}"
            for finding in result.findings
        ) or "- No structured findings yet"
        return f"""You are a real-time penetration-testing coach working only on an explicitly authorized classroom target.
Give at most five concise next-step suggestions based on the current evidence. Prefer evidence collection, configuration review, and non-destructive validation. Do not suggest credential guessing, destructive actions, evasion, service stress, automatic access, or access chaining. Never claim that a vulnerability exists solely because a port is open.
If the next useful teaching step would require access, say only: STOP: use the gated access-test command and wait for instructor confirmation.

Tool: {result.tool or 'unknown'}
Command: {result.command or 'not captured'}
Authorized targets: {', '.join(result.targets) or 'not identified'}
Findings:
{findings}

Sanitized terminal excerpt:
{excerpt[-5000:]}
"""
