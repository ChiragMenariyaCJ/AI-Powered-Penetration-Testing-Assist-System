"""Request optional local-model advice from Ollama with safety checks."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from Backend.terminal_assistant.models import AnalysisResult
from Backend.terminal_assistant.safety import (
    filter_safe_recommendations,
    is_safe_recommendation,
    is_safe_manual_command,
    manual_command_rejection_reason,
)


class AdvisorError(RuntimeError):
    """Represent or coordinate AdvisorError in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """
    pass


class OllamaAdvisor:
    """Represent or coordinate OllamaAdvisor in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        allow_remote: bool = False,
        timeout: int = 90,
    ):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        if not model:
            raise ValueError("An Ollama model name is required")
        self.model = model
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")
        self.timeout = timeout
        # The dashboard reads this after a rejected response so it can explain
        # why it is switching to its deterministic evidence-based queue.
        self.last_rejection_reason: str | None = None

        hostname = (urlparse(self.base_url).hostname or "").lower()
        local_hosts = {"127.0.0.1", "::1", "localhost"}
        if hostname not in local_hosts and not allow_remote:
            raise ValueError(
                "Refusing to send terminal data to a remote model. "
                "Use --allow-remote-llm only after reviewing the privacy impact."
            )

    def advise(self, result: AnalysisResult, excerpt: str) -> list[str]:
        """Perform the advise step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
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
        """Perform the advise prompt step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        response_text = self.complete(prompt)
        suggestions = self._parse_suggestions(response_text, limit=limit * 2)
        return filter_safe_recommendations(suggestions, authorized_targets, limit)

    def complete(self, prompt: str, json_mode: bool = False) -> str:
        """Perform the complete step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        request_body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # A low temperature improves structured-command consistency on the
            # small local model installed by the Kali setup script.
            "options": {"temperature": 0},
        }
        if json_mode:
            request_body["format"] = "json"
        payload = json.dumps(request_body).encode("utf-8")
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

    def ensure_model_available(self, timeout: int = 3) -> None:
        """Verify that the local Ollama server has the configured model.

        Configuration alone does not mean model-backed recommendations are
        usable. This inexpensive startup check gives the student an immediate,
        specific fallback message instead of waiting for the first generation
        request to time out.
        """

        request = Request(f"{self.base_url}/api/tags", method="GET")
        try:
            with urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AdvisorError(f"Ollama is unavailable at {self.base_url}: {exc}") from exc

        installed = {
            str(model.get("name") or model.get("model") or "")
            for model in body.get("models", [])
            if isinstance(model, dict)
        }
        if self.model not in installed:
            raise AdvisorError(
                f"Ollama model '{self.model}' is not installed; run: "
                f"ollama pull {self.model}"
            )

    def advise_next_command(
        self,
        result: AnalysisResult,
        excerpt: str,
        completed_commands: set[str] | None = None,
        lab_access_command: str | None = None,
    ) -> dict[str, str] | None:
        """Generate one new command from completed, in-scope terminal evidence.

        The local model's JSON is never trusted directly. PTAS verifies that the
        command uses one allowlisted metadata tool and explicitly targets only
        the authorized host before returning it to the dashboard.
        """

        self.last_rejection_reason = None
        if result.scope_allowed is not True:
            self.last_rejection_reason = "the completed command was not verified as in scope"
            return None
        if not result.targets:
            self.last_rejection_reason = "no authorized target was parsed from the command"
            return None
        normalized_completed = {
            " ".join(item.split()) for item in (completed_commands or set())
        }
        base_prompt = self._next_command_prompt(
            result,
            excerpt,
            completed_commands or set(),
            lab_access_command,
        )
        prompt = base_prompt
        # Small local models occasionally copy the JSON template or mismatch a
        # service script and port. One correction request substantially improves
        # reliability while every response still goes through the same guards.
        for attempt in range(2):
            payload = self._parse_json_object(self.complete(prompt, json_mode=True))
            rejection_reason: str | None = None
            if not payload:
                rejection_reason = "the model response was not one JSON object"
                purpose = ""
                command = ""
            else:
                purpose = " ".join(str(payload.get("purpose", "")).split())
                command = " ".join(str(payload.get("command", "")).split())
                if not purpose:
                    rejection_reason = "the model response did not include a purpose"
                elif purpose.lower() == "short evidence-based reason":
                    rejection_reason = "the model copied the example purpose placeholder"
                elif (
                    lab_access_command
                    and command == " ".join(lab_access_command.split())
                ):
                    # The exact command supplied by the verified lab context
                    # only opens PTAS's separate identity/confirmation gate.
                    rejection_reason = None
                else:
                    rejection_reason = manual_command_rejection_reason(
                        command,
                        result.targets,
                    )
                if not rejection_reason and command in normalized_completed:
                    rejection_reason = (
                        "the model repeated a command that was already completed"
                    )
                # Prefix the prose for classification so natural first words
                # such as "Inspect" are not mistaken for executable names.
                if not rejection_reason and not is_safe_recommendation(
                    f"Review {purpose}",
                    result.targets,
                ):
                    rejection_reason = "the model purpose did not pass the safety policy"
            if not rejection_reason:
                self.last_rejection_reason = None
                return {"purpose": purpose, "command": command, "source": "ollama"}
            self.last_rejection_reason = rejection_reason
            if attempt == 0:
                prompt = (
                    base_prompt
                    + "\nYour previous response was rejected because "
                    + rejection_reason
                    + ". Return a corrected JSON object that follows every rule."
                )
        return None

    def advise_commands(
        self,
        prompt: str,
        authorized_targets: list[str],
        limit: int = 5,
    ) -> list[dict[str, str]]:
        """Generate and validate structured commands from scan evidence."""

        response_text = self.complete(prompt, json_mode=True)
        start = response_text.find("[")
        end = response_text.rfind("]")
        if start < 0 or end <= start:
            return []
        try:
            payload = json.loads(response_text[start : end + 1])
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []

        recommendations: list[dict[str, str]] = []
        seen_commands: set[str] = set()
        for item in payload:
            if not isinstance(item, dict):
                continue
            purpose = " ".join(str(item.get("purpose", "")).split())
            command = " ".join(str(item.get("command", "")).split())
            if (
                not purpose
                or command in seen_commands
                or not is_safe_manual_command(command, authorized_targets)
                or not is_safe_recommendation(f"Review {purpose}", authorized_targets)
            ):
                continue
            recommendations.append(
                {"purpose": purpose, "command": command, "source": "ollama"}
            )
            seen_commands.add(command)
            if len(recommendations) >= limit:
                break
        return recommendations

    @staticmethod
    def _parse_json_object(response_text: str) -> dict | None:
        """Extract the first JSON object from a model response."""

        start = response_text.find("{")
        end = response_text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(response_text[start : end + 1])
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _next_command_prompt(
        result: AnalysisResult,
        excerpt: str,
        completed_commands: set[str],
        lab_access_command: str | None = None,
    ) -> str:
        """Build the strict structured prompt for an adaptive next command."""

        findings = "\n".join(
            f"- {finding.summary}: {finding.evidence}"
            for finding in result.findings
        ) or "- No structured findings were parsed"
        completed = "\n".join(f"- {item}" for item in sorted(completed_commands))
        lab_transition = (
            "\nThis exact target is a registered and runtime-verified "
            "Metasploitable 2 training VM. If useful evidence-only checks are "
            "exhausted, do not return an empty command. Recommend this exact "
            "PTAS command, which opens a separate identity and confirmation "
            f"gate without automatically accessing the VM: {lab_access_command}\n"
            if lab_access_command
            else ""
        )
        return f"""You are a classroom security assessment coach operating only on an explicitly authorized target.
Analyze the completed command and its real terminal output. Recommend exactly one useful next evidence-collection command that moves the assessment forward. Use a command appropriate for the observed service and port. Examples of the required matching are: ftp-syst for FTP ports, http-title/http-headers for HTTP ports, ssh scripts for SSH port 22, SMB scripts for ports 139/445, and telnet-encryption for Telnet port 23. Do not repeat a completed command or merely add an unrelated script to it. Use one of these non-destructive tools only: curl, dig, enum4linux-ng, nmap, pg_isready, sslscan, whatweb. For Nmap --script, use only: banner, dns-nsid, ftp-syst, http-headers, http-title, mysql-info, nbstat, smb-protocols, smb-security-mode, smb2-capabilities, smb2-time, smtp-commands, ssh-hostkey, ssh2-enum-algos, ssl-cert, ssl-enum-ciphers, telnet-encryption. The command must explicitly contain one of the authorized targets. Do not use shell operators, credential attempts, access/login testing, vulnerability exploitation, destructive actions, evasion, stress, or persistence.
{lab_transition}

Return exactly one JSON object and no Markdown:
{{"purpose":"short evidence-based reason", "command":"complete command to run manually"}}
If no useful safe command follows from the evidence, return:
{{"purpose":"Assessment has no additional safe validation step", "command":""}}

Authorized targets: {', '.join(result.targets)}
Completed command: {result.command or 'unknown'}
Previously completed commands:
{completed or '- None'}
Parsed findings:
{findings}
Sanitized completed terminal output:
{excerpt[-5000:]}
"""

    @staticmethod
    def _parse_suggestions(response_text: str, limit: int = 5) -> list[str]:
        """Perform the parse suggestions step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
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
        """Perform the prompt step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
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
