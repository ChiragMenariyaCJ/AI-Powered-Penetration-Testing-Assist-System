
# This file connects PTAS to local Ollama.
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


# Keep scan recommendations small enough for the local model to return valid JSON.
COMMAND_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "recommendations": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "purpose": {"type": "string", "maxLength": 180},
                    "command": {"type": "string", "maxLength": 240},
                },
                "required": ["purpose", "command"],
            },
        }
    },
    "required": ["recommendations"],
}


# Build a strict response shape for recommendations tied to stored findings.
def _finding_command_response_schema(finding_ids: list[int]) -> dict:
    return {
        "type": "object",
        "properties": {
            "recommendations": {
                "type": "array",
                "minItems": len(finding_ids),
                "maxItems": len(finding_ids),
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "integer",
                            "enum": finding_ids,
                        },
                        "purpose": {"type": "string", "maxLength": 180},
                        "command": {"type": "string", "maxLength": 240},
                    },
                    "required": ["finding_id", "purpose", "command"],
                },
            }
        },
        "required": ["recommendations"],
    }


# Handle the advisor error.
class AdvisorError(RuntimeError):
    pass


# This class sends safe requests to Ollama.
class OllamaAdvisor:

    # Set up this object.
    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        allow_remote: bool = False,
        timeout: int | None = None,
    ):
        if not model:
            raise ValueError("An Ollama model name is required")
        self.model = model
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")
        self.timeout = timeout or int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "300"))
        # The dashboard reads this to explain why model output was rejected.
        self.last_rejection_reason: str | None = None

        hostname = (urlparse(self.base_url).hostname or "").lower()
        local_hosts = {"127.0.0.1", "::1", "localhost"}
        if hostname not in local_hosts and not allow_remote:
            raise ValueError(
                "Refusing to send terminal data to a remote model. "
                "Use --allow-remote-llm only after reviewing the privacy impact."
            )

    # Ask Ollama for advice.
    def advise(self, result: AnalysisResult, excerpt: str) -> list[str]:
        if result.scope_allowed is False:
            return []

        prompt = self._prompt(result, excerpt)
        return self.advise_prompt(prompt, result.targets)

    # Ask Ollama to review a prompt.
    def advise_prompt(
        self,
        prompt: str,
        authorized_targets: list[str] | None = None,
        limit: int = 5,
    ) -> list[str]:
        response_text = self.complete(prompt)
        suggestions = self._parse_suggestions(response_text, limit=limit * 2)
        return filter_safe_recommendations(suggestions, authorized_targets, limit)

    # Send one request to Ollama.
    def complete(
        self,
        prompt: str,
        json_mode: bool = False,
        json_schema: dict | None = None,
    ) -> str:
        request_body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # Keep the local model response short and consistent.
            "options": {"temperature": 0, "num_predict": 512},
            "keep_alive": "10m",
        }
        if json_schema is not None:
            request_body["format"] = json_schema
        elif json_mode:
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

    # Check that the Ollama model is available.
    def ensure_model_available(self, timeout: int = 3) -> None:

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

    # Ask Ollama for one safe next command.
    def advise_next_command(
        self,
        result: AnalysisResult,
        excerpt: str,
        completed_commands: set[str] | None = None,
        lab_access_command: str | None = None,
    ) -> dict[str, str] | None:

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
        # Small local models occasionally copy the JSON template or mismatch a service script and port.
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
                    # This command only opens the separate access approval gate.
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
                # Add a text prefix so normal prose is not treated as a command.
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

    # Ask Ollama for safe commands based on scan evidence.
    def advise_commands(
        self,
        prompt: str,
        authorized_targets: list[str],
        limit: int = 5,
    ) -> list[dict[str, str]]:

        response_text = self.complete(prompt, json_schema=COMMAND_RESPONSE_SCHEMA)
        try:
            payload = self._load_json(response_text)
        except json.JSONDecodeError:
            correction = (
                prompt
                + "\nYour last response was incomplete. Return exactly one short "
                "recommendation. The command must be under 120 characters and use "
                "only scripts from the supplied allowlist."
            )
            response_text = self.complete(
                correction,
                json_schema=COMMAND_RESPONSE_SCHEMA,
            )
            try:
                payload = self._load_json(response_text)
            except json.JSONDecodeError:
                self.last_rejection_reason = "the model response was not valid JSON"
                return []
        items = self._command_items(payload)
        if not items:
            self.last_rejection_reason = "the model response did not contain recommendation items"
            return []

        recommendations, rejected = self._validate_command_items(
            items,
            authorized_targets,
            limit,
        )
        if not recommendations and rejected:
            correction = (
                prompt
                + "\nYour last recommendations were rejected because: "
                + "; ".join(dict.fromkeys(rejected))
                + ". Return exactly one different, short command that follows "
                "the tool, script, service-port, target and safety rules."
            )
            try:
                corrected_payload = self._load_json(
                    self.complete(correction, json_schema=COMMAND_RESPONSE_SCHEMA)
                )
            except json.JSONDecodeError:
                corrected_payload = {}
            recommendations, second_rejected = self._validate_command_items(
                self._command_items(corrected_payload),
                authorized_targets,
                limit,
            )
            rejected.extend(second_rejected)
        self.last_rejection_reason = (
            None
            if recommendations
            else "; ".join(dict.fromkeys(rejected)) or "the model returned no usable command"
        )
        return recommendations

    # Ask Ollama for one recommendation for each stored finding in a small batch.
    def advise_finding_commands(
        self,
        prompt: str,
        authorized_targets: list[str],
        finding_ids: list[int],
    ) -> list[dict]:
        self.last_rejection_reason = None
        requested_ids = list(dict.fromkeys(int(value) for value in finding_ids))
        if not requested_ids:
            return []
        schema = _finding_command_response_schema(requested_ids)
        response_text = self.complete(prompt, json_schema=schema)
        try:
            payload = self._load_json(response_text)
        except json.JSONDecodeError:
            correction = (
                prompt
                + "\nThe last response was invalid JSON. Return the required JSON "
                "object with exactly one item for every requested finding ID."
            )
            try:
                payload = self._load_json(
                    self.complete(correction, json_schema=schema)
                )
            except json.JSONDecodeError:
                self.last_rejection_reason = "the model response was not valid JSON"
                return []

        recommendations, rejected = self._validate_finding_command_items(
            self._command_items(payload),
            authorized_targets,
            requested_ids,
        )
        returned_ids = {item["finding_id"] for item in recommendations}
        missing_ids = [value for value in requested_ids if value not in returned_ids]
        if missing_ids:
            retry_schema = _finding_command_response_schema(missing_ids)
            correction = (
                prompt
                + "\nThe previous response was incomplete or unsafe. Return corrected "
                f"items only for these missing finding IDs: {missing_ids}."
            )
            try:
                corrected_payload = self._load_json(
                    self.complete(correction, json_schema=retry_schema)
                )
            except json.JSONDecodeError:
                corrected_payload = {}
            corrected, second_rejected = self._validate_finding_command_items(
                self._command_items(corrected_payload),
                authorized_targets,
                missing_ids,
            )
            recommendations.extend(corrected)
            rejected.extend(second_rejected)

        final_ids = {item["finding_id"] for item in recommendations}
        still_missing = [value for value in requested_ids if value not in final_ids]
        self.last_rejection_reason = (
            None
            if not still_missing
            else "; ".join(dict.fromkeys(rejected))
            or f"no usable recommendation was returned for finding IDs {still_missing}"
        )
        return recommendations

    # Check finding IDs, scope and safety before model output reaches the database.
    @staticmethod
    def _validate_finding_command_items(
        items: list[dict],
        authorized_targets: list[str],
        requested_ids: list[int],
    ) -> tuple[list[dict], list[str]]:
        recommendations: list[dict] = []
        requested = set(requested_ids)
        seen_ids: set[int] = set()
        rejected: list[str] = []
        for item in items:
            try:
                finding_id = int(item.get("finding_id"))
            except (TypeError, ValueError):
                rejected.append("the model did not return a valid finding ID")
                continue
            purpose = " ".join(str(item.get("purpose", "")).split())
            command = " ".join(str(item.get("command", "")).split())
            reason = manual_command_rejection_reason(command, authorized_targets)
            if finding_id not in requested:
                reason = f"finding ID {finding_id} was not requested"
            elif finding_id in seen_ids:
                reason = f"finding ID {finding_id} was repeated"
            elif not purpose:
                reason = f"finding ID {finding_id} had no purpose"
            elif not is_safe_recommendation(f"Review {purpose}", authorized_targets):
                reason = f"finding ID {finding_id} had an unsafe purpose"
            if reason:
                rejected.append(reason)
                continue
            recommendations.append(
                {
                    "finding_id": finding_id,
                    "purpose": purpose,
                    "command": command,
                    "source": "ollama",
                }
            )
            seen_ids.add(finding_id)
        return recommendations, rejected

    # Apply scope and safety checks to Ollama command items.
    @staticmethod
    def _validate_command_items(
        items: list[dict],
        authorized_targets: list[str],
        limit: int,
    ) -> tuple[list[dict[str, str]], list[str]]:
        recommendations: list[dict[str, str]] = []
        seen_commands: set[str] = set()
        rejected: list[str] = []
        for item in items:
            purpose = " ".join(str(item.get("purpose", "")).split())
            command = " ".join(str(item.get("command", "")).split())
            reason = manual_command_rejection_reason(command, authorized_targets)
            if not purpose:
                reason = "the model response did not include a purpose"
            elif command in seen_commands:
                reason = "the model repeated a command"
            elif not is_safe_recommendation(f"Review {purpose}", authorized_targets):
                reason = "the recommendation purpose failed the safety check"
            if reason:
                rejected.append(reason)
                continue
            recommendations.append(
                {"purpose": purpose, "command": command, "source": "ollama"}
            )
            seen_commands.add(command)
            if len(recommendations) >= limit:
                break
        return recommendations, rejected

    # Read a JSON response with or without a Markdown code fence.
    @staticmethod
    def _load_json(response_text: str):
        value = response_text.strip()
        if value.startswith("```"):
            value = value.split("\n", 1)[1] if "\n" in value else ""
        if value.endswith("```"):
            value = value[:-3].rstrip()
        return json.loads(value)

    # Read recommendation items from the JSON shapes returned by small local models.
    @staticmethod
    def _command_items(payload) -> list[dict]:
        items: list[dict] = []

        def collect(value) -> None:
            if isinstance(value, list):
                for entry in value:
                    collect(entry)
            elif isinstance(value, dict):
                if "purpose" in value or "command" in value:
                    items.append(value)
                else:
                    for entry in value.values():
                        collect(entry)

        collect(payload)
        return items

    # Read JSON object.
    @staticmethod
    def _parse_json_object(response_text: str) -> dict | None:

        start = response_text.find("{")
        end = response_text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            parsed = json.loads(response_text[start : end + 1])
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    # Build the prompt for the next command.
    @staticmethod
    def _next_command_prompt(
        result: AnalysisResult,
        excerpt: str,
        completed_commands: set[str],
        lab_access_command: str | None = None,
    ) -> str:

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

    # Read suggestions.
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

    # Build the prompt sent to Ollama.
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
