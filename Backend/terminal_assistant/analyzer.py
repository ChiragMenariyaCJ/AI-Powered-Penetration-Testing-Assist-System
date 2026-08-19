import re
import shlex

from Backend.terminal_assistant.models import AnalysisResult, Finding
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.scope_guard import ScopeGuard


SUPPORTED_TOOLS = {
    "curl",
    "dirsearch",
    "ffuf",
    "gobuster",
    "masscan",
    "nikto",
    "nmap",
    "sqlmap",
    "whatweb",
    "wget",
}

PROMPT_COMMAND = re.compile(
    r"(?m)^.*?(?:\$|#|❯|>)\s*"
    r"(?P<command>(?:sudo\s+)?(?:nmap|masscan|nikto|gobuster|ffuf|whatweb|"
    r"curl|wget|sqlmap|dirsearch)\b[^\r\n]*)$",
    re.IGNORECASE,
)
DIRECT_COMMAND = re.compile(
    r"^\s*(?P<command>(?:sudo\s+)?(?:nmap|masscan|nikto|gobuster|ffuf|whatweb|"
    r"curl|wget|sqlmap|dirsearch)\b[^\r\n]*)\s*$",
    re.IGNORECASE,
)
NMAP_PORT = re.compile(
    r"(?m)^(?P<port>\d{1,5})/(?P<protocol>tcp|udp)\s+"
    r"(?P<state>open(?:\|filtered)?)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>[^\r\n]+))?"
)
WEB_PATH = re.compile(
    r"(?m)^(?P<path>/\S*?)\s+(?:\(Status:\s*|\[Status:\s*)"
    r"(?P<status>\d{3})"
)
HTTP_STATUS = re.compile(r"(?m)^HTTP/\d(?:\.\d)?\s+(?P<status>\d{3})\b")


class TerminalAnalyzer:
    """Convert sanitized terminal output into scoped, read-only suggestions."""

    def __init__(self, scope_guard: ScopeGuard):
        self.scope_guard = scope_guard

    @staticmethod
    def extract_latest_command(text: str) -> str | None:
        matches = list(PROMPT_COMMAND.finditer(text))
        if matches:
            return matches[-1].group("command").strip()

        for line in reversed(text.splitlines()):
            direct_match = DIRECT_COMMAND.match(line)
            if direct_match:
                return direct_match.group("command").strip()
        return None

    @staticmethod
    def extract_latest_prompt_command(text: str) -> str | None:
        """Return only a command visibly entered at a shell prompt.

        Pane monitoring uses this stricter form so commands printed in PTAS
        recommendations are not mistaken for commands executed by the student.
        """
        matches = list(PROMPT_COMMAND.finditer(text))
        return matches[-1].group("command").strip() if matches else None

    @staticmethod
    def command_tool(command: str | None) -> str | None:
        if not command:
            return None
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        if parts and parts[0].lower() == "sudo":
            parts = parts[1:]
        if not parts:
            return None
        tool = parts[0].rsplit("/", 1)[-1].lower()
        return tool if tool in SUPPORTED_TOOLS else None

    def analyze(
        self,
        text: str,
        context_command: str | None = None,
        explicit_targets: list[str] | None = None,
    ) -> AnalysisResult:
        clean_text = sanitize_terminal_text(text)
        command = self.extract_latest_command(clean_text) or context_command
        tool = self.command_tool(command)
        targets = ScopeGuard.extract_targets(command or "")
        for target in explicit_targets or []:
            normalized = target.strip()
            if normalized and normalized not in targets:
                targets.append(normalized)

        if targets:
            scope_decision = self.scope_guard.check(targets)
            scope_allowed: bool | None = scope_decision.allowed
            blocked_targets = scope_decision.blocked_targets
        else:
            scope_allowed = None
            blocked_targets = []

        result = AnalysisResult(
            command=command,
            tool=tool,
            targets=targets,
            scope_allowed=scope_allowed,
            blocked_targets=blocked_targets,
        )

        if scope_allowed is False:
            result.findings.append(
                Finding(
                    kind="scope",
                    severity="BLOCKED",
                    summary="Observed target is outside the authorized scope",
                    evidence=", ".join(blocked_targets),
                )
            )
            result.suggestions.append(
                "Stop and confirm written authorization before interacting with the blocked target."
            )
            return result

        if scope_allowed is None:
            result.findings.append(
                Finding(
                    kind="scope",
                    severity="WARNING",
                    summary="The command target could not be verified",
                    evidence="Supply --target or use a command containing an IP, CIDR, domain, or URL",
                )
            )
            result.suggestions.append(
                "Confirm the target is inside the declared scope before continuing."
            )
            return result

        self._collect_findings(clean_text, result)
        self._build_suggestions(clean_text, result)
        return result

    def _collect_findings(self, text: str, result: AnalysisResult) -> None:
        for match in NMAP_PORT.finditer(text):
            port = int(match.group("port"))
            if not 0 < port <= 65535:
                continue
            protocol = match.group("protocol")
            service = match.group("service")
            version = (match.group("version") or "").strip()
            evidence = f"{port}/{protocol} {service}"
            if version:
                evidence = f"{evidence} {version}"
            result.findings.append(
                Finding(
                    kind="open_port",
                    summary=f"Open {service} service on {port}/{protocol}",
                    evidence=evidence,
                )
            )

        for match in WEB_PATH.finditer(text):
            status_code = int(match.group("status"))
            if status_code in {200, 204, 301, 302, 307, 308, 401, 403}:
                result.findings.append(
                    Finding(
                        kind="web_path",
                        summary=f"Web path returned HTTP {status_code}",
                        evidence=match.group("path"),
                        severity="LOW",
                    )
                )

        for match in HTTP_STATUS.finditer(text):
            result.findings.append(
                Finding(
                    kind="http_status",
                    summary=f"HTTP endpoint returned {match.group('status')}",
                    evidence=match.group(0),
                )
            )

        lowered = text.lower()
        error_patterns = {
            "command not found": "A requested tool is not installed or is not on PATH",
            "permission denied": "The command encountered a permission error",
            "host seems down": "The target did not respond to host discovery",
            "no route to host": "The target is unreachable from this network path",
            "connection refused": "The remote endpoint refused the connection",
        }
        for pattern, summary in error_patterns.items():
            if pattern in lowered:
                result.findings.append(
                    Finding(
                        kind="runtime_error",
                        summary=summary,
                        evidence=pattern,
                        severity="LOW",
                    )
                )

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        if value not in items:
            items.append(value)

    def _build_suggestions(self, text: str, result: AnalysisResult) -> None:
        services = {
            finding.evidence.lower()
            for finding in result.findings
            if finding.kind == "open_port"
        }

        if any("http" in service for service in services):
            self._append_unique(
                result.suggestions,
                "Review HTTP headers, redirects, authentication boundaries, and exposed routes.",
            )
        if any("ssh" in service for service in services):
            self._append_unique(
                result.suggestions,
                "Verify the SSH version and configuration against the assessment baseline; avoid credential attacks unless separately approved.",
            )
        if any(
            marker in service
            for service in services
            for marker in ("microsoft-ds", "netbios", "smb")
        ):
            self._append_unique(
                result.suggestions,
                "Confirm SMB dialect, signing requirements, and authorized share exposure.",
            )
        if any(
            marker in service
            for service in services
            for marker in ("mysql", "postgres", "redis", "mongodb")
        ):
            self._append_unique(
                result.suggestions,
                "Confirm whether the data service should be network-exposed and test authentication only with approved credentials.",
            )
        if any("rdp" in service or "ms-wbt-server" in service for service in services):
            self._append_unique(
                result.suggestions,
                "Review RDP encryption, Network Level Authentication, and access-control policy.",
            )

        if any(finding.kind == "web_path" for finding in result.findings):
            self._append_unique(
                result.suggestions,
                "Record the discovered paths as evidence and review access controls before deeper testing.",
            )

        if any(finding.kind == "runtime_error" for finding in result.findings):
            self._append_unique(
                result.suggestions,
                "Resolve the reported local/network error before changing scan intensity.",
            )

        if result.findings and not result.suggestions:
            self._append_unique(
                result.suggestions,
                "Correlate identified versions with authoritative advisories and document evidence before validation.",
            )
