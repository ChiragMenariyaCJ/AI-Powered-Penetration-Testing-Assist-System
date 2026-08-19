"""Service-aware, bounded checks using locally installed Kali tools."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess

from Backend.services.nmap_service import NmapService
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text


@dataclass(frozen=True)
class ToolCheck:
    tool: str
    purpose: str
    command: tuple[str, ...]
    port: int | None = None
    service: str | None = None


@dataclass(frozen=True)
class ToolResult:
    check: ToolCheck
    status: str
    returncode: int | None
    output: str


class ServiceScanService:
    """Choose checks from observed services; never invokes a shell."""

    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def __init__(self, timeout: int = 90, output_limit: int = 6000):
        self.timeout = timeout
        self.output_limit = output_limit

    @staticmethod
    def _available(tool: str) -> str | None:
        return shutil.which(tool)

    @staticmethod
    def _is_hostname(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return False
        except ValueError:
            return "/" not in target

    def build_checks(self, target: str, findings: list) -> list[ToolCheck]:
        target = NmapService._validate_target(target)
        checks: list[ToolCheck] = []
        seen: set[tuple[str, int | None]] = set()

        def add(
            tool: str,
            purpose: str,
            arguments: list[str],
            port: int | None,
            service: str,
        ) -> None:
            executable = self._available(tool)
            key = (tool, port)
            if not executable or key in seen:
                return
            seen.add(key)
            checks.append(
                ToolCheck(
                    tool=tool,
                    purpose=purpose,
                    command=(executable, *arguments),
                    port=port,
                    service=service,
                )
            )

        observed = {
            (int(item.port), (item.service or "unknown").lower())
            for item in findings
            if item.port is not None
            and item.vulnerability_type
            in {"EXPOSED_SERVICE", "CVE_CANDIDATE", "CONFIRMED_CVE"}
        }
        for port, service in sorted(observed):
            if service in {"http", "https", "http-alt", "https-alt"} or port in {
                80,
                443,
                8080,
                8443,
            }:
                tls = "https" in service or port in {443, 8443}
                url = f"{'https' if tls else 'http'}://{target}:{port}/"
                add("whatweb", "Web technology fingerprint", ["--color=never", url], port, service)
                add(
                    "curl",
                    "HTTP response headers",
                    ["-k", "-sS", "-I", "--max-time", "20", url],
                    port,
                    service,
                )
                add(
                    "nikto",
                    "Bounded web configuration assessment",
                    ["-host", url, "-nointeractive", "-maxtime", "60s"],
                    port,
                    service,
                )
                wordlist = Path("/usr/share/wordlists/dirb/common.txt")
                if wordlist.exists():
                    add(
                        "gobuster",
                        "Bounded common-path discovery",
                        [
                            "dir",
                            "--quiet",
                            "--url",
                            url,
                            "--wordlist",
                            str(wordlist),
                            "--threads",
                            "10",
                            "--timeout",
                            "5s",
                            "--no-error",
                            "--no-tls-validation",
                        ],
                        port,
                        service,
                    )
                if tls:
                    add(
                        "sslscan",
                        "TLS protocol and cipher assessment",
                        ["--no-colour", f"{target}:{port}"],
                        port,
                        service,
                    )

            if service in {"smb", "microsoft-ds", "netbios-ssn"} or port in {139, 445}:
                add(
                    "enum4linux-ng",
                    "SMB and NetBIOS configuration enumeration",
                    ["-A", target],
                    port,
                    service,
                )

            if service in {"mysql", "mariadb"} or port == 3306:
                add(
                    "mysqladmin",
                    "MySQL availability and authentication-boundary check",
                    ["--connect-timeout=5", "--host", target, "--port", str(port), "ping"],
                    port,
                    service,
                )

            if service in {"postgres", "postgresql"} or port == 5432:
                add(
                    "pg_isready",
                    "PostgreSQL availability check",
                    ["--host", target, "--port", str(port), "--timeout", "5"],
                    port,
                    service,
                )

            if service == "redis" or port == 6379:
                add(
                    "redis-cli",
                    "Redis authentication-boundary PING check",
                    ["-h", target, "-p", str(port), "--no-auth-warning", "PING"],
                    port,
                    service,
                )

        if self._is_hostname(target):
            add("dig", "DNS address resolution", ["+short", target, "A"], None, "dns")
        return checks

    def execute(self, checks: list[ToolCheck]) -> list[ToolResult]:
        results = []
        for check in checks:
            try:
                completed = subprocess.run(
                    list(check.command),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                raw = "\n".join(value for value in (completed.stdout, completed.stderr) if value)
                clean = sanitize_terminal_text(raw).strip()[: self.output_limit]
                results.append(
                    ToolResult(
                        check=check,
                        status="COMPLETED" if completed.returncode == 0 else "COMPLETED_WITH_ERRORS",
                        returncode=completed.returncode,
                        output=clean,
                    )
                )
            except subprocess.TimeoutExpired as exc:
                partial = exc.stdout or ""
                if isinstance(partial, bytes):
                    partial = partial.decode("utf-8", errors="replace")
                results.append(
                    ToolResult(
                        check=check,
                        status="TIMEOUT",
                        returncode=None,
                        output=sanitize_terminal_text(partial).strip()[: self.output_limit],
                    )
                )
            except OSError as exc:
                results.append(
                    ToolResult(check, "FAILED", None, str(exc))
                )
        return results

    def as_findings(self, scan_id: int, target: str, results: list[ToolResult]) -> list[dict]:
        findings = []
        for result in results:
            cves = sorted({value.upper() for value in self.CVE_PATTERN.findall(result.output)})
            excerpt = result.output or "No textual output returned"
            finding_type = "TOOL_CVE_CANDIDATE" if cves else "TOOL_OBSERVATION"
            findings.append(
                {
                    "scan_id": scan_id,
                    "host": target,
                    "port": result.check.port,
                    "service": result.check.service,
                    "vulnerability_type": finding_type,
                    "severity": "INFO",
                    "description": (
                        f"{result.check.tool}: {result.check.purpose} "
                        f"[{result.status}]\n{excerpt}"
                    ),
                    "version": None,
                    "cves": ", ".join(cves) if cves else None,
                    "remediation": (
                        "Review this tool observation manually. Tool output and CVE text "
                        "are supporting evidence, not automatic confirmation."
                    ),
                    "status": "OPEN",
                }
            )
        return findings
