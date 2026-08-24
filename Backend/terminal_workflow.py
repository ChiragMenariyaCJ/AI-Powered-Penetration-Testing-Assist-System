"""Interactive, terminal-first PTAS student workflow.

The workflow deliberately limits automated activity to scoped Nmap assessment.
Realtime recommendations are generated from current evidence, filtered through
PTAS guardrails, and never executed by PTAS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from getpass import getpass
import json
import os
from pathlib import Path
import re
import shlex
import time
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from Backend.api_client import PTASApiClient, PTASApiError
from Backend.config import settings
from Backend.database import Base, SessionLocal, engine
# Importing from the model package registers all relationship targets. The terminal
# process runs separately from FastAPI, so it cannot rely on main.py doing this first.
from Backend.models import Recommendation, Vulnerability
from Backend.repositories.recommendation_repository import RecommendationRepository
from Backend.repositories.report_repository import ReportRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.services.nmap_service import NmapService
from Backend.services.exploitdb_service import ExploitDbService
from Backend.services.service_scan_service import ServiceScanService
from Backend.services.html_report_renderer import HtmlReportRenderer
from Backend.services.lab_profile_service import (
    AccessExercise,
    LabVerificationError,
    Metasploitable2LabService,
)
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.advisor import AdvisorError, OllamaAdvisor
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.safety import (
    SAFE_METADATA_TOOLS,
    filter_safe_recommendations,
    is_safe_manual_command,
    is_safe_recommendation,
)
from Backend.terminal_assistant.sources import FollowFileSource
from Backend.usecases.report_usecase import ReportUseCase


SCAN_STAGES = (
    ("QUICK", "Fast port and service discovery"),
    ("FULL", "Detailed default-script and version assessment"),
)
CVE_SCAN_STAGE = (
    "VULNERABILITY",
    "Fast external Vulners CVE correlation on common ports",
)
SHELL_READY_PATTERN = re.compile(r"(?m)(?:\$|#|❯)\s*$")
LIVE_PROMPT_CONTEXT_LIMIT = 4000
RECOMMENDATION_SAFETY_NOTICE = (
    "Safety: validation recommendations collect evidence only. Credential or "
    "access testing must use the separate gated access-test workflow."
)
SEVERITY_PRIORITY = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ---------------------------------------------------------------------------
# Output, events, and realtime-advisor configuration
# ---------------------------------------------------------------------------


# Print a PTAS-prefixed status message immediately so both terminals receive timely output.
def _say(message: str) -> None:
    print(f"[PTAS] {message}", flush=True)


# Keep enough adjacent terminal text to join a prompt to typed input.
def _append_live_prompt_context(existing: str, new_text: str) -> str:
    """Keep enough adjacent terminal text to join a prompt to typed input.

    QTerminal writes the shell prompt and the student's command to the
    transcript independently.  The dashboard therefore cannot assume that a
    single file read contains both pieces.  Keeping a short bounded tail lets
    command detection see ``$ nmap ...`` without retaining the full session or
    allowing the monitor's memory usage to grow indefinitely.
    """

    return (existing + new_text)[-LIVE_PROMPT_CONTEXT_LIMIT:]


# Extract a command despite Kali zsh repainting it away from the prompt.
def _extract_live_executed_command(
    analyzer: TerminalAnalyzer,
    transcript_context: str,
) -> str | None:
    """Extract a command despite Kali zsh repainting it away from the prompt.

    A normal transcript contains ``$ command`` and uses the strict prompt
    parser. Kali's autosuggestion and syntax-highlighting plugins sometimes
    repaint the command after cursor rewinds, leaving the final executable text
    on its own line. The dashboard reads only the student's left pane and calls
    this function only after assessment setup has completed, so accepting the
    analyzer's standalone-command fallback here does not confuse commands
    printed in the read-only recommendation pane with executed commands.
    """

    return (
        analyzer.extract_latest_prompt_command(transcript_context)
        or analyzer.extract_latest_command(transcript_context)
    )


# Append one timestamped JSON event to the optional student-session audit log.
def _event(path: Path | None, kind: str, message: str, **data) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "kind": kind,
        "message": message,
        **data,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


# Copy CLI model options into environment variables shared with the dashboard process.
def configure_realtime_advisor_env(
    provider: str | None = None,
    model: str | None = None,
    ollama_url: str | None = None,
    allow_remote_llm: bool = False,
) -> None:
    """Perform the configure realtime advisor env operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    if provider:
        os.environ["PTAS_LLM_PROVIDER"] = provider
    if model:
        os.environ["PTAS_LLM_MODEL"] = model
    if ollama_url:
        os.environ["OLLAMA_BASE_URL"] = ollama_url
    if allow_remote_llm:
        os.environ["PTAS_ALLOW_REMOTE_LLM"] = "1"


# Build safely quoted environment assignments for the separately launched dashboard process.
def _realtime_env_prefix(
    provider: str | None = None,
    model: str | None = None,
    ollama_url: str | None = None,
    allow_remote_llm: bool = False,
) -> str:
    values: dict[str, str] = {}
    if provider:
        values["PTAS_LLM_PROVIDER"] = provider
    if model:
        values["PTAS_LLM_MODEL"] = model
    if ollama_url:
        values["OLLAMA_BASE_URL"] = ollama_url
    if allow_remote_llm:
        values["PTAS_ALLOW_REMOTE_LLM"] = "1"
    if not values:
        return ""
    assignments = " ".join(f"{key}={shlex.quote(value)}" for key, value in values.items())
    return f"env {assignments} "


# Create the configured local Ollama advisor or return None for the rules-only provider.
def _build_realtime_advisor() -> OllamaAdvisor | None:
    provider = os.getenv("PTAS_LLM_PROVIDER", "rules").lower()
    if provider != "ollama":
        return None
    model = os.getenv("PTAS_LLM_MODEL") or os.getenv("OLLAMA_MODEL")
    if not model:
        raise ValueError("Set --model or OLLAMA_MODEL when using --provider ollama")
    allow_remote = os.getenv("PTAS_ALLOW_REMOTE_LLM", "").lower() in {"1", "true", "yes"}
    return OllamaAdvisor(
        model=model,
        base_url=os.getenv("OLLAMA_BASE_URL"),
        allow_remote=allow_remote,
    )


# Enable the advisor only when Ollama and the configured model pass startup checks.
def _optional_realtime_advisor() -> OllamaAdvisor | None:
    try:
        advisor = _build_realtime_advisor()
        if advisor:
            advisor.ensure_model_available()
        return advisor
    except (AdvisorError, ValueError) as exc:
        _say(f"Realtime advisor disabled: {exc}")
        return None


# ---------------------------------------------------------------------------
# Student input, account, project, and authorized target setup
# ---------------------------------------------------------------------------


# Prompt repeatedly until the student supplies a non-empty normal or secret value.
def _required(prompt: str, *, secret: bool = False) -> str:
    while True:
        value = (getpass(prompt) if secret else input(prompt)).strip()
        if value:
            return value
        _say("A value is required.")


# Prompt until the student enters one of the explicitly supported choices.
def _choose(prompt: str, choices: tuple[str, ...]) -> str:
    labels = "/".join(choices)
    while True:
        value = input(f"{prompt} [{labels}]: ").strip().lower()
        if value in choices:
            return value
        _say(f"Choose one of: {', '.join(choices)}")


# Guide login or registration through the backend API and return the authenticated user.
def _authenticate(api: PTASApiClient) -> dict:

    action = _choose("Login or register", ("login", "register"))
    email: str | None = None
    password: str | None = None
    if action == "register":
        while True:
            full_name = _required("Full name: ")
            email = _required("Email: ").lower()
            password = _required("Password (8-72 characters): ", secret=True)
            confirmation = _required("Confirm password: ", secret=True)
            if password != confirmation:
                _say("Passwords do not match.")
                continue
            try:
                api.post(
                    "/api/auth/register",
                    {"full_name": full_name, "email": email, "password": password},
                )
            except PTASApiError as exc:
                _say(f"Registration failed: {exc}")
                email = None
                password = None
                continue
            _say("Registration complete. Logging in through the PTAS API.")
            break

    while True:
        email = email or _required("Email: ").lower()
        password = password or _required("Password: ", secret=True)
        try:
            result = api.post(
                "/api/auth/login",
                {"email": email, "password": password},
            )
        except PTASApiError as exc:
            _say(f"Login failed: {exc}")
            email = None
            password = None
            continue
        api.access_token = result["access_token"]
        user = result["user"]
        _say(f"Login successful. Welcome, {user['full_name']}.")
        return user


# List the user projects and either select one or create a new project through the API.
def _select_project(api: PTASApiClient, user: dict) -> dict:

    result = api.get("/api/projects/", query={"user_id": user["id"]})
    projects = result["projects"]
    if projects:
        _say("Your projects:")
        for project in projects:
            print(f"  {project['id']}: {project['project_name']} ({project['status']})")
        selection = input("Project ID, or press Enter to create a new project: ").strip()
        if selection.isdigit():
            selected = next(
                (item for item in projects if item["id"] == int(selection)),
                None,
            )
            if selected:
                return selected
            _say("That project does not belong to this account; creating a new one.")

    name = _required("Project name: ")
    description = input("Project description (optional): ").strip() or None
    return api.post(
        "/api/projects/",
        {
            "user_id": user["id"],
            "project_name": name,
            "description": description,
            "status": "ACTIVE",
        },
    )


# Classify one scope entry as CIDR, IP address, or domain for API persistence.
def _scope_type(scope_value: str) -> str:
    if "/" in scope_value:
        return "CIDR"
    try:
        NmapService._validate_target(scope_value)
    except ValueError:
        return "DOMAIN"
    return "HOSTNAME" if any(char.isalpha() for char in scope_value) else "CIDR"


# Collect scope, target, and authorisation confirmation before creating API records.
def _configure_target(api: PTASApiClient, project: dict) -> tuple[dict, str]:

    print("\nScope setup")
    print("  Scope is the complete authorized boundary, for example:")
    print("    192.168.56.101       one authorized host")
    print("    192.168.56.0/24      an authorized lab network")
    print("    lab.example.test     an authorized domain and its subdomains")
    print("    metasploitable       a single-label local lab hostname")
    while True:
        scope_value = _required("Authorized scope: ").rstrip(".")
        try:
            guard = ScopeGuard([scope_value])
            break
        except ValueError as exc:
            _say(f"Invalid scope: {exc}. Please try again.")

    while True:
        target_value = _required("Training target inside that scope: ").rstrip(".")
        try:
            NmapService._validate_target(target_value)
        except ValueError as exc:
            _say(f"Invalid target: {exc}. Please try again.")
            continue
        if not guard.is_allowed(target_value):
            _say(
                f"Target {target_value} is outside scope {scope_value}. "
                "Enter a target inside the authorized boundary."
            )
            continue
        break

    print("\nAuthorization confirmation")
    print(f"  Project: {project['project_name']}")
    print(f"  Scope:   {scope_value}")
    print(f"  Target:  {target_value}")
    confirmation = input(
        "Do you confirm that this is an authorized training target? [yes/no]: "
    ).strip().lower()
    if confirmation not in {"yes", "y"}:
        raise RuntimeError("Authorization was not confirmed; no scan was run")

    api.post(
        "/api/scope-validation/",
        {
            "project_id": project["id"],
            "scope_rule_name": "Student-confirmed training scope",
            "scope_type": _scope_type(scope_value),
            "scope_value": scope_value,
            "description": "Created by the terminal-first student workflow",
            "is_inclusive": True,
            "status": "ACTIVE",
        },
    )
    scope_check = api.post(
        "/api/scope-validation/check-target-scope",
        {"project_id": project["id"], "target_value": target_value},
    )
    if not scope_check["is_in_scope"]:
        raise RuntimeError("The API rejected the target as outside the authorized scope")
    target = api.post(
        "/api/targets/",
        {
            "project_id": project["id"],
            "target_name": f"Training target {target_value}",
            "target_type": "NETWORK" if "/" in target_value else "HOST",
            "target_value": target_value,
            "scope": scope_value,
            "status": "ACTIVE",
        },
    )
    return target, scope_value


# ---------------------------------------------------------------------------
# Evidence-based recommendation generation and persistence
# ---------------------------------------------------------------------------


# Sort findings by severity, port, and database ID for stable terminal presentation.
def _finding_sort_key(finding: Vulnerability) -> tuple[int, int, int]:
    severity = (getattr(finding, "severity", None) or "INFO").upper()
    return (
        SEVERITY_PRIORITY.get(severity, 5),
        0 if finding.port is not None else 1,
        int(finding.port or 0),
    )


# Format one stored finding as a concise target, port, service, and title evidence line.
def _finding_evidence(finding: Vulnerability, target: str) -> str:
    endpoint = target
    if finding.port is not None:
        endpoint = f"{target}:{finding.port}"
    service = getattr(finding, "service", None) or "unknown"
    details = getattr(finding, "description", None) or "observed service"
    version = getattr(finding, "version", None)
    if version:
        details = f"{details} ({version})"
    return f"{endpoint} {service} - {details}"


# Build the bounded scan-evidence prompt used to request model recommendations.
def _scan_recommendation_prompt(
    findings: list[Vulnerability],
    target: str,
    scan_id: int | None = None,
    lab_name: str | None = None,
) -> str:
    evidence = "\n".join(
        f"- [{getattr(finding, 'severity', None) or 'INFO'}] {_finding_evidence(finding, target)}"
        for finding in sorted(findings, key=_finding_sort_key)[:20]
    ) or "- No stored findings"
    access_command = (
        f"./ptas.sh access-test --scan-id {scan_id} --lab {lab_name}"
        if scan_id is not None and lab_name
        else "./ptas.sh access-test --scan-id <scan-id> --lab <registered-lab>"
    )
    return f"""You are a real-time classroom penetration-testing coach.
Use only the current scan evidence. Generate up to five useful next evidence-collection commands. Keep every command scoped to {target}. Use only curl, dig, enum4linux-ng, nmap, pg_isready, sslscan, or whatweb. For Nmap --script, use only banner, dns-nsid, ftp-syst, http-headers, http-title, mysql-info, nbstat, smb-protocols, smb-security-mode, smb2-capabilities, smb2-time, smtp-commands, ssh-hostkey, ssh2-enum-algos, ssl-cert, ssl-enum-ciphers, or telnet-encryption. Do not repeat equivalent commands. Do not use shell operators, credential guessing, destructive actions, evasion, service stress, automatic access, or access chaining.
If the next useful teaching step would require access, say only: STOP: use `{access_command}` and wait for instructor confirmation.

Return one JSON array and no Markdown. Every item must use this shape:
[{{"purpose":"short evidence-based reason", "command":"complete command to run manually"}}]

Authorized target: {target}
Current scan id: {scan_id or "unknown"}
Current evidence:
{evidence}
"""


# Build manual, non-destructive validation commands from observed evidence.
def _fallback_realtime_suggestions(
    vulnerabilities: list[Vulnerability],
    target: str,
    limit: int | None = 5,
) -> list[dict]:
    """Build manual, non-destructive validation commands from observed evidence.

    Commands use only Nmap discovery scripts that Kali identifies as safe. They
    remain suggestions: PTAS displays and stores them but never executes them.
    """

    script_profiles = {
        21: ("ftp-syst,banner", "Collect FTP system and banner metadata"),
        22: ("ssh2-enum-algos,ssh-hostkey", "Review SSH algorithms and host keys"),
        23: ("banner", "Collect the Telnet service banner"),
        25: ("smtp-commands,banner", "Review advertised SMTP commands and banner"),
        53: ("dns-nsid", "Collect DNS server identity metadata"),
        80: ("http-title,http-headers", "Review the HTTP title and response headers"),
        139: ("nbstat", "Collect NetBIOS names and host metadata"),
        445: (
            "smb-protocols,smb-security-mode",
            "Review supported SMB dialects and security mode",
        ),
        2121: ("ftp-syst,banner", "Collect FTP system and banner metadata"),
        3306: ("mysql-info", "Collect MySQL protocol and version metadata"),
        5432: ("banner", "Collect the PostgreSQL service banner"),
    }
    suggestions: list[dict] = []
    seen: set[tuple[int | None, str]] = set()
    for finding in sorted(vulnerabilities, key=_finding_sort_key):
        if finding.port is None:
            continue
        service = getattr(finding, "service", None) or "unknown service"
        key = (finding.port, service.lower())
        if key in seen:
            continue
        seen.add(key)
        endpoint = f"{target}:{finding.port}"
        scripts, action = script_profiles.get(
            int(finding.port),
            ("banner", f"Collect additional {service} banner metadata"),
        )
        command = (
            f"nmap -Pn -sV -p {int(finding.port)} --script {scripts} "
            f"--script-timeout 20s {shlex.quote(target)}"
        )
        if not is_safe_recommendation(command, [target]):
            continue
        suggestions.append(
            {
                "finding_id": finding.id,
                "purpose": (
                    f"{action} for {service} on {endpoint}; record the evidence."
                ),
                "command": command,
                "tool": "nmap",
                "source": "evidence-fallback",
                "attack_technique": "Guided service validation",
            }
        )
        if limit is not None and len(suggestions) >= limit:
            break
    return suggestions


# Return a stable representation used to compare manual commands.
def _normalize_validation_command(command: str | None) -> str:
    """Return a stable representation used to compare manual commands."""

    if not command:
        return ""
    try:
        return shlex.join(shlex.split(command))
    except ValueError:
        return " ".join(command.split())


# Select the next unexecuted validation after the completed command.
def select_follow_up_suggestion(
    suggestions: list[dict],
    executed_commands: set[str],
    completed_command: str | None,
) -> dict | None:
    """Select the next unexecuted validation after the completed command.

    The list is rotated after the command the student just ran. This makes the
    pane advance naturally even when the student chooses recommendation three
    before recommendation one. Previously shown commands remain eligible until
    they are actually executed.
    """

    if not suggestions:
        return None
    completed = _normalize_validation_command(completed_command)
    start = 0
    for index, suggestion in enumerate(suggestions):
        if _normalize_validation_command(suggestion.get("command")) == completed:
            start = index + 1
            break
    ordered = suggestions[start:] + suggestions[:start]
    return next(
        (
            suggestion
            for suggestion in ordered
            if suggestion.get("command")
            and _normalize_validation_command(suggestion["command"])
            not in executed_commands
        ),
        None,
    )


# Build every safe manual validation available for one completed scan.
def _scan_validation_catalog(scan_id: int) -> list[dict]:
    """Build every safe manual validation available for one completed scan."""

    with SessionLocal() as db:
        scan = ScanRepository(db).get_scan_by_id(scan_id)
        if not scan:
            return []
        findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        return _fallback_realtime_suggestions(
            findings,
            scan.target.target_value,
            limit=None,
        )


# Return the verified lab manifest matching a completed scan and target.
def _verified_metasploitable_lab(scan_id: int, target: str):
    """Return the verified lab manifest matching a completed scan and target.

    An IP address by itself never enables lab behavior. The saved manifest,
    current route/MAC identity, database scan target, and Metasploitable service
    fingerprint must all agree first.
    """

    project_dir = Path(__file__).resolve().parents[1]
    service = Metasploitable2LabService(project_dir)
    if not service.lab_dir.is_dir():
        return None
    matching_manifest = None
    for path in sorted(service.lab_dir.glob("*.json")):
        try:
            manifest = service.load(path.stem)
        except LabVerificationError:
            continue
        if manifest.target == target and manifest.profile == service.PROFILE:
            matching_manifest = manifest
            break
    if matching_manifest is None:
        return None

    service.verify_runtime(matching_manifest)
    service.verify_neighbor(matching_manifest)
    with SessionLocal() as db:
        scan = ScanRepository(db).get_scan_by_id(scan_id)
        if not scan:
            raise LabVerificationError(f"Scan {scan_id} was not found")
        findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        service.verify_scan(matching_manifest, scan, findings)
    return matching_manifest


# Build deduplicated, service-aware validation suggestions from stored scan findings.
def validation_suggestions(
    vulnerabilities: list[Vulnerability],
    target: str,
    advisor: OllamaAdvisor | None = None,
    scan_id: int | None = None,
    lab_name: str | None = None,
) -> list[dict]:
    """Perform the validation suggestions operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    findings = [item for item in vulnerabilities if getattr(item, "id", None) is not None]
    if not findings:
        return []
    primary_finding = sorted(findings, key=_finding_sort_key)[0]
    generated: list[dict[str, str]] = []
    source = "evidence-fallback"
    if advisor:
        try:
            generated = advisor.advise_commands(
                _scan_recommendation_prompt(findings, target, scan_id, lab_name),
                [target],
                limit=5,
            )
            generated = [
                item
                for item in generated
                if is_safe_manual_command(item.get("command", ""), [target])
                and is_safe_recommendation(
                    f"Review {item.get('purpose', '')}",
                    [target],
                )
            ][:5]
            source = "realtime-ollama"
            if not generated:
                _say(
                    "Ollama returned no structured command that passed PTAS "
                    "scope and safety checks; using evidence fallback."
                )
        except AdvisorError as exc:
            _say(f"Realtime advisor unavailable; using evidence fallback: {exc}")
    if not generated:
        return _fallback_realtime_suggestions(findings, target)
    return [
        {
            "finding_id": primary_finding.id,
            "purpose": suggestion["purpose"],
            "command": suggestion["command"],
            "tool": source,
            "source": source,
            "attack_technique": "Realtime guided validation",
        }
        for suggestion in generated[:5]
    ]


# Return whether stored execution text is a runnable, allowlisted command.
def _is_manual_validation_command(value: str | None, target: str) -> bool:
    """Return whether stored execution text is a runnable, allowlisted command."""

    if not value:
        return False
    try:
        parts = shlex.split(value)
    except ValueError:
        return False
    if parts and parts[0].lower() == "sudo":
        parts = parts[1:]
    if not parts or parts[0].rsplit("/", 1)[-1].lower() not in SAFE_METADATA_TOOLS:
        return False
    return is_safe_recommendation(value, [target])


# Store new safe validation suggestions while skipping commands already saved for the scan.
def persist_validation_suggestions(db, suggestions: list[dict]) -> int:
    """Perform the persist validation suggestions operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    repository = RecommendationRepository(db)
    created = 0
    for suggestion in suggestions:
        existing = repository.get_recommendations_by_vulnerability_id(
            suggestion["finding_id"]
        )
        execution_step = suggestion.get("command") or suggestion["purpose"]
        if any(item.execution_steps == execution_step for item in existing):
            continue
        tool = suggestion.get("tool")
        if not tool and suggestion.get("command"):
            tool = suggestion["command"].split(maxsplit=1)[0]
        tool = tool or "realtime-advisor"
        repository.create_recommendation(
            vulnerability_id=suggestion["finding_id"],
            attack_technique=suggestion.get("attack_technique", "Realtime guided validation"),
            mitre_technique_id="T1046",
            exploitation_method=suggestion["purpose"],
            risk_level="LOW",
            priority=3,
            likelihood=50,
            impact=20,
            prerequisites="Explicit authorization and network access to the training target",
            tools_required=tool,
            execution_steps=execution_step,
            post_exploitation="Record the evidence; do not proceed beyond the authorized validation step",
            confidence_score=80,
            status="PENDING_APPROVAL",
        )
        created += 1
    return created


# Correlate versioned findings with local Exploit-DB entries and store them as review evidence.
def persist_exploitdb_references(db, scan_id: int, target: str) -> int:
    """Perform the persist exploitdb references operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    vulnerability_repository = VulnerabilityRepository(db)
    findings = vulnerability_repository.get_vulnerabilities_by_scan_id(scan_id)
    existing_edb_ids = {
        token
        for finding in findings
        if finding.vulnerability_type == "EXPLOIT_DB_REFERENCE"
        for token in (finding.description or "").split()
        if token.startswith("EDB-")
    }
    service = ExploitDbService()
    pending: list[dict] = []
    searched: set[tuple[str, str]] = set()
    for finding in findings:
        product = (finding.service or "").strip()
        version = (finding.version or "").strip()
        key = (product.lower(), version.lower())
        if not product or not version or key in searched:
            continue
        searched.add(key)
        for reference in service.search(product, version):
            if not reference["cves"]:
                continue
            marker = f"EDB-{reference['edb_id']}"
            if marker in existing_edb_ids:
                continue
            existing_edb_ids.add(marker)
            verification = "verified entry" if reference["verified"] else "unverified entry"
            pending.append(
                {
                    "scan_id": scan_id,
                    "host": finding.host or target,
                    "port": finding.port,
                    "service": finding.service,
                    "vulnerability_type": "EXPLOIT_DB_REFERENCE",
                    "severity": "INFO",
                    "description": (
                        f"{marker} ({verification}): {reference['title']}"
                    ),
                    "version": finding.version,
                    "cves": ", ".join(reference["cves"]),
                    "remediation": (
                        "Research reference only. Confirm the exact product build, "
                        "distribution backports, affected configuration, and vendor "
                        "advisory before treating any listed CVE as applicable."
                    ),
                    "status": "OPEN",
                }
            )
    if pending:
        vulnerability_repository.bulk_create_vulnerabilities(pending)
    return len(pending)


# Run installed metadata tools for observed services and persist their successful evidence.
def run_service_aware_checks(
    db,
    scan_id: int,
    target: str,
    event_log: Path | None,
) -> int:
    """Perform the run service aware checks operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    repository = VulnerabilityRepository(db)
    base_findings = repository.get_vulnerabilities_by_scan_id(scan_id)
    scanner = ServiceScanService()
    checks = scanner.build_checks(target, base_findings)
    if not checks:
        _say("No additional installed service-specific tool applies to the detected services.")
        _event(event_log, "tool_scan", "No additional service-specific checks selected")
        return 0

    persisted = 0
    _say(f"Running {len(checks)} service-specific checks with installed Kali tools.")
    for index, check in enumerate(checks, start=1):
        _say(f"Tool check {index}/{len(checks)}: {check.tool} — {check.purpose}")
        _event(
            event_log,
            "tool_started",
            f"{check.tool}: {check.purpose}",
            tool=check.tool,
            port=check.port,
        )
        results = scanner.execute([check])
        tool_findings = scanner.as_findings(scan_id, target, results)
        if tool_findings:
            repository.bulk_create_vulnerabilities(tool_findings)
            persisted += len(tool_findings)
        status = results[0].status if results else "FAILED"
        _event(
            event_log,
            "tool_completed",
            f"{check.tool} finished with status {status}",
            tool=check.tool,
            status=status,
            observations=len(tool_findings),
        )
    _say(f"Service-specific checks completed; {persisted} observations stored.")
    return persisted


# ---------------------------------------------------------------------------
# Main student session and live recommendation dashboard
# ---------------------------------------------------------------------------


# Validate a scan-execution response before reading success-only fields.
def _completed_finding_count(scan_type: str, result: dict) -> int:
    """Validate a scan-execution response before reading success-only fields.

    The backend normally reports failures with a non-2xx response, but this guard
    also handles an older backend or malformed response without exposing a Python
    traceback to the student.
    """

    if not isinstance(result, dict):
        raise RuntimeError(f"{scan_type} scan returned an invalid API response")
    if str(result.get("status", "")).upper() != "COMPLETED":
        error = result.get("error") or "the backend did not provide an error message"
        raise RuntimeError(f"{scan_type} scan failed: {error}")
    if "findings_persisted" not in result:
        raise RuntimeError(
            f"{scan_type} scan completed but its API response omitted findings_persisted"
        )
    return int(result["findings_persisted"])


# Describe the evidence level separately from its review priority.
def _finding_display_label(finding: dict) -> str:
    """Describe the evidence level separately from its review priority.

    An open service is directly observed network evidence, while a Vulners match is
    only a candidate based on a product/version fingerprint. Keeping those labels
    visible prevents a student from reading every stored finding as a confirmed CVE.
    """

    finding_type = str(finding.get("vulnerability_type", "")).upper()
    evidence_labels = {
        "EXPOSED_SERVICE": "OBSERVED SERVICE",
        "CVE_CANDIDATE": "CVE CANDIDATE",
        "CONFIRMED_CVE": "NMAP VULNERABLE",
        "TOOL_OBSERVATION": "TOOL OBSERVATION",
        "TOOL_CVE_CANDIDATE": "TOOL CVE CANDIDATE",
        "EXPLOIT_DB_REFERENCE": "EXPLOIT-DB REFERENCE",
    }
    evidence = evidence_labels.get(finding_type, "FINDING")
    severity = str(finding.get("severity", "UNKNOWN")).upper()
    return f"[{evidence}] [REVIEW: {severity}]"


# Guide authentication, scope confirmation, staged scanning, findings, and report preparation.
def run_student_session(event_log: Path | None = None) -> int:
    """Perform the run student session operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    _say("Terminal-first student workflow")
    _say("Only explicitly authorized training targets may be scanned.")
    _say("PTAS runs scoped Nmap stages; realtime recommendations are never auto-executed.")
    try:
        advisor = _optional_realtime_advisor()
        if advisor:
            _say(f"Realtime recommendations enabled with local Ollama model '{advisor.model}'.")
        else:
            _say("Realtime model not configured; using evidence-only fallback recommendations.")
        # Confirm the separately started backend is ready before asking for student input.
        api = PTASApiClient()
        api.get("/health/ready")
        _say(f"Connected to backend API at {api.base_url}; calls will appear in ./start.sh.")
        # Keep one database session for local enrichment and reporting that follow the API scans.
        with SessionLocal() as db:
            user = _authenticate(api)
            _event(event_log, "auth", f"Logged in as {user['email']}")
            project = _select_project(api, user)
            _event(event_log, "project", f"Project selected: {project['project_name']}")
            target, scope_value = _configure_target(api, project)
            _event(
                event_log,
                "target",
                f"Authorized target configured: {target['target_value']}",
                target=target["target_value"],
                scope=scope_value,
            )
            cve_lookup = _choose(
                "Include CVE correlation? This sends detected product/version or CPE data to Vulners",
                ("yes", "no"),
            ) == "yes"
            scan_stages = SCAN_STAGES
            if cve_lookup:
                scan_stages = SCAN_STAGES + (CVE_SCAN_STAGE,)
            _event(
                event_log,
                "cve_lookup",
                "External Vulners CVE correlation enabled"
                if cve_lookup
                else "External Vulners CVE correlation skipped",
            )

            completed_scan = None
            # Create a separate stored scan for each stage so its evidence remains auditable.
            for index, (scan_type, description) in enumerate(scan_stages, start=1):
                _say(f"Scan stage {index}/{len(scan_stages)}: {description}")
                _event(event_log, "scan_started", description, scan_type=scan_type)
                scan = api.post(
                    "/api/scans/",
                    {
                        "target_id": target["id"],
                        "scan_name": f"Terminal session {scan_type.lower()} scan",
                        "scan_type": scan_type,
                        "status": "PENDING",
                    },
                )
                result = api.post(
                    f"/api/scan-execution/execute/{scan['id']}",
                    query={"project_id": project["id"]},
                    timeout=settings.nmap_timeout + 30,
                )
                findings_persisted = _completed_finding_count(scan_type, result)
                completed_scan = scan
                _say(f"{scan_type} completed; {findings_persisted} findings stored.")
                _event(
                    event_log,
                    "scan_completed",
                    f"{scan_type} completed",
                    scan_id=scan["id"],
                    findings=findings_persisted,
                )
                stage_result = api.get(
                    "/api/vulnerabilities/",
                    query={"scan_id": scan["id"]},
                )
                stage_findings = stage_result["vulnerabilities"]
                if not stage_findings:
                    _say(f"{scan_type}: no exposed-service findings were identified.")
                    _event(
                        event_log,
                        "finding",
                        f"{scan_type}: no exposed-service findings identified",
                        scan_id=scan["id"],
                    )
                for finding in stage_findings:
                    evidence = (
                        f"{finding['host']}:{finding['port']} {finding.get('service') or 'unknown'}"
                        if finding.get("port") is not None
                        else f"{finding['host']} {finding['description']}"
                    )
                    message = (
                        f"{_finding_display_label(finding)} "
                        f"{finding['description']} — {evidence}"
                    )
                    _say(message)
                    _event(
                        event_log,
                        "finding",
                        message,
                        scan_id=scan["id"],
                        finding_id=finding["id"],
                        severity=finding["severity"],
                    )

            if completed_scan is None:
                raise RuntimeError("No scan stage completed")
            # Enrich only the final detailed scan with installed service tools and local Exploit-DB data.
            tool_observations = run_service_aware_checks(
                db,
                completed_scan["id"],
                target["target_value"],
                event_log,
            )
            exploitdb_count = persist_exploitdb_references(
                db, completed_scan["id"], target["target_value"]
            )
            _event(
                event_log,
                "exploitdb",
                f"Exploit-DB enrichment added {exploitdb_count} version-specific CVE reference(s)",
                scan_id=completed_scan["id"],
                references=exploitdb_count,
                tool_observations=tool_observations,
            )
            final_result = api.get(
                "/api/vulnerabilities/",
                query={"scan_id": completed_scan["id"]},
            )
            findings = [
                SimpleNamespace(**finding)
                for finding in final_result["vulnerabilities"]
            ]
            # Generate advice from stored evidence, then persist it so reports use the same recommendations.
            suggestions = validation_suggestions(
                findings,
                target["target_value"],
                advisor=advisor,
                scan_id=completed_scan["id"],
            )
            saved_suggestions = persist_validation_suggestions(db, suggestions)
            _event(
                event_log,
                "assessment_completed",
                f"Assessment completed with {len(findings)} findings",
                scan_id=completed_scan["id"],
                target=target["target_value"],
                recommendations=saved_suggestions,
            )
            output = Path("reports") / f"ptas-scan-{completed_scan['id']}.json"
            report_command = (
                f"./ptas.sh report --scan-id {completed_scan['id']} "
                f"--output {shlex.quote(str(output))}"
            )
            for number, suggestion in enumerate(suggestions, start=1):
                _event(
                    event_log,
                    "suggestion",
                    suggestion["purpose"],
                    number=number,
                    command=suggestion["command"],
                    source=suggestion.get("source", "unknown"),
                    report_command=report_command,
                )
            if event_log is None:
                print("\nRealtime recommendations:")
                print(f"  {RECOMMENDATION_SAFETY_NOTICE}")
                if not suggestions:
                    print("  No realtime recommendation is available for the stored findings.")
                for number, suggestion in enumerate(suggestions, start=1):
                    print(f"  {number}. {suggestion['purpose']}")
                    if suggestion.get("command"):
                        print(f"     {suggestion['command']}")
                    print(f"     Report: {report_command}")
            recommendation_command = (
                f"./ptas.sh recommend --scan-id {completed_scan['id']}"
            )
            _event(
                event_log,
                "recommendation_ready",
                "Request one validation recommendation at a time",
                command=recommendation_command,
                scan_id=completed_scan["id"],
            )
            _event(
                event_log,
                "report_ready",
                "A report can now be generated",
                command=report_command,
                output=str(output),
                scan_id=completed_scan["id"],
            )
            print("\nAssessment complete.")
            if event_log is None:
                print("Suggestions are displayed above.")
            else:
                print("Suggestions are displayed in the right-hand PTAS panel.")
            print("To generate and save the report, run:")
            print(f"  {report_command}")
            print("To display the next validation recommendation, run:")
            print(f"  {recommendation_command}")
            print("PTAS setup is complete. This left pane will now become your normal")
            print("shell, where you can run the displayed validation and report commands.")
            return 0
    except (EOFError, KeyboardInterrupt):
        _say("Session cancelled.")
        _event(event_log, "stopped", "Session cancelled by the student")
        return 130
    except (HTTPException, OSError, RuntimeError, SQLAlchemyError, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        _say(f"Session stopped: {detail}")
        _event(event_log, "error", str(detail))
        return 1


# Follow the left-terminal transcript and continuously show analysed recommendations on the right.
def run_dashboard(
    event_log: Path,
    transcript: Path,
    interval: float = 0.5,
) -> int:
    """Perform the run dashboard operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    _say("Live recommendation assistant")
    _say(RECOMMENDATION_SAFETY_NOTICE)
    _say("Waiting for assessment evidence from the left terminal...")
    position = 0
    terminal_source = FollowFileSource(transcript)
    advisor = _optional_realtime_advisor()
    if advisor:
        _say(f"Realtime monitor recommendations enabled with local Ollama model '{advisor.model}'.")
    scope_value: str | None = None
    assessment_completed = False
    validation_catalog: list[dict] = []
    catalog_loaded = False
    executed_commands: set[str] = set()
    observation_chunks: list[str] = []
    # A prompt and its typed command commonly arrive in different transcript
    # reads. Preserve a small tail until a complete prompt-command pair exists.
    prompt_context = ""
    last_executed_command: str | None = None
    current_report_command: str | None = None
    current_scan_id: int | None = None
    assessment_target: str | None = None
    verified_lab = None
    try:
        while True:
            transcript_chunk = terminal_source.read_new()
            if event_log.exists():
                # Resume at the saved byte offset so each workflow event is rendered exactly once.
                with event_log.open("r", encoding="utf-8") as handle:
                    handle.seek(position)
                    for line in handle:
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        kind = str(event.get("kind", "event")).upper()
                        if kind == "TARGET":
                            scope_value = event.get("scope")
                            assessment_target = event.get("target") or assessment_target
                        elif kind == "ASSESSMENT_COMPLETED":
                            assessment_completed = True
                            current_scan_id = event.get("scan_id")
                            assessment_target = event.get("target") or assessment_target
                        elif kind == "REPORT_READY":
                            current_report_command = event.get("command")
                            current_scan_id = event.get("scan_id") or current_scan_id
                        if kind in {
                            "SUGGESTION",
                            "RECOMMENDATION_READY",
                            "REPORT_READY",
                        }:
                            print(f"\n[{kind}] {event.get('message', '')}")
                            if event.get("command"):
                                print(f"  Command: {event['command']}")
                            if kind == "SUGGESTION":
                                source = event.get("source") or "rules"
                                print(f"  Source: {source}")
                                print("  Run this in the left terminal only if you choose to.")
                                if event.get("report_command"):
                                    print(f"  Report: {event['report_command']}")
                    position = handle.tell()
            if assessment_completed and current_scan_id is not None and not catalog_loaded:
                # Load fallback commands and verify lab identity once after assessment completion.
                try:
                    validation_catalog = _scan_validation_catalog(current_scan_id)
                except (OSError, SQLAlchemyError):
                    validation_catalog = []
                if assessment_target:
                    try:
                        verified_lab = _verified_metasploitable_lab(
                            current_scan_id,
                            assessment_target,
                        )
                    except (LabVerificationError, OSError, SQLAlchemyError) as exc:
                        print(f"\n[METASPLOITABLE LAB NOT ENABLED] {exc}")
                    if verified_lab:
                        print("\n[METASPLOITABLE 2 LAB MODE ENABLED]")
                        print(f"  Lab: {verified_lab.name}")
                        print(f"  Exact target: {verified_lab.target}")
                        print(
                            "  Guidance may transition to the separately "
                            "confirmed access-test workflow."
                        )
                catalog_loaded = True
            if transcript_chunk and assessment_completed and scope_value:
                # Sanitise terminal control codes and rebuild commands split across QTerminal writes.
                clean = sanitize_terminal_text(transcript_chunk)
                analyzer = TerminalAnalyzer(ScopeGuard([scope_value]))
                if last_executed_command:
                    observation_chunks.append(clean)
                    observation_chunks = observation_chunks[-8:]
                else:
                    prompt_context = _append_live_prompt_context(prompt_context, clean)
                    detected_command = _extract_live_executed_command(
                        analyzer,
                        prompt_context,
                    )
                    if not detected_command:
                        time.sleep(interval)
                        continue
                    last_executed_command = detected_command
                    observation_chunks = [prompt_context]
                    prompt_context = ""
                command_finished = bool(SHELL_READY_PATTERN.search(clean))
                if not command_finished:
                    time.sleep(interval)
                    continue
                # Analyse only after the next shell prompt proves the command has finished producing output.
                context = "\n".join(observation_chunks)
                result = analyzer.analyze(
                    context,
                    context_command=last_executed_command,
                )
                normalized_command = _normalize_validation_command(
                    last_executed_command
                )
                if normalized_command:
                    executed_commands.add(normalized_command)

                print("\n[COMMAND ANALYSIS COMPLETE]")
                if result.command:
                    print(f"  Command: {result.command}")
                print(
                    "  Scope: "
                    + ("authorized" if result.scope_allowed is True else "not verified")
                )
                if result.findings:
                    for finding in result.findings[:8]:
                        print(f"  [{finding.severity}] {finding.summary}: {finding.evidence}")
                else:
                    print("  No structured finding was parsed; the completed output was still reviewed.")
                for suggestion in result.suggestions[:3]:
                    print(f"  Analysis: {suggestion}")
                if current_report_command:
                    print(f"  Report: {current_report_command}")
                _event(
                    event_log,
                    "command_analysis",
                    "Completed terminal command analyzed",
                    scan_id=current_scan_id,
                    analysis=result.to_dict(),
                )

                model_follow_up: dict[str, str] | None = None
                # The lab command opens a separate confirmation gate; it does not execute access testing.
                lab_access_command = (
                    f"./ptas.sh access-test --scan-id {current_scan_id} "
                    f"--lab {verified_lab.name}"
                    if verified_lab and current_scan_id is not None
                    else None
                )
                if advisor and result.scope_allowed is not False:
                    print(
                        f"\n[PTAS] Asking local Ollama model '{advisor.model}' "
                        "for the next evidence-based command...",
                        flush=True,
                    )
                    try:
                        if lab_access_command:
                            model_follow_up = advisor.advise_next_command(
                                result,
                                context,
                                executed_commands,
                                lab_access_command=lab_access_command,
                            )
                        else:
                            model_follow_up = advisor.advise_next_command(
                                result,
                                context,
                                executed_commands,
                            )
                    except AdvisorError as exc:
                        print(f"  Realtime advisor warning: {exc}")

                # Prefer accepted model output, then a verified lab gate, then deterministic safe fallbacks.
                if model_follow_up:
                    print("\n[NEXT ADAPTIVE RECOMMENDATION]")
                    print(f"  Source: local Ollama model '{advisor.model}'")
                    print("  Based on: the completed command and terminal output above")
                    print(f"  Purpose: {model_follow_up['purpose']}")
                    print(f"  Command: {model_follow_up['command']}")
                    print("  Run it manually in the left terminal if you choose to continue.")
                    _event(
                        event_log,
                        "adaptive_recommendation",
                        model_follow_up["purpose"],
                        scan_id=current_scan_id,
                        command=model_follow_up["command"],
                        source="ollama",
                    )
                elif advisor and lab_access_command:
                    print("\n[NEXT METASPLOITABLE 2 LAB STEP]")
                    print(
                        "  Source: verified PTAS lab profile for exact target "
                        f"{verified_lab.target}"
                    )
                    print(
                        "  Purpose: Continue through the identity-checked, "
                        "explicitly confirmed access-testing workflow."
                    )
                    print(f"  Command: {lab_access_command}")
                    print("  Run it manually in the left terminal to review the gate.")
                    _event(
                        event_log,
                        "adaptive_recommendation",
                        "Open the verified Metasploitable 2 access-testing gate",
                        scan_id=current_scan_id,
                        command=lab_access_command,
                        source="verified-metasploitable-lab",
                        model_rejection=getattr(
                            advisor,
                            "last_rejection_reason",
                            None,
                        ),
                    )
                elif advisor:
                    print("\n[NO SAFE MODEL RECOMMENDATION]")
                    rejection_reason = getattr(
                        advisor,
                        "last_rejection_reason",
                        None,
                    )
                    if rejection_reason:
                        print(f"  Reason: {rejection_reason}.")
                    else:
                        print(
                            "  Ollama did not return a new command that passed "
                            "PTAS safety and scope checks."
                        )
                    fallback = select_follow_up_suggestion(
                        validation_catalog,
                        executed_commands,
                        last_executed_command,
                    )
                    if fallback:
                        print("\n[NEXT SAFETY FALLBACK]")
                        print(
                            "  Source: PTAS evidence-based validation queue "
                            "(the Ollama response was rejected)"
                        )
                        print(f"  Purpose: {fallback['purpose']}")
                        print(f"  Command: {fallback['command']}")
                        print("  Run it manually in the left terminal if you choose to continue.")
                        _event(
                            event_log,
                            "adaptive_recommendation",
                            fallback["purpose"],
                            scan_id=current_scan_id,
                            command=fallback["command"],
                            source="safety-fallback",
                            model_rejection=rejection_reason,
                        )
                    else:
                        print("\n[VALIDATION QUEUE COMPLETE]")
                        print("  No additional unexecuted safe validation is available.")
                else:
                    fallback = select_follow_up_suggestion(
                        validation_catalog,
                        executed_commands,
                        last_executed_command,
                    )
                    if fallback:
                        print("\n[NEXT RULES FALLBACK]")
                        print("  Source: deterministic PTAS fallback (Ollama is unavailable)")
                        print(f"  Purpose: {fallback['purpose']}")
                        print(f"  Command: {fallback['command']}")
                        print("  Run it manually in the left terminal if you choose to continue.")
                        _event(
                            event_log,
                            "adaptive_recommendation",
                            fallback["purpose"],
                            scan_id=current_scan_id,
                            command=fallback["command"],
                            source="rules-fallback",
                        )
                    else:
                        print("\n[VALIDATION QUEUE COMPLETE]")
                        print("  No additional unexecuted rules-based validation is available.")

                # Reset per-command state while preserving the final prompt for the next transcript chunk.
                last_executed_command = None
                observation_chunks = []
                # The completion chunk ends with the next shell prompt. Keep it
                # so a command typed in the following read is detectable.
                prompt_context = _append_live_prompt_context("", clean)
            time.sleep(interval)
    except KeyboardInterrupt:
        _say("Monitor stopped.")
        return 0


# Create the transcript paths and launch the real shell beside the read-only recommendation pane.
def start_terminal_workflow(
    plain: bool = False,
    provider: str | None = None,
    model: str | None = None,
    ollama_url: str | None = None,
    allow_remote_llm: bool = False,
) -> int:
    """Perform the start terminal workflow operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    configure_realtime_advisor_env(provider, model, ollama_url, allow_remote_llm)
    if plain:
        return run_student_session()
    if not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")):
        _say("Graphical desktop unavailable; continuing in plain mode.")
        return run_student_session()

    project_dir = Path(__file__).resolve().parents[1]
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    state_dir = project_dir / ".ptas"
    event_log = state_dir / f"student-{timestamp}.jsonl"
    transcript = state_dir / f"student-{timestamp}.typescript"
    layout_path = state_dir / f"student-{timestamp}.terminator.json"
    realtime_prefix = _realtime_env_prefix(
        provider,
        model,
        ollama_url,
        allow_remote_llm,
    )
    from Backend.split_terminal import (
        NativeTerminalError,
        launch_split_terminals,
        run_recorded_shell,
        split_qterminal_recommendations,
    )

    qterminal_service = os.getenv("QTERM_DBUS_SERVICE")
    qterminal_object = os.getenv("QTERM_DBUS_OBJECT")
    if qterminal_service and qterminal_object:
        state_dir.mkdir(parents=True, exist_ok=True)
        transcript.touch(exist_ok=True)
        dashboard_command = [
            str(project_dir / "ptas.sh"),
            "dashboard",
            "--event-log",
            str(event_log),
            "--transcript",
            str(transcript),
        ]
        if provider:
            dashboard_command.extend(["--provider", provider])
        if model:
            dashboard_command.extend(["--model", model])
        if ollama_url:
            dashboard_command.extend(["--ollama-url", ollama_url])
        if allow_remote_llm:
            dashboard_command.append("--allow-remote-llm")
        try:
            split_qterminal_recommendations(
                qterminal_service,
                qterminal_object,
                project_dir,
                dashboard_command,
            )
        except NativeTerminalError as exc:
            _say(f"Native QTerminal split unavailable: {exc}")
        else:
            _say("Opened Actions → Split View Left-Right in this QTerminal window.")
            session_result = run_student_session(event_log)
            if session_result != 0:
                return session_result
            _say("Student setup finished. Starting a normal recorded shell on the left.")
            return run_recorded_shell(
                project_dir,
                transcript,
                os.getenv("SHELL", "/bin/bash"),
            )

    try:
        result = launch_split_terminals(
            project_dir,
            event_log,
            transcript,
            layout_path,
            realtime_prefix,
            os.getenv("SHELL", "/bin/bash"),
        )
    except NativeTerminalError as exc:
        _say(str(exc))
        _say("Falling back to the current terminal.")
        return run_student_session()
    _say("Opened two native PTAS terminals in one Terminator window.")
    return result


# ---------------------------------------------------------------------------
# Reports and step-by-step recommendations
# ---------------------------------------------------------------------------


# Generate the scan report through the report use case and save JSON plus optional HTML output.
def save_report(scan_id: int, output: Path) -> int:
    """Perform the save report operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        scan = ScanRepository(db).get_scan_by_id(scan_id)
        if not scan:
            _say(f"Scan {scan_id} was not found.")
            return 1
        newer_scan = (
            db.query(type(scan))
            .filter(type(scan).target_id == scan.target_id)
            .filter(type(scan).id > scan.id)
            .order_by(type(scan).id.desc())
            .first()
        )
        if newer_scan:
            _say(
                f"Note: scan {newer_scan.id} is newer for this target; "
                f"you requested historical scan {scan_id}."
            )
        findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        persist_exploitdb_references(db, scan_id, scan.target.target_value)
        findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        suggestions = validation_suggestions(
            findings,
            scan.target.target_value,
            advisor=_optional_realtime_advisor(),
            scan_id=scan_id,
        )
        persist_validation_suggestions(db, suggestions)
        result = ReportUseCase.generate_report(
            db,
            scan_id,
            f"PTAS training assessment - scan {scan_id}",
            "Generated from the terminal-first student workflow",
            "PTAS terminal student",
        )
        if "error" in result:
            _say(result["error"])
            return 1
        report = ReportRepository.get_report_by_id(db, result["id"])
        if report is None:
            _say("The report record could not be loaded.")
            return 1
        output = output.expanduser().resolve()
        if output.suffix.lower() == ".html":
            html_output = output
            json_output = output.with_suffix(".json")
        else:
            json_output = output if output.suffix else output.with_suffix(".json")
            html_output = json_output.with_suffix(".html")
        json_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.parent.mkdir(parents=True, exist_ok=True)
        parsed = json.loads(report.report_content or "{}")
        json_output.write_text(
            json.dumps(parsed, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        html_output.write_text(
            HtmlReportRenderer.render(parsed),
            encoding="utf-8",
        )
        _say(f"Structured JSON report saved to {json_output}")
        _say(f"Formatted HTML report saved to {html_output}")
        return 0


# Select the first safe recommendation command not already displayed for this scan.
def select_next_recommendation(recommendations: list, shown_ids: set[int]):
    """Perform the select next recommendation operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    return next((item for item in recommendations if item.id not in shown_ids), None)


# Load scan evidence and display one new manual validation recommendation at a time.
def next_recommendation(
    scan_id: int,
    reset: bool = False,
    provider: str | None = None,
    model: str | None = None,
    ollama_url: str | None = None,
    allow_remote_llm: bool = False,
    lab_name: str | None = None,
) -> int:
    """Perform the next recommendation operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    configure_realtime_advisor_env(provider, model, ollama_url, allow_remote_llm)
    Base.metadata.create_all(bind=engine)
    project_dir = Path(__file__).resolve().parents[1]
    state_path = project_dir / ".ptas" / "recommendation-state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        state = {}
    scan_key = str(scan_id)
    if reset:
        state.pop(scan_key, None)

    with SessionLocal() as db:
        scan = ScanRepository(db).get_scan_by_id(scan_id)
        if not scan:
            _say(f"Scan {scan_id} was not found.")
            return 1
        newer_scan = (
            db.query(type(scan))
            .filter(type(scan).target_id == scan.target_id)
            .filter(type(scan).id > scan.id)
            .order_by(type(scan).id.desc())
            .first()
        )
        if newer_scan:
            _say(
                f"Note: scan {newer_scan.id} is newer for this target; "
                f"you requested historical scan {scan_id}."
            )
        vulnerability_ids = [
            item.id
            for item in VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        ]
        findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
        new_suggestions = validation_suggestions(
            findings,
            scan.target.target_value,
            advisor=_optional_realtime_advisor(),
            scan_id=scan_id,
            lab_name=lab_name,
        )
        created = persist_validation_suggestions(db, new_suggestions)
        if created:
            _say(f"Stored {created} refreshed realtime recommendation(s).")
        recommendations = []
        if vulnerability_ids:
            recommendations = (
                db.query(Recommendation)
                .filter(Recommendation.vulnerability_id.in_(vulnerability_ids))
                .filter(
                    Recommendation.attack_technique.in_(
                        ["Realtime guided validation", "Guided service validation"]
                    )
                )
                .order_by(Recommendation.priority.desc(), Recommendation.id.asc())
                .all()
            )
        # Older PTAS versions persisted prose in execution_steps. Once runnable,
        # allowlisted commands exist, show those instead of making the student
        # cycle through stale prose-only recommendations first.
        command_recommendations = [
            item
            for item in recommendations
            if _is_manual_validation_command(
                item.execution_steps,
                scan.target.target_value,
            )
        ]
        if command_recommendations:
            recommendations = command_recommendations
        shown_ids = {int(value) for value in state.get(scan_key, [])}
        selected = select_next_recommendation(recommendations, shown_ids)
        report_output = f"reports/ptas-scan-{scan_id}.json"
        report_command = (
            f"./ptas.sh report --scan-id {scan_id} --output {report_output}"
        )
        if selected is None:
            if recommendations:
                _say("All realtime recommendations for this scan have been shown.")
                print("Restart from the first recommendation with:")
                print(f"  ./ptas.sh recommend --scan-id {scan_id} --reset")
            else:
                _say("No realtime recommendations are stored for this scan.")
                print("Run a new assessment, or enable the local model with --provider ollama --model MODEL.")
            print("Generate or refresh the report with:")
            print(f"  {report_command}")
            return 0

        finding = db.query(Vulnerability).filter(Vulnerability.id == selected.vulnerability_id).first()
        position = len(shown_ids) + 1
        print(f"\nPTAS recommendation {position}/{len(recommendations)}")
        if finding:
            print(
                f"Finding: [{finding.severity}] {finding.host}"
                + (f":{finding.port}" if finding.port is not None else "")
                + f" {finding.service or ''}"
            )
            if finding.cves:
                print(f"CVE references: {finding.cves}")
        print(f"Purpose: {selected.exploitation_method}")
        print("Suggested next step (review it; PTAS will not execute it):")
        print(f"  {selected.execution_steps}")
        print("\nAfter reviewing or running it, request the next recommendation with:")
        print(f"  ./ptas.sh recommend --scan-id {scan_id}")
        print("Generate or refresh the report at any time with:")
        print(f"  {report_command}")

        shown_ids.add(selected.id)
        state[scan_key] = sorted(shown_ids)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        temporary.replace(state_path)
        return 0


# Read a structured JSON report and render its escaped standalone HTML companion.
def render_existing_report(json_report: Path, output: Path | None = None) -> int:
    """Perform the render existing report operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """
    json_report = json_report.expanduser().resolve()
    if not json_report.is_file():
        _say(f"JSON report not found: {json_report}")
        return 1
    try:
        payload = json.loads(json_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _say(f"Could not read JSON report: {exc}")
        return 1
    if not isinstance(payload, dict) or "report_metadata" not in payload:
        _say("The input is not a recognized PTAS JSON report.")
        return 1
    html_output = (
        output.expanduser().resolve()
        if output
        else json_report.with_suffix(".html")
    )
    if html_output.suffix.lower() != ".html":
        html_output = html_output.with_suffix(".html")
    html_output.parent.mkdir(parents=True, exist_ok=True)
    html_output.write_text(HtmlReportRenderer.render(payload), encoding="utf-8")
    _say(f"Formatted HTML report saved to {html_output}")
    return 0


# ---------------------------------------------------------------------------
# Restricted Metasploitable 2 lab access exercises
# ---------------------------------------------------------------------------


# Register an exact isolated Metasploitable 2 VM identity for later gated access exercises.
def register_metasploitable2_lab(
    name: str,
    target: str,
    vm: str | None = None,
    provider: str = "virtualbox",
    interface: str | None = None,
    kali_source: str | None = None,
) -> int:
    """Perform the register metasploitable2 lab operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    project_dir = Path(__file__).resolve().parents[1]
    service = Metasploitable2LabService(project_dir)
    try:
        if provider == "virtualbox":
            if not vm:
                raise LabVerificationError("VirtualBox registration requires --vm")
            manifest = service.register_virtualbox(name, target, vm)
        elif provider == "vmware":
            if not vm:
                raise LabVerificationError("VMware host registration requires --vm")
            manifest = service.register_vmware(
                name,
                target,
                vm,
                interface or "vmnet1",
                kali_source,
            )
        elif provider == "vmware-network":
            manifest = service.register_vmware_network(
                name,
                target,
                interface,
                kali_source,
            )
        else:
            raise LabVerificationError(
                "Provider must be virtualbox, vmware, or vmware-network"
            )
    except LabVerificationError as exc:
        _say(f"Lab registration failed: {exc}")
        return 1
    _say(f"Registered Metasploitable 2 lab '{manifest.name}'.")
    print(f"  Provider: {manifest.provider}")
    print(f"  VM UUID: {manifest.vm_uuid}")
    print(f"  Target: {manifest.target}")
    if manifest.interface:
        print(f"  Interface: {manifest.interface}")
    if manifest.kali_source:
        print(f"  Kali source: {manifest.kali_source}")
    print(f"  Host-only MAC: {manifest.expected_mac}")
    print(f"  Manifest: {service.manifest_path(name)}")
    return 0


# Revalidate a saved lab against its VM identity, route, neighbour MAC, and optional scan.
def check_metasploitable2_lab(name: str) -> int:
    """Perform the check metasploitable2 lab operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    project_dir = Path(__file__).resolve().parents[1]
    service = Metasploitable2LabService(project_dir)
    try:
        manifest = service.load(name)
        snapshots = service.verify_runtime(manifest)
        service.verify_neighbor(manifest)
    except LabVerificationError as exc:
        _say(f"Lab verification failed: {exc}")
        return 1
    if manifest.provider == "vmware-network":
        _say(
            f"Lab '{name}' passed private route, isolated interface, VMware MAC, "
            "and network identity checks."
        )
    else:
        _say(f"Lab '{name}' passed VM identity, host-only network, snapshot, and MAC checks.")
    print(f"  Target: {manifest.target}")
    print(f"  Baseline: {', '.join(snapshots)}")
    return 0


# Choose the first service-specific lab exercise not already shown in the saved state.
def select_next_access_exercise(exercises: list[AccessExercise], shown_keys: set[str]):
    """Perform the select next access exercise operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    return next((item for item in exercises if item.key not in shown_keys), None)


# Verify the exact lab and typed consent before displaying one manual access exercise.
def next_access_exercise(scan_id: int, lab_name: str, reset: bool = False) -> int:
    """Perform the next access exercise operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    project_dir = Path(__file__).resolve().parents[1]
    service = Metasploitable2LabService(project_dir)
    state_path = project_dir / ".ptas" / "access-state.json"
    try:
        manifest = service.load(lab_name)
        snapshots = service.verify_runtime(manifest)
        service.verify_neighbor(manifest)
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            scan = ScanRepository(db).get_scan_by_id(scan_id)
            if not scan:
                raise LabVerificationError(f"Scan {scan_id} was not found")
            findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan_id)
            ports = service.verify_scan(manifest, scan, findings)
            exercises = service.exercises(manifest.target, ports)
            if not exercises:
                raise LabVerificationError("No allowlisted access exercise matches this scan")

            print("\nRestricted access-testing gate")
            print(f"  Profile: {manifest.profile}")
            print(f"  Provider: {manifest.provider}")
            print(f"  VM UUID: {manifest.vm_uuid}")
            print(f"  Target: {manifest.target}/32")
            if manifest.interface:
                print(f"  Interface: {manifest.interface}")
            if manifest.kali_source:
                print(f"  Kali source: {manifest.kali_source}")
            print(f"  Baseline: {snapshots[-1]}")
            confirmation = input("Type ENABLE ACCESS TESTING to continue: ").strip()
            if confirmation != "ENABLE ACCESS TESTING":
                raise LabVerificationError("Access testing was not enabled")

            try:
                state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
            except (OSError, json.JSONDecodeError):
                state = {}
            state_key = f"{lab_name}:{scan_id}"
            if reset:
                state.pop(state_key, None)
            shown_keys = set(state.get(state_key, []))
            selected = select_next_access_exercise(exercises, shown_keys)
            report_command = (
                f"./ptas.sh report --scan-id {scan_id} "
                f"--output reports/ptas-scan-{scan_id}.json"
            )
            if selected is None:
                _say("All allowlisted access exercises have been shown.")
                print(f"  Reset: ./ptas.sh access-test --scan-id {scan_id} --lab {lab_name} --reset")
                print(f"  Report: {report_command}")
                return 0

            print(f"\nACCESS_TESTING exercise {len(shown_keys) + 1}/{len(exercises)}")
            print(f"Service: {selected.service} on port {selected.port}")
            print(f"Title: {selected.title}")
            print(f"Purpose: {selected.purpose}")
            print(f"Credential handling: {selected.credential_note}")
            print("Review and manually execute only against the registered VM:")
            print(f"  {selected.command}")
            print("Next exercise:")
            print(f"  ./ptas.sh access-test --scan-id {scan_id} --lab {lab_name}")
            print(f"Report: {report_command}")

            matching_finding = next(
                (item for item in findings if item.port == selected.port),
                None,
            )
            if matching_finding:
                repository = RecommendationRepository(db)
                existing = repository.get_recommendations_by_vulnerability_id(
                    matching_finding.id
                )
                if not any(item.execution_steps == selected.command for item in existing):
                    repository.create_recommendation(
                        vulnerability_id=matching_finding.id,
                        attack_technique="Restricted Metasploitable 2 access testing",
                        mitre_technique_id=None,
                        exploitation_method=selected.purpose,
                        risk_level="MEDIUM",
                        priority=5,
                        likelihood=50,
                        impact=40,
                        prerequisites=(
                            "Registered host-only Metasploitable 2 VM, matching UUID/MAC, "
                            "clean snapshot, exact /32 target, and explicit operator approval"
                        ),
                        tools_required=selected.command.split(maxsplit=1)[0],
                        execution_steps=selected.command,
                        post_exploitation="Stop after access validation and restore the clean VM snapshot",
                        confidence_score=100,
                        status="PENDING_APPROVAL",
                    )
            shown_keys.add(selected.key)
            state[state_key] = sorted(shown_keys)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = state_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
            temporary.replace(state_path)
            return 0
    except (EOFError, KeyboardInterrupt):
        _say("Access testing cancelled.")
        return 130
    except LabVerificationError as exc:
        _say(f"Access testing blocked: {exc}")
        return 1
