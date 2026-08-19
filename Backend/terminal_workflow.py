"""Interactive, terminal-first PTAS student workflow.

The workflow deliberately limits automated activity to scoped Nmap assessment.
Suggested follow-up commands are hard-coded, non-destructive validation steps and
are never executed by PTAS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from getpass import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

from fastapi import HTTPException

from Backend.database import Base, SessionLocal, engine
from Backend.models.recommendation_model import Recommendation  # noqa: F401
from Backend.models.report_model import Report  # noqa: F401
from Backend.models.vulnerability_model import Vulnerability
from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.recommendation_repository import RecommendationRepository
from Backend.repositories.report_repository import ReportRepository
from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.scope_validation_repository import ScopeValidationRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.user_repository import UserRepository
from Backend.repositories.vulnerability_repository import VulnerabilityRepository
from Backend.services.nmap_service import NmapService
from Backend.services.exploitdb_service import ExploitDbService
from Backend.services.service_scan_service import ServiceScanService
from Backend.services.html_report_renderer import HtmlReportRenderer
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.sources import TmuxPaneSource
from Backend.usecases.report_usecase import ReportUseCase
from Backend.usecases.scan_execution_usecase import ScanExecutionUseCase
from Backend.utils.password_utils import hash_password, verify_password


SCAN_STAGES = (
    ("QUICK", "Fast port and service discovery"),
    ("FULL", "Detailed default-script and version assessment"),
)
CVE_SCAN_STAGE = (
    "VULNERABILITY",
    "Safe CVE checks and external Vulners correlation",
)
SHELL_READY_PATTERN = re.compile(r"(?m)(?:\$|#|❯)\s*$")


def _say(message: str) -> None:
    print(f"[PTAS] {message}", flush=True)


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


def _required(prompt: str, *, secret: bool = False) -> str:
    while True:
        value = (getpass(prompt) if secret else input(prompt)).strip()
        if value:
            return value
        _say("A value is required.")


def _choose(prompt: str, choices: tuple[str, ...]) -> str:
    labels = "/".join(choices)
    while True:
        value = input(f"{prompt} [{labels}]: ").strip().lower()
        if value in choices:
            return value
        _say(f"Choose one of: {', '.join(choices)}")


def _authenticate(db):
    users = UserRepository(db)
    action = _choose("Login or register", ("login", "register"))
    if action == "register":
        full_name = _required("Full name: ")
        email = _required("Email: ").lower()
        if users.get_user_by_email(email):
            _say("That email already exists; continuing with login.")
        else:
            while True:
                password = _required("Password (8-72 characters): ", secret=True)
                confirmation = _required("Confirm password: ", secret=True)
                if password != confirmation:
                    _say("Passwords do not match.")
                    continue
                if len(password) < 8:
                    _say("Password must contain at least 8 characters.")
                    continue
                try:
                    user = users.create_user(full_name, email, hash_password(password))
                except ValueError as exc:
                    _say(str(exc))
                    continue
                _say(f"Registration complete. Logged in as {user.email}.")
                return user

    while True:
        email = _required("Email: ").lower()
        password = _required("Password: ", secret=True)
        user = users.get_user_by_email(email)
        if user and verify_password(password, user.password_hash):
            _say(f"Login successful. Welcome, {user.full_name}.")
            return user
        _say("Invalid email or password. Try again.")


def _select_project(db, user):
    repository = ProjectRepository(db)
    projects = repository.get_projects_by_user_id(user.id)
    if projects:
        _say("Your projects:")
        for project in projects:
            print(f"  {project.id}: {project.project_name} ({project.status})")
        selection = input("Project ID, or press Enter to create a new project: ").strip()
        if selection.isdigit():
            selected = next((item for item in projects if item.id == int(selection)), None)
            if selected:
                return selected
            _say("That project does not belong to this account; creating a new one.")

    name = _required("Project name: ")
    description = input("Project description (optional): ").strip() or None
    return repository.create_project(user.id, name, description, "ACTIVE")


def _scope_type(scope_value: str) -> str:
    if "/" in scope_value:
        return "CIDR"
    try:
        NmapService._validate_target(scope_value)
    except ValueError:
        return "DOMAIN"
    return "HOSTNAME" if any(char.isalpha() for char in scope_value) else "CIDR"


def _configure_target(db, project):
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
    print(f"  Project: {project.project_name}")
    print(f"  Scope:   {scope_value}")
    print(f"  Target:  {target_value}")
    confirmation = input(
        "Do you confirm that this is an authorized training target? [yes/no]: "
    ).strip().lower()
    if confirmation not in {"yes", "y"}:
        raise RuntimeError("Authorization was not confirmed; no scan was run")

    scope_repository = ScopeValidationRepository(db)
    scope_repository.create_scope_validation(
        project.id,
        "Student-confirmed training scope",
        _scope_type(scope_value),
        scope_value,
        "Created by the terminal-first student workflow",
        True,
        "ACTIVE",
    )
    target = TargetRepository(db).create_target(
        project.id,
        f"Training target {target_value}",
        "NETWORK" if "/" in target_value else "HOST",
        target_value,
        scope_value,
        "ACTIVE",
    )
    return target, scope_value


def validation_suggestions(vulnerabilities: list[Vulnerability], target: str) -> list[dict]:
    """Return deduplicated, non-destructive follow-up commands."""
    quoted = shlex.quote(target)
    suggestions: list[dict] = []
    seen: set[tuple[int | None, str]] = set()
    for finding in vulnerabilities:
        service = (finding.service or "unknown").lower()
        key = (finding.port, service)
        if key in seen or finding.port is None:
            continue
        seen.add(key)
        port = int(finding.port)
        if service in {"http", "https", "http-alt", "https-alt"} or port in {80, 443, 8080, 8443}:
            scheme = "https" if "https" in service or port in {443, 8443} else "http"
            command = f"curl -k -I {scheme}://{quoted}:{port}/"
            purpose = "Review HTTP response headers and server exposure"
        elif service in {"ssh"} or port == 22:
            command = f"nmap -sV -p {port} --script ssh2-enum-algos {quoted}"
            purpose = "Review supported SSH algorithms without attempting login"
        elif service in {"smb", "microsoft-ds", "netbios-ssn"} or port in {139, 445}:
            command = f"nmap -p {port} --script smb-protocols,smb2-security-mode {quoted}"
            purpose = "Review SMB protocol and signing configuration"
        elif service in {"ftp"} or port == 21:
            command = f"nmap -p {port} --script ftp-syst {quoted}"
            purpose = "Collect the FTP system banner without authentication attacks"
        elif service in {"mysql"} or port == 3306:
            command = f"nmap -p {port} --script mysql-info {quoted}"
            purpose = "Collect exposed MySQL service metadata"
        elif service in {"rdp", "ms-wbt-server"} or port == 3389:
            command = f"nmap -p {port} --script rdp-enum-encryption {quoted}"
            purpose = "Review RDP encryption configuration"
        else:
            command = f"nmap -sV -p {port} {quoted}"
            purpose = f"Confirm the observed {service} service and version"
        suggestions.append({"finding_id": finding.id, "purpose": purpose, "command": command})
    return suggestions[:12]


def persist_validation_suggestions(db, suggestions: list[dict]) -> int:
    """Store terminal suggestions so generated reports include them."""
    repository = RecommendationRepository(db)
    created = 0
    for suggestion in suggestions:
        existing = repository.get_recommendations_by_vulnerability_id(
            suggestion["finding_id"]
        )
        if any(item.execution_steps == suggestion["command"] for item in existing):
            continue
        tool = suggestion["command"].split(maxsplit=1)[0]
        repository.create_recommendation(
            vulnerability_id=suggestion["finding_id"],
            attack_technique="Guided service validation",
            mitre_technique_id="T1046",
            exploitation_method=suggestion["purpose"],
            risk_level="LOW",
            priority=3,
            likelihood=50,
            impact=20,
            prerequisites="Explicit authorization and network access to the training target",
            tools_required=tool,
            execution_steps=suggestion["command"],
            post_exploitation="Record the evidence; do not proceed beyond the authorized validation step",
            confidence_score=80,
            status="PENDING_APPROVAL",
        )
        created += 1
    return created


def persist_exploitdb_references(db, scan_id: int, target: str) -> int:
    """Add version-specific Exploit-DB CVE references as candidate findings."""
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


def run_service_aware_checks(
    db,
    scan_id: int,
    target: str,
    event_log: Path | None,
) -> int:
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


def run_student_session(event_log: Path | None = None) -> int:
    _say("Terminal-first student workflow")
    _say("Only explicitly authorized training targets may be scanned.")
    _say("PTAS runs scoped Nmap stages; follow-up commands are never auto-executed.")
    try:
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            user = _authenticate(db)
            _event(event_log, "auth", f"Logged in as {user.email}")
            project = _select_project(db, user)
            _event(event_log, "project", f"Project selected: {project.project_name}")
            target, scope_value = _configure_target(db, project)
            _event(
                event_log,
                "target",
                f"Authorized target configured: {target.target_value}",
                target=target.target_value,
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

            scan_repository = ScanRepository(db)
            execution = ScanExecutionUseCase(
                scan_repository,
                TargetRepository(db),
                ScopeValidationRepository(db),
                ProjectRepository(db),
                VulnerabilityRepository(db),
            )
            completed_scan = None
            for index, (scan_type, description) in enumerate(scan_stages, start=1):
                _say(f"Scan stage {index}/{len(scan_stages)}: {description}")
                _event(event_log, "scan_started", description, scan_type=scan_type)
                scan = scan_repository.create_scan(
                    target.id,
                    f"Terminal session {scan_type.lower()} scan",
                    scan_type,
                    "PENDING",
                )
                result = execution.execute_scan_on_target(scan.id, project.id)
                completed_scan = scan
                _say(f"{scan_type} completed; {result['findings_persisted']} findings stored.")
                _event(
                    event_log,
                    "scan_completed",
                    f"{scan_type} completed",
                    scan_id=scan.id,
                    findings=result["findings_persisted"],
                )
                stage_findings = (
                    VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(scan.id)
                )
                if not stage_findings:
                    _say(f"{scan_type}: no exposed-service findings were identified.")
                    _event(
                        event_log,
                        "finding",
                        f"{scan_type}: no exposed-service findings identified",
                        scan_id=scan.id,
                    )
                for finding in stage_findings:
                    evidence = (
                        f"{finding.host}:{finding.port} {finding.service or 'unknown'}"
                        if finding.port is not None
                        else f"{finding.host} {finding.description}"
                    )
                    message = f"[{finding.severity}] {finding.description} — {evidence}"
                    _say(message)
                    _event(
                        event_log,
                        "finding",
                        message,
                        scan_id=scan.id,
                        finding_id=finding.id,
                        severity=finding.severity,
                    )

            if completed_scan is None:
                raise RuntimeError("No scan stage completed")
            tool_observations = run_service_aware_checks(
                db,
                completed_scan.id,
                target.target_value,
                event_log,
            )
            exploitdb_count = persist_exploitdb_references(
                db, completed_scan.id, target.target_value
            )
            _event(
                event_log,
                "exploitdb",
                f"Exploit-DB enrichment added {exploitdb_count} version-specific CVE reference(s)",
                scan_id=completed_scan.id,
                references=exploitdb_count,
                tool_observations=tool_observations,
            )
            findings = VulnerabilityRepository(db).get_vulnerabilities_by_scan_id(
                completed_scan.id
            )
            suggestions = validation_suggestions(findings, target.target_value)
            saved_suggestions = persist_validation_suggestions(db, suggestions)
            _event(
                event_log,
                "assessment_completed",
                f"Assessment completed with {len(findings)} findings",
                scan_id=completed_scan.id,
                target=target.target_value,
                recommendations=saved_suggestions,
            )
            output = Path("reports") / f"ptas-scan-{completed_scan.id}.json"
            report_command = (
                f"./ptas.sh report --scan-id {completed_scan.id} "
                f"--output {shlex.quote(str(output))}"
            )
            for number, suggestion in enumerate(suggestions, start=1):
                _event(
                    event_log,
                    "suggestion",
                    suggestion["purpose"],
                    number=number,
                    command=suggestion["command"],
                    report_command=report_command,
                )
            if event_log is None:
                print("\nValidation suggestions:")
                if not suggestions:
                    print("  No service-specific validation command is available.")
                for number, suggestion in enumerate(suggestions, start=1):
                    print(f"  {number}. {suggestion['purpose']}")
                    print(f"     {suggestion['command']}")
                    print(f"     Report: {report_command}")
            recommendation_command = (
                f"./ptas.sh recommend --scan-id {completed_scan.id}"
            )
            _event(
                event_log,
                "recommendation_ready",
                "Request one validation recommendation at a time",
                command=recommendation_command,
                scan_id=completed_scan.id,
            )
            _event(
                event_log,
                "report_ready",
                "A report can now be generated",
                command=report_command,
                output=str(output),
                scan_id=completed_scan.id,
            )
            print("\nAssessment complete.")
            print("Suggestions are displayed in the PTAS monitor pane.")
            print("To generate and save the report, run:")
            print(f"  {report_command}")
            print("To display the next validation recommendation, run:")
            print(f"  {recommendation_command}")
            print("PTAS setup is complete. Your left terminal remains open for the")
            print("displayed validation and report commands; use Ctrl+b then d to detach.")
            return 0
    except (EOFError, KeyboardInterrupt):
        _say("Session cancelled.")
        _event(event_log, "stopped", "Session cancelled by the student")
        return 130
    except (HTTPException, OSError, RuntimeError, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        _say(f"Session stopped: {detail}")
        _event(event_log, "error", str(detail))
        return 1


def run_dashboard(
    event_log: Path,
    interval: float = 0.5,
    pane: str | None = None,
) -> int:
    _say("Student-session monitor")
    _say("Waiting for login, scope, scan, finding, and report events...")
    position = 0
    pane_source = TmuxPaneSource(pane) if pane else None
    scope_value: str | None = None
    assessment_completed = False
    seen_observations: set[str] = set()
    observation_chunks: list[str] = []
    last_executed_command: str | None = None
    current_report_command: str | None = None
    current_scan_id: int | None = None
    try:
        while True:
            pane_chunk = pane_source.read_new() if pane_source else ""
            if event_log.exists():
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
                        elif kind == "ASSESSMENT_COMPLETED":
                            assessment_completed = True
                            current_scan_id = event.get("scan_id")
                        elif kind == "REPORT_READY":
                            current_report_command = event.get("command")
                            current_scan_id = event.get("scan_id") or current_scan_id
                        print(f"\n[{kind}] {event.get('message', '')}")
                        if event.get("command"):
                            print(f"  Command: {event['command']}")
                        if kind == "SUGGESTION":
                            print("  Copy this command to the left pane only if you want to run it.")
                            if event.get("report_command"):
                                print(f"  Report: {event['report_command']}")
                    position = handle.tell()
            if pane_chunk and assessment_completed and scope_value:
                clean = sanitize_terminal_text(pane_chunk)
                analyzer = TerminalAnalyzer(ScopeGuard([scope_value]))
                detected_command = analyzer.extract_latest_prompt_command(clean)
                if detected_command:
                    last_executed_command = detected_command
                    observation_chunks = [clean]
                elif last_executed_command:
                    observation_chunks.append(clean)
                    observation_chunks = observation_chunks[-8:]
                else:
                    time.sleep(interval)
                    continue
                context = "\n".join(observation_chunks)
                result = analyzer.analyze(
                    context,
                    context_command=last_executed_command,
                )
                fingerprint = result.fingerprint()
                if (result.command or result.findings) and fingerprint not in seen_observations:
                    seen_observations.add(fingerprint)
                    print("\n[LEFT PANE OBSERVATION]")
                    if result.command:
                        print(f"  Command: {result.command}")
                    print(
                        "  Scope: "
                        + ("authorized" if result.scope_allowed is True else "not verified")
                    )
                    for finding in result.findings[:8]:
                        print(f"  [{finding.severity}] {finding.summary}: {finding.evidence}")
                    for suggestion in result.suggestions[:5]:
                        print(f"  Suggestion: {suggestion}")
                    if current_report_command:
                        print(f"  Report: {current_report_command}")
                command_finished = bool(SHELL_READY_PATTERN.search(clean))
                if (
                    command_finished
                    and current_scan_id is not None
                    and last_executed_command
                ):
                    print("\n[NEXT RECOMMENDATION]")
                    next_recommendation(current_scan_id)
                    last_executed_command = None
                    observation_chunks = []
            time.sleep(interval)
    except KeyboardInterrupt:
        _say("Monitor stopped.")
        return 0


def start_terminal_workflow(no_tmux: bool = False) -> int:
    if no_tmux or not shutil.which("tmux") or not sys.stdout.isatty():
        if not no_tmux and not shutil.which("tmux"):
            _say("tmux is unavailable; continuing in one terminal.")
        return run_student_session()
    if "TMUX" in os.environ:
        _say("Already inside tmux; use ./ptas.sh student in this pane and")
        _say("./ptas.sh dashboard --event-log PATH in a second pane.")
        return 2

    project_dir = Path(__file__).resolve().parents[1]
    launcher = project_dir / "ptas.sh"
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    event_log = project_dir / ".ptas" / f"student-{timestamp}.jsonl"
    session = f"ptas-{timestamp}"
    login_shell = os.environ.get("SHELL", "/bin/bash")
    left = (
        f"{shlex.quote(str(launcher))} student --event-log {shlex.quote(str(event_log))}; "
        f"exec {shlex.quote(login_shell)}"
    )
    try:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "-c", str(project_dir), left],
            check=True,
        )
        pane_result = subprocess.run(
            ["tmux", "list-panes", "-t", session, "-F", "#{pane_id}"],
            check=True,
            capture_output=True,
            text=True,
        )
        left_pane = pane_result.stdout.strip().splitlines()[0]
        right = (
            f"{shlex.quote(str(launcher))} dashboard "
            f"--event-log {shlex.quote(str(event_log))} --pane {shlex.quote(left_pane)}"
        )
        subprocess.run(
            ["tmux", "split-window", "-h", "-t", session, "-c", str(project_dir), right],
            check=True,
        )
        subprocess.run(["tmux", "select-layout", "-t", session, "even-horizontal"], check=True)
        return subprocess.run(["tmux", "attach-session", "-t", session]).returncode
    except subprocess.CalledProcessError as exc:
        _say(f"Could not create tmux workspace: {exc}")
        return 1


def save_report(scan_id: int, output: Path) -> int:
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
        suggestions = validation_suggestions(findings, scan.target.target_value)
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


def select_next_recommendation(recommendations: list, shown_ids: set[int]):
    """Select the first recommendation not already presented."""
    return next((item for item in recommendations if item.id not in shown_ids), None)


def next_recommendation(scan_id: int, reset: bool = False) -> int:
    """Present one safe stored recommendation and remember progress locally."""
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
        recommendations = []
        if vulnerability_ids:
            recommendations = (
                db.query(Recommendation)
                .filter(Recommendation.vulnerability_id.in_(vulnerability_ids))
                .filter(Recommendation.attack_technique == "Guided service validation")
                .order_by(Recommendation.priority.desc(), Recommendation.id.asc())
                .all()
            )
        shown_ids = {int(value) for value in state.get(scan_key, [])}
        selected = select_next_recommendation(recommendations, shown_ids)
        report_output = f"reports/ptas-scan-{scan_id}.json"
        report_command = (
            f"./ptas.sh report --scan-id {scan_id} --output {report_output}"
        )
        if selected is None:
            if recommendations:
                _say("All validation recommendations for this scan have been shown.")
                print("Restart from the first recommendation with:")
                print(f"  ./ptas.sh recommend --scan-id {scan_id} --reset")
            else:
                _say("No guided validation recommendations are stored for this scan.")
                print("Run a new terminal assessment to generate recommendations.")
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
        print("Suggested command (review it; PTAS will not execute it):")
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


def render_existing_report(json_report: Path, output: Path | None = None) -> int:
    """Render an existing JSON report without requiring database access."""
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
