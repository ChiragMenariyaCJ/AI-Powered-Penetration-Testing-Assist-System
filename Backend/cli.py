"""Command-line entry point for the PTAS student workflow."""

import argparse
from collections import deque
import os
from pathlib import Path
import shutil
import sys
import time

from Backend.terminal_assistant.advisor import AdvisorError, OllamaAdvisor
from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.renderer import ConsoleRenderer, append_audit_event
from Backend.terminal_assistant.sanitizer import sanitize_terminal_text
from Backend.terminal_assistant.scope_guard import ScopeGuard
from Backend.terminal_assistant.sources import FollowFileSource


# ---------------------------------------------------------------------------
# Shared command-line options
# ---------------------------------------------------------------------------


def _scope_entries(args: argparse.Namespace) -> list[str]:
    """Combine repeated scope arguments with entries from a scope file."""

    entries = list(args.scope or [])
    if args.scope_file:
        path = Path(args.scope_file)
        entries.extend(path.read_text(encoding="utf-8").splitlines())
    return [entry.strip() for entry in entries if entry.strip() and not entry.startswith("#")]


def _add_scope_arguments(parser: argparse.ArgumentParser) -> None:
    """Add authorized-target options to a command parser."""

    parser.add_argument(
        "--scope",
        action="append",
        help="Authorized IP, CIDR, or domain. Repeat for multiple entries.",
    )
    parser.add_argument(
        "--scope-file",
        help="Text file containing one authorized scope entry per line.",
    )


def _add_realtime_arguments(parser: argparse.ArgumentParser) -> None:
    """Add realtime recommendation provider options."""

    parser.add_argument(
        "--provider",
        choices=("rules", "ollama"),
        default=os.getenv("PTAS_LLM_PROVIDER", "rules"),
        help="Realtime recommendation provider",
    )
    parser.add_argument("--model", help="Ollama model name for realtime recommendations")
    parser.add_argument("--ollama-url", help="Ollama base URL")
    parser.add_argument(
        "--allow-remote-llm",
        action="store_true",
        help="Allow sanitized evidence to leave localhost",
    )


def _add_advisor_arguments(parser: argparse.ArgumentParser) -> None:
    """Add recommendation options shared by analyze and watch."""

    parser.add_argument(
        "--target",
        action="append",
        help="Explicit observed target when it cannot be inferred from the command.",
    )
    parser.add_argument(
        "--provider",
        choices=("rules", "ollama"),
        default=os.getenv("PTAS_LLM_PROVIDER", "rules"),
    )
    parser.add_argument("--model", help="Ollama model name")
    parser.add_argument("--ollama-url", help="Ollama base URL")
    parser.add_argument(
        "--allow-remote-llm",
        action="store_true",
        help="Allow sanitized terminal excerpts to leave localhost",
    )


def _build_advisor(args: argparse.Namespace):
    """Create the optional Ollama advisor selected on the command line."""

    if args.provider == "rules":
        return None
    model = args.model or os.getenv("OLLAMA_MODEL", "")
    return OllamaAdvisor(
        model=model,
        base_url=args.ollama_url,
        allow_remote=args.allow_remote_llm,
    )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _analyze_command(args: argparse.Namespace) -> int:
    """Analyze one saved transcript and print safe recommendations."""

    try:
        guard = ScopeGuard(_scope_entries(args))
    except (OSError, ValueError) as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2

    if args.file == "-":
        raw_text = sys.stdin.read()
    else:
        raw_text = Path(args.file).read_text(encoding="utf-8", errors="replace")

    clean_text = sanitize_terminal_text(raw_text)
    result = TerminalAnalyzer(guard).analyze(
        clean_text,
        explicit_targets=args.target,
    )
    renderer = ConsoleRenderer()

    try:
        advisor = _build_advisor(args)
        if advisor and result.scope_allowed is not False:
            result.suggestions.extend(advisor.advise(result, clean_text))
    except (AdvisorError, ValueError) as exc:
        renderer.warning(str(exc))

    renderer.render(result)
    if args.audit_log:
        append_audit_event(Path(args.audit_log), result)
    return 1 if result.scope_allowed is False else 0


def _watch_command(args: argparse.Namespace) -> int:
    """Continuously analyze new text appended to a transcript."""

    try:
        guard = ScopeGuard(_scope_entries(args))
        source = FollowFileSource(Path(args.file), from_start=args.from_start)
        advisor = _build_advisor(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Startup error: {exc}", file=sys.stderr)
        return 2

    analyzer = TerminalAnalyzer(guard)
    renderer = ConsoleRenderer()
    renderer.status(f"Watching {args.file}; press Ctrl+C to stop")
    renderer.status("Read-only mode: PTAS will never execute a suggestion")

    recent_chunks: deque[str] = deque(maxlen=12)
    seen: deque[str] = deque(maxlen=200)
    last_command: str | None = None

    try:
        while True:
            chunk = source.read_new()
            if chunk:
                clean_chunk = sanitize_terminal_text(chunk)
                if clean_chunk.strip():
                    recent_chunks.append(clean_chunk)
                    context = "\n".join(recent_chunks)
                    detected_command = analyzer.extract_latest_command(context)
                    if detected_command:
                        last_command = detected_command
                    result = analyzer.analyze(
                        context,
                        context_command=last_command,
                        explicit_targets=args.target,
                    )

                    if result.command or result.findings:
                        fingerprint = result.fingerprint()
                        if fingerprint not in seen:
                            if advisor and result.scope_allowed is not False:
                                try:
                                    for suggestion in advisor.advise(result, context):
                                        if suggestion not in result.suggestions:
                                            result.suggestions.append(suggestion)
                                except AdvisorError as exc:
                                    renderer.warning(str(exc))
                            renderer.render(result)
                            seen.append(fingerprint)
                            if args.audit_log:
                                append_audit_event(Path(args.audit_log), result)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        renderer.status("Watcher stopped")
        return 0
    except (OSError, RuntimeError) as exc:
        renderer.warning(str(exc))
        return 1


def _doctor_command(_: argparse.Namespace) -> int:
    """Report whether PTAS's required and optional local tools are installed."""

    renderer = ConsoleRenderer()
    commands = {
        "python3": shutil.which("python3") or shutil.which("python"),
        "terminator": shutil.which("terminator"),
        "nmap": shutil.which("nmap"),
        "mariadb/mysql": shutil.which("mariadb") or shutil.which("mysql"),
        "ollama (optional)": shutil.which("ollama"),
        "whatweb (optional)": shutil.which("whatweb"),
        "nikto (optional)": shutil.which("nikto"),
        "gobuster (optional)": shutil.which("gobuster"),
        "sslscan (optional)": shutil.which("sslscan"),
        "enum4linux-ng (optional)": shutil.which("enum4linux-ng"),
        "dig (optional)": shutil.which("dig"),
        "searchsploit (optional)": shutil.which("searchsploit"),
        "mysqladmin (optional)": shutil.which("mysqladmin"),
        "pg_isready (optional)": shutil.which("pg_isready"),
        "redis-cli (optional)": shutil.which("redis-cli"),
        "VBoxManage (access-lab optional)": shutil.which("VBoxManage"),
        "vmrun (VMware access-lab optional)": shutil.which("vmrun"),
    }
    required_ok = True
    for name, path in commands.items():
        optional = "optional" in name
        state = f"OK ({path})" if path else ("optional" if optional else "MISSING")
        renderer.status(f"{name}: {state}")
        if not path and not optional:
            required_ok = False
    return 0 if required_ok else 1


def _start_command(args: argparse.Namespace) -> int:
    """Start the native split workspace or the requested plain interface."""

    from Backend.terminal_workflow import start_terminal_workflow

    return start_terminal_workflow(
        plain=args.plain,
        provider=args.provider,
        model=args.model,
        ollama_url=args.ollama_url,
        allow_remote_llm=args.allow_remote_llm,
    )


def _student_command(args: argparse.Namespace) -> int:
    """Run the internal left-pane student session."""

    from Backend.terminal_workflow import configure_realtime_advisor_env, run_student_session

    configure_realtime_advisor_env(
        args.provider,
        args.model,
        args.ollama_url,
        args.allow_remote_llm,
    )
    return run_student_session(Path(args.event_log) if args.event_log else None)


def _dashboard_command(args: argparse.Namespace) -> int:
    """Run the internal right-pane recommendation dashboard."""

    from Backend.terminal_workflow import configure_realtime_advisor_env, run_dashboard

    configure_realtime_advisor_env(
        args.provider,
        args.model,
        args.ollama_url,
        args.allow_remote_llm,
    )
    return run_dashboard(
        Path(args.event_log),
        interval=args.interval,
        transcript=Path(args.transcript),
    )


def _report_command(args: argparse.Namespace) -> int:
    """Save reports for a completed scan."""

    from Backend.terminal_workflow import save_report

    return save_report(args.scan_id, Path(args.output))


def _recommend_command(args: argparse.Namespace) -> int:
    """Display the next recommendation for a completed scan."""

    from Backend.terminal_workflow import next_recommendation

    return next_recommendation(
        args.scan_id,
        reset=args.reset,
        provider=args.provider,
        model=args.model,
        ollama_url=args.ollama_url,
        allow_remote_llm=args.allow_remote_llm,
        lab_name=args.lab,
    )


def _render_report_command(args: argparse.Namespace) -> int:
    """Convert an existing JSON report to HTML."""

    from Backend.terminal_workflow import render_existing_report

    return render_existing_report(
        Path(args.json_report),
        Path(args.output) if args.output else None,
    )


def _lab_register_command(args: argparse.Namespace) -> int:
    """Register an isolated training VM."""

    from Backend.terminal_workflow import register_metasploitable2_lab

    return register_metasploitable2_lab(
        args.name,
        args.target,
        args.vm,
        provider=args.provider,
        interface=args.interface,
        kali_source=args.kali_source,
    )


def _lab_check_command(args: argparse.Namespace) -> int:
    """Verify a registered training VM and its network isolation."""

    from Backend.terminal_workflow import check_metasploitable2_lab

    return check_metasploitable2_lab(args.name)


def _access_test_command(args: argparse.Namespace) -> int:
    """Show one gated exercise for a verified training lab."""

    from Backend.terminal_workflow import next_access_exercise

    return next_access_exercise(args.scan_id, args.lab, reset=args.reset)


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the complete ``ptas`` command tree."""

    parser = argparse.ArgumentParser(
        prog="ptas",
        description="PTAS native terminal workspace and transcript analysis tools",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser(
        "start",
        help="Open the native two-terminal PTAS workspace",
    )
    start_parser.add_argument(
        "--plain",
        action="store_true",
        help="Disable the split screen and use plain terminal output",
    )
    _add_realtime_arguments(start_parser)
    start_parser.set_defaults(func=_start_command)

    student_parser = subparsers.add_parser(
        "student",
        help="Run the internal student pane",
    )
    student_parser.add_argument("--event-log")
    _add_realtime_arguments(student_parser)
    student_parser.set_defaults(func=_student_command)

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Run the internal monitor pane",
    )
    dashboard_parser.add_argument("--event-log", required=True)
    dashboard_parser.add_argument("--transcript", required=True)
    dashboard_parser.add_argument("--interval", type=float, default=0.5)
    _add_realtime_arguments(dashboard_parser)
    dashboard_parser.set_defaults(func=_dashboard_command)

    report_parser = subparsers.add_parser(
        "report",
        help="Generate and save a completed scan report",
    )
    report_parser.add_argument("--scan-id", type=int, required=True)
    report_parser.add_argument("--output", required=True)
    report_parser.set_defaults(func=_report_command)

    recommend_parser = subparsers.add_parser(
        "recommend",
        help="Refresh and show the next realtime recommendation for a scan",
    )
    recommend_parser.add_argument("--scan-id", type=int, required=True)
    recommend_parser.add_argument(
        "--reset",
        action="store_true",
        help="Restart the recommendation sequence from the first item",
    )
    recommend_parser.add_argument(
        "--lab",
        help="Registered lab name used when the realtime advisor needs to stop at the access gate",
    )
    _add_realtime_arguments(recommend_parser)
    recommend_parser.set_defaults(func=_recommend_command)

    render_parser = subparsers.add_parser(
        "render-report",
        help="Convert an existing PTAS JSON report into standalone HTML",
    )
    render_parser.add_argument("json_report")
    render_parser.add_argument("--output", help="HTML output path")
    render_parser.set_defaults(func=_render_report_command)

    lab_register_parser = subparsers.add_parser(
        "lab-register",
        help="Register a host-only Metasploitable 2 lab",
    )
    lab_register_parser.add_argument("--name", required=True)
    lab_register_parser.add_argument("--target", required=True)
    lab_register_parser.add_argument(
        "--provider",
        choices=("virtualbox", "vmware"),
        default="virtualbox",
        help="VM platform used for the isolated lab",
    )
    lab_register_parser.add_argument(
        "--vm",
        required=True,
        help="VirtualBox VM name/UUID, or VMware .vmx path when --provider vmware",
    )
    lab_register_parser.add_argument(
        "--interface",
        default="vmnet1",
        help="Expected Kali interface for VMware host-only routing",
    )
    lab_register_parser.add_argument(
        "--kali-source",
        help="Expected Kali source IP for VMware host-only routing, for example 192.168.178.129",
    )
    lab_register_parser.set_defaults(func=_lab_register_command)

    lab_check_parser = subparsers.add_parser(
        "lab-check",
        help="Verify a registered Metasploitable 2 lab",
    )
    lab_check_parser.add_argument("--name", required=True)
    lab_check_parser.set_defaults(func=_lab_check_command)

    access_parser = subparsers.add_parser(
        "access-test",
        help="Show the next gated Metasploitable 2 access exercise",
    )
    access_parser.add_argument("--scan-id", type=int, required=True)
    access_parser.add_argument("--lab", required=True)
    access_parser.add_argument("--reset", action="store_true")
    access_parser.set_defaults(func=_access_test_command)

    doctor_parser = subparsers.add_parser("doctor", help="Check local tools")
    doctor_parser.set_defaults(func=_doctor_command)

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a saved terminal transcript"
    )
    analyze_parser.add_argument("file", help="Transcript path, or - for stdin")
    _add_scope_arguments(analyze_parser)
    _add_advisor_arguments(analyze_parser)
    analyze_parser.add_argument("--audit-log", help="Optional sanitized JSONL audit log")
    analyze_parser.set_defaults(func=_analyze_command)

    watch_parser = subparsers.add_parser(
        "watch", help="Watch a growing terminal transcript"
    )
    watch_parser.add_argument(
        "--file",
        required=True,
        help="Transcript written by script -f",
    )
    watch_parser.add_argument("--from-start", action="store_true")
    watch_parser.add_argument("--interval", type=float, default=1.0)
    watch_parser.add_argument("--audit-log", help="Optional sanitized JSONL audit log")
    _add_scope_arguments(watch_parser)
    _add_advisor_arguments(watch_parser)
    watch_parser.set_defaults(func=_watch_command)
    return parser


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> int:
    """Parse arguments and execute the selected command."""

    parser = build_parser()
    arguments = sys.argv[1:] or ["start"]
    args = parser.parse_args(arguments)
    if getattr(args, "interval", 1.0) <= 0:
        parser.error("--interval must be greater than zero")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
