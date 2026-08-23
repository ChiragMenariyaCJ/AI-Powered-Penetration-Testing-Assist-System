"""Launch PTAS as two genuine terminal panes without tmux.

Inside QTerminal, PTAS invokes its native left/right split action over D-Bus.
Terminator provides the same two-VTE layout as a fallback. The left terminal
runs the student workflow and then becomes the student's normal shell. The
right terminal runs the read-only recommendation dashboard. A ``script``
transcript lets the dashboard observe new left-terminal output without trying
to emulate terminal input or requiring tmux.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time


class NativeTerminalError(RuntimeError):
    """Raised when the native split-terminal window cannot be started."""


# ---------------------------------------------------------------------------
# QTerminal: split the current window into two native terminal panes
# ---------------------------------------------------------------------------


def _gvariant_string(value: str) -> str:
    """Escape one string for QTerminal's D-Bus argument map."""

    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def qterminal_argument_map(project_dir: Path, command: list[str]) -> str:
    """Serialize QTerminal's ``a{sv}`` split-terminal argument map."""

    shell = ", ".join(_gvariant_string(value) for value in command)
    return (
        "{'workingDirectory': <"
        + _gvariant_string(str(project_dir))
        + ">, 'shell': <["
        + shell
        + "]>}"
    )


def split_qterminal_recommendations(
    service: str,
    terminal_object: str,
    project_dir: Path,
    dashboard_command: list[str],
) -> int:
    """Use QTerminal's native Actions → Split View Left-Right operation."""

    if not re.fullmatch(r"org\.lxqt\.QTerminal(?:-\d+)?", service):
        raise NativeTerminalError("The QTerminal D-Bus service name is invalid")
    if not re.fullmatch(r"/terminals/[A-Fa-f0-9]+", terminal_object):
        raise NativeTerminalError("The QTerminal terminal object path is invalid")
    executable = shutil.which("gdbus")
    if not executable:
        raise NativeTerminalError("gdbus is required for QTerminal split view")

    result = subprocess.run(
        [
            executable,
            "call",
            "--session",
            "--dest",
            service,
            "--object-path",
            terminal_object,
            "--method",
            # QTerminal's D-Bus implementation passes splitHorizontal to a
            # Qt::Horizontal splitter, which produces the left/right layout.
            "org.lxqt.QTerminal.Terminal.splitHorizontal",
            qterminal_argument_map(project_dir, dashboard_command),
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown D-Bus error"
        raise NativeTerminalError(f"QTerminal could not create the right pane: {detail}")

    # QTerminal focuses the newly created pane. On X11, use QTerminal's normal
    # Alt+Left navigation shortcut so the student can type immediately in the
    # original left terminal. This is best-effort (Wayland may block xdotool).
    focus_tool = shutil.which("xdotool") if os.getenv("DISPLAY") else None
    if focus_tool:
        subprocess.run(
            [focus_tool, "key", "--clearmodifiers", "alt+Left"],
            capture_output=True,
            timeout=2,
        )
    return 0


# ---------------------------------------------------------------------------
# Student shell: record output while preserving normal terminal behavior
# ---------------------------------------------------------------------------


def run_recorded_shell(project_dir: Path, transcript: Path, login_shell: str) -> int:
    """Run a normal interactive shell while flushing output for the dashboard."""

    script = shutil.which("script")
    if not script:
        return subprocess.run([login_shell, "-l"], cwd=project_dir).returncode
    command = f"exec {shlex.quote(login_shell)} -l"
    return subprocess.run(
        [script, "-q", "-f", "-a", "-c", command, str(transcript)],
        cwd=project_dir,
    ).returncode


# ---------------------------------------------------------------------------
# Terminator fallback: create one window containing two real terminals
# ---------------------------------------------------------------------------


def build_terminator_layout(
    project_dir: Path,
    event_log: Path,
    transcript: Path,
    realtime_prefix: str = "",
    login_shell: str = "/bin/bash",
) -> dict:
    """Build a two-pane Terminator JSON layout."""

    launcher = project_dir / "ptas.sh"
    quoted_project = shlex.quote(str(project_dir))
    quoted_launcher = shlex.quote(str(launcher))
    quoted_event_log = shlex.quote(str(event_log))
    quoted_transcript = shlex.quote(str(transcript))
    quoted_shell = shlex.quote(login_shell)

    student_session = (
        f"cd {quoted_project} && "
        f"{realtime_prefix}{quoted_launcher} student --event-log {quoted_event_log}; "
        f"exec {quoted_shell} -l"
    )
    student_command = (
        "script -q -f "
        f"-c {shlex.quote(student_session)} {quoted_transcript}"
    )
    dashboard_command = (
        f"cd {quoted_project} && "
        f"{realtime_prefix}{quoted_launcher} dashboard "
        f"--event-log {quoted_event_log} --transcript {quoted_transcript}; "
        f"exec {quoted_shell} -l"
    )

    return {
        "layout": {
            # Terminator calls an HPaned (left/right) layout non-vertical.
            "vertical": False,
            "ptas": [
                {
                    "title": "PTAS Student Terminal",
                    "command": student_command,
                    "ratio": 0.62,
                },
                {
                    "title": "PTAS Recommendations",
                    "command": dashboard_command,
                },
            ],
        }
    }


def launch_split_terminals(
    project_dir: Path,
    event_log: Path,
    transcript: Path,
    layout_path: Path,
    realtime_prefix: str = "",
    login_shell: str = "/bin/bash",
) -> int:
    """Open a maximized native Terminator window with two real terminals."""

    executable = shutil.which("terminator")
    if not executable:
        raise NativeTerminalError(
            "Terminator is not installed. Install it with: sudo apt install terminator"
        )

    event_log.parent.mkdir(parents=True, exist_ok=True)
    transcript.touch(exist_ok=True)
    layout = build_terminator_layout(
        project_dir,
        event_log,
        transcript,
        realtime_prefix,
        login_shell,
    )
    layout_path.write_text(json.dumps(layout, indent=2) + "\n", encoding="utf-8")

    process = subprocess.Popen(
        [
            executable,
            "--no-dbus",
            "--maximise",
            "--title",
            "PTAS Student Workspace",
            "--config-json",
            str(layout_path),
        ],
        cwd=project_dir,
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Catch immediate display/configuration failures without waiting for the GUI.
    time.sleep(0.2)
    result = process.poll()
    if result not in {None, 0}:
        raise NativeTerminalError(
            f"Terminator exited before opening the PTAS workspace (status {result})"
        )
    return 0
