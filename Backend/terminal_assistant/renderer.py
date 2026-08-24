"""Render analysis results and optional sanitized audit events."""

import json
import os
from pathlib import Path
import sys

from Backend.terminal_assistant.models import AnalysisResult


class ConsoleRenderer:
    """Represent or coordinate ConsoleRenderer in the terminal guidance pipeline.

    The assistant analyzes evidence but never automatically executes its
    recommendations.
    """
    # Enable or disable ANSI colour according to terminal support or caller preference.
    def __init__(self):
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    # Wrap terminal text in an ANSI colour only when colour output is enabled.
    def _paint(self, code: str, text: str) -> str:
        """Perform the paint step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        return f"\033[{code}m{text}\033[0m" if self.color else text

    # Print an informational PTAS status line to the recommendation terminal.
    def status(self, message: str) -> None:
        """Perform the status step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        print(self._paint("36", f"[PTAS] {message}"), flush=True)

    # Print a visually distinct warning without interrupting the monitoring loop.
    def warning(self, message: str) -> None:
        """Perform the warning step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        print(self._paint("33", f"[PTAS] {message}"), flush=True)

    # Display command, scope, findings, analysis, and suggestions from one analysis result.
    def render(self, result: AnalysisResult) -> None:
        """Perform the render step of the terminal guidance pipeline.

        The operation works with sanitized evidence and does not execute a recommended
        security command.
        """
        print()
        print(self._paint("1;36", "PTAS terminal observation"))
        if result.command:
            print(f"Command: {result.command}")
        if result.targets:
            print(f"Targets: {', '.join(result.targets)}")

        if result.scope_allowed is False:
            scope_text = self._paint(
                "1;31", f"BLOCKED ({', '.join(result.blocked_targets)})"
            )
        elif result.scope_allowed is True:
            scope_text = self._paint("32", "authorized")
        else:
            scope_text = self._paint("33", "target not recognized")
        print(f"Scope: {scope_text}")

        if result.findings:
            print("Findings:")
            for finding in result.findings[:12]:
                print(f"  [{finding.severity}] {finding.summary} — {finding.evidence}")

        if result.suggestions:
            print("Suggestions:")
            for index, suggestion in enumerate(result.suggestions[:8], start=1):
                print(f"  {index}. {suggestion}")
        print(flush=True)


# Append one timestamped analysis result as JSON to the optional audit log.
def append_audit_event(path: Path, result: AnalysisResult) -> None:
    """Perform the append audit event step of the terminal guidance pipeline.

    The operation works with sanitized evidence and does not execute a recommended
    security command.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result.to_dict(), sort_keys=True, default=str))
        handle.write("\n")
