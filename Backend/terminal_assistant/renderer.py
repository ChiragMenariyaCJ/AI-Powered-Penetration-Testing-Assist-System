"""Render analysis results and optional sanitized audit events."""

import json
import os
from pathlib import Path
import sys

from Backend.terminal_assistant.models import AnalysisResult


class ConsoleRenderer:
    def __init__(self):
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def _paint(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def status(self, message: str) -> None:
        print(self._paint("36", f"[PTAS] {message}"), flush=True)

    def warning(self, message: str) -> None:
        print(self._paint("33", f"[PTAS] {message}"), flush=True)

    def render(self, result: AnalysisResult) -> None:
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


def append_audit_event(path: Path, result: AnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result.to_dict(), sort_keys=True, default=str))
        handle.write("\n")
