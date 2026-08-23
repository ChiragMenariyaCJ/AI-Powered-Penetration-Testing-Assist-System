"""Local, read-only transcript analysis used by the PTAS recommendation pane."""

from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.scope_guard import ScopeGuard

__all__ = ["ScopeGuard", "TerminalAnalyzer"]
