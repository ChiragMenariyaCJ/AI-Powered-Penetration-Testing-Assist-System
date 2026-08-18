"""Local, read-only terminal sidecar for PTAS."""

from Backend.terminal_assistant.analyzer import TerminalAnalyzer
from Backend.terminal_assistant.scope_guard import ScopeGuard

__all__ = ["ScopeGuard", "TerminalAnalyzer"]
