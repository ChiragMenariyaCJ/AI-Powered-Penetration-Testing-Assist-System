"""Filter model output to non-destructive, explicitly scoped guidance."""

from __future__ import annotations

import re

from Backend.terminal_assistant.scope_guard import ScopeGuard


SAFE_METADATA_TOOLS = {
    "curl",
    "dig",
    "enum4linux-ng",
    "nmap",
    "pg_isready",
    "sslscan",
    "whatweb",
}

FORBIDDEN_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:hydra|medusa|ncrack|crowbar|john|hashcat)\b",
        r"\b(?:msfconsole|meterpreter|msfvenom|shellcode|payload)\b",
        r"\b(?:reverse\s+shell|bind\s+shell|backdoor)\b",
        r"\b(?:persistence|persist|autorun|rc\.local)\b",
        r"\b(?:pivot|proxychains|pass-the-hash|relay)\b",
        r"\b(?:dos|ddos|denial[-\s]+of[-\s]+service|flood|slowloris|hping3)\b",
        r"\b(?:exploit|exploitation|exploiting|weaponize)\b",
        r"\b(?:drop\s+table|delete\s+from|truncate\s+table|rm\s+-rf)\b",
        r"\b(?:ssh|telnet|ftp|mysql|psql|smbclient)\s+[^;\n]*@",
    )
)


def is_safe_recommendation(text: str, authorized_targets: list[str] | None = None) -> bool:
    """Perform the is safe recommendation step of the terminal guidance pipeline.

    The operation works with sanitized evidence and does not execute a recommended
    security command.
    """
    value = " ".join(text.split())
    if not value:
        return False
    if any(pattern.search(value) for pattern in FORBIDDEN_PATTERNS):
        return False

    if authorized_targets:
        observed_targets = ScopeGuard.extract_targets(value)
        if observed_targets:
            try:
                decision = ScopeGuard(authorized_targets).check(observed_targets)
            except ValueError:
                return False
            if not decision.allowed:
                return False

    command_match = re.match(r"^(?:run\s+)?(?:sudo\s+)?(?P<tool>[a-z0-9_.+-]+)\b", value, re.I)
    if command_match:
        tool = command_match.group("tool").lower()
        if tool in {"run", "review", "record", "confirm", "compare", "document", "stop", "use"}:
            return True
        if tool not in SAFE_METADATA_TOOLS:
            return False
        lowered = value.lower()
        if "--script" in lowered and any(marker in lowered for marker in ("vuln", "dos", "exploit")):
            return False
    return True


def filter_safe_recommendations(
    suggestions: list[str],
    authorized_targets: list[str] | None = None,
    limit: int = 5,
) -> list[str]:
    """Perform the filter safe recommendations step of the terminal guidance pipeline.

    The operation works with sanitized evidence and does not execute a recommended
    security command.
    """
    filtered: list[str] = []
    for suggestion in suggestions:
        cleaned = " ".join(suggestion.strip().split())
        if not cleaned or cleaned in filtered:
            continue
        if not is_safe_recommendation(cleaned, authorized_targets):
            continue
        filtered.append(cleaned)
        if len(filtered) >= limit:
            break
    return filtered
