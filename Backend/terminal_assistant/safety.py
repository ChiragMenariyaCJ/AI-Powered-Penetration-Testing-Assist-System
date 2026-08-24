"""Filter model output to non-destructive, explicitly scoped guidance."""

from __future__ import annotations

import re
import shlex

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
SAFE_NMAP_SCRIPTS = {
    "banner",
    "dns-nsid",
    "ftp-syst",
    "http-headers",
    "http-title",
    "mysql-info",
    "nbstat",
    "smb-protocols",
    "smb-security-mode",
    "smb2-capabilities",
    "smb2-time",
    "smtp-commands",
    "ssh-hostkey",
    "ssh2-enum-algos",
    "ssl-cert",
    "ssl-enum-ciphers",
    "telnet-encryption",
}
# Scripts in this map only make sense on their corresponding service ports.
# ``banner`` and the TLS scripts are intentionally omitted because they can
# provide useful metadata on many non-standard ports.
NMAP_SCRIPT_PORTS = {
    "dns-nsid": {53},
    "ftp-syst": {21, 2121},
    "http-headers": {80, 443, 8000, 8080, 8443},
    "http-title": {80, 443, 8000, 8080, 8443},
    "mysql-info": {3306},
    "nbstat": {137, 139},
    "smb-protocols": {139, 445},
    "smb-security-mode": {139, 445},
    "smb2-capabilities": {139, 445},
    "smb2-time": {139, 445},
    "smtp-commands": {25, 465, 587},
    "ssh-hostkey": {22},
    "ssh2-enum-algos": {22},
    "telnet-encryption": {23, 2323},
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
SHELL_CONTROL_SYNTAX = re.compile(r"(?:[;&|`<>]|\$\(|\r|\n)")


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


def manual_command_rejection_reason(
    command: str,
    authorized_targets: list[str],
) -> str | None:
    """Explain why an LLM-produced command cannot be shown as runnable.

    Model text is treated as untrusted input. A runnable recommendation must be
    one simple allowlisted command, contain an explicit in-scope target, and
    pass the existing destructive-content checks. Shell composition is rejected
    so a safe first command cannot hide a second operation after a pipe or
    separator. Returning a short reason also lets the terminal explain a model
    fallback without printing the rejected command itself.
    """

    value = command.strip()
    if not value:
        return "the model returned an empty command"
    if SHELL_CONTROL_SYNTAX.search(value):
        return "the command contained shell chaining or redirection"
    try:
        parts = shlex.split(value)
    except ValueError:
        return "the command contained invalid shell quoting"
    if parts and parts[0].lower() == "sudo":
        parts = parts[1:]
    if not parts:
        return "the command did not contain a tool"
    tool = parts[0].rsplit("/", 1)[-1].lower()
    if tool not in SAFE_METADATA_TOOLS:
        return f"the tool '{tool}' is not in the manual validation allowlist"
    arguments = parts[1:]
    lowered_parts = [part.lower() for part in arguments]
    if tool == "curl":
        state_changing_curl = {
            "--data",
            "--data-ascii",
            "--data-binary",
            "--data-raw",
            "--form",
            "--upload-file",
        }
        if any(
            original in {"-d", "-F", "-T"} or lowered in state_changing_curl
            for original, lowered in zip(arguments, lowered_parts)
        ):
            return "the curl command could change or upload data"
        for index, part in enumerate(arguments[:-1]):
            if part == "-X" or part.lower() == "--request":
                if lowered_parts[index + 1] in {
                    "get",
                    "head",
                }:
                    continue
                return "the curl command used a state-changing request method"
    if tool == "nmap":
        selected_ports: set[int] = set()
        for index, part in enumerate(lowered_parts):
            port_value = None
            if part in {"-p", "--ports"} and index + 1 < len(lowered_parts):
                port_value = lowered_parts[index + 1]
            elif part.startswith("-p") and len(part) > 2:
                port_value = part[2:]
            if port_value:
                selected_ports.update(
                    int(item)
                    for item in port_value.split(",")
                    if item.isdigit()
                )
        for index, part in enumerate(lowered_parts):
            script_value = None
            if part == "--script" and index + 1 < len(lowered_parts):
                script_value = lowered_parts[index + 1]
            elif part.startswith("--script="):
                script_value = part.split("=", 1)[1]
            if script_value is not None:
                scripts = {item.strip() for item in script_value.split(",") if item.strip()}
                if not scripts or not scripts.issubset(SAFE_NMAP_SCRIPTS):
                    rejected = sorted(scripts - SAFE_NMAP_SCRIPTS)
                    detail = ", ".join(rejected) if rejected else "an empty selection"
                    return f"the Nmap script selection was not allowlisted: {detail}"
                for script in sorted(scripts):
                    expected_ports = NMAP_SCRIPT_PORTS.get(script)
                    if expected_ports and not selected_ports.intersection(expected_ports):
                        chosen = ", ".join(str(port) for port in sorted(selected_ports))
                        return (
                            f"the Nmap script '{script}' does not match the selected "
                            f"service port{f' {chosen}' if chosen else ''}"
                        )
    observed_targets = ScopeGuard.extract_targets(value)
    if not observed_targets:
        return "the command did not explicitly contain the authorized target"
    try:
        decision = ScopeGuard(authorized_targets).check(observed_targets)
    except ValueError:
        return "the authorized scope configuration could not be validated"
    if not decision.allowed:
        return "the command contained a target outside the authorized scope"
    if not is_safe_recommendation(value, authorized_targets):
        return "the command did not pass the non-destructive safety policy"
    return None


def is_safe_manual_command(command: str, authorized_targets: list[str]) -> bool:
    """Return whether a model command passes every manual-command guard."""

    return manual_command_rejection_reason(command, authorized_targets) is None
