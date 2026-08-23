"""Strict local-lab identity checks for opt-in access testing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess


class LabVerificationError(RuntimeError):
    """Encapsulate the LabVerificationError service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """
    pass


@dataclass(frozen=True)
class LabManifest:
    """Encapsulate the LabManifest service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """
    name: str
    profile: str
    provider: str
    vm_identifier: str
    vm_uuid: str
    target: str
    expected_mac: str
    network_mode: str
    created_at: str
    interface: str | None = None
    kali_source: str | None = None


@dataclass(frozen=True)
class AccessExercise:
    """Encapsulate the AccessExercise service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """
    key: str
    service: str
    port: int
    title: str
    purpose: str
    command: str
    credential_note: str


class Metasploitable2LabService:
    """Encapsulate the Metasploitable2LabService service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """
    PROFILE = "metasploitable2"
    EXPECTED_PORTS = {
        21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099,
        1524, 2049, 2121, 3306, 3632, 5432, 5900, 6000, 6667, 8009, 8180,
    }
    DISTINCTIVE_PORTS = {21, 23, 139, 445, 1524, 2121, 3306, 5432, 6667, 8180}

    def __init__(self, project_dir: Path):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.project_dir = project_dir.resolve()
        self.lab_dir = self.project_dir / ".ptas" / "labs"

    @staticmethod
    def _private_host(target: str) -> str:
        """Perform the service-level operation needed to private host.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        if "/" in target:
            raise LabVerificationError("Access testing requires one exact host, not a CIDR")
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise LabVerificationError("Access testing requires an exact private IP address") from exc
        if not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified:
            raise LabVerificationError("Access testing requires a non-loopback private lab IP")
        return str(address)

    @staticmethod
    def _normalize_mac(value: str) -> str:
        """Perform the service-level operation needed to normalize mac.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        compact = re.sub(r"[^0-9a-fA-F]", "", value).lower()
        if len(compact) != 12:
            raise LabVerificationError("VirtualBox did not return a valid VM MAC address")
        return ":".join(compact[index:index + 2] for index in range(0, 12, 2))

    @staticmethod
    def _machine_values(output: str) -> dict[str, str]:
        """Perform the service-level operation needed to machine values.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        values = {}
        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
        return values

    @staticmethod
    def _vmx_values(path: Path) -> dict[str, str]:
        """Perform the service-level operation needed to vmx values.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise LabVerificationError(f"Could not read VMware .vmx file: {exc}") from exc
        values = {}
        for line in lines:
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
        return values

    @staticmethod
    def _run(command: list[str], timeout: int = 20) -> str:
        """Perform the service-level operation needed to run.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LabVerificationError(f"Lab verification command failed: {exc}") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
            raise LabVerificationError(detail)
        return result.stdout

    def manifest_path(self, name: str) -> Path:
        """Perform the service-level operation needed to manifest path.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,50}", name):
            raise LabVerificationError("Lab name may contain only letters, numbers, _ and -")
        return self.lab_dir / f"{name}.json"

    def register_virtualbox(self, name: str, target: str, vm_identifier: str) -> LabManifest:
        """Perform the service-level operation needed to register virtualbox.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        target = self._private_host(target)
        executable = shutil.which("VBoxManage")
        if not executable:
            raise LabVerificationError("VBoxManage is not installed or not on PATH")
        values = self._machine_values(
            self._run([executable, "showvminfo", vm_identifier, "--machinereadable"])
        )
        hostonly_nics = [
            key.removeprefix("nic")
            for key, value in values.items()
            if key.startswith("nic") and key.removeprefix("nic").isdigit() and value == "hostonly"
        ]
        if not hostonly_nics:
            raise LabVerificationError("The VM must have a VirtualBox host-only network adapter")
        non_isolated_nics = [
            value
            for key, value in values.items()
            if key.startswith("nic")
            and key.removeprefix("nic").isdigit()
            and value not in {"none", "hostonly"}
        ]
        if non_isolated_nics:
            raise LabVerificationError(
                "Disable NAT, bridged, and other non-host-only VM adapters before registration"
            )
        nic_number = hostonly_nics[0]
        manifest = LabManifest(
            name=name,
            profile=self.PROFILE,
            provider="virtualbox",
            vm_identifier=vm_identifier,
            vm_uuid=values.get("UUID", ""),
            target=target,
            expected_mac=self._normalize_mac(values.get(f"macaddress{nic_number}", "")),
            network_mode="hostonly",
            created_at=datetime.now(UTC).isoformat(),
        )
        if not manifest.vm_uuid:
            raise LabVerificationError("VirtualBox did not return a VM UUID")
        path = self.manifest_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return manifest

    def _route_to_target(self, target: str) -> tuple[str | None, str | None]:
        """Perform the service-level operation needed to route to target.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        executable = shutil.which("ip")
        if not executable:
            raise LabVerificationError("The ip command is required for route verification")
        output = self._run([executable, "route", "get", target])
        dev_match = re.search(r"\bdev\s+(\S+)", output)
        src_match = re.search(r"\bsrc\s+(\S+)", output)
        return (
            dev_match.group(1) if dev_match else None,
            src_match.group(1) if src_match else None,
        )

    def register_vmware(
        self,
        name: str,
        target: str,
        vm_identifier: str,
        interface: str = "vmnet1",
        kali_source: str | None = None,
    ) -> LabManifest:
        """Perform the service-level operation needed to register vmware.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        target = self._private_host(target)
        vmx_path = Path(vm_identifier).expanduser().resolve()
        if vmx_path.suffix.lower() != ".vmx" or not vmx_path.is_file():
            raise LabVerificationError("VMware registration requires the Metasploitable 2 .vmx path")
        values = self._vmx_values(vmx_path)
        hostonly_nics = [
            key.removesuffix(".connectionType").removeprefix("ethernet")
            for key, value in values.items()
            if key.startswith("ethernet")
            and key.endswith(".connectionType")
            and value.lower() == "hostonly"
        ]
        if not hostonly_nics:
            raise LabVerificationError("The VM must have a VMware host-only network adapter")
        non_isolated_nics = [
            value
            for key, value in values.items()
            if key.startswith("ethernet")
            and key.endswith(".connectionType")
            and value.lower() not in {"hostonly"}
        ]
        if non_isolated_nics:
            raise LabVerificationError(
                "Disable NAT, bridged, and other non-host-only VMware adapters before registration"
            )
        nic_number = hostonly_nics[0]
        expected_mac = values.get(f"ethernet{nic_number}.generatedAddress") or values.get(
            f"ethernet{nic_number}.address", ""
        )
        route_interface, route_source = self._route_to_target(target)
        if route_interface != interface:
            raise LabVerificationError(
                f"Target route uses {route_interface or 'unknown'}, expected {interface}"
            )
        if kali_source and route_source != kali_source:
            raise LabVerificationError(
                f"Target route source is {route_source or 'unknown'}, expected {kali_source}"
            )
        manifest = LabManifest(
            name=name,
            profile=self.PROFILE,
            provider="vmware",
            vm_identifier=str(vmx_path),
            vm_uuid=values.get("uuid.bios") or values.get("uuid.location", ""),
            target=target,
            expected_mac=self._normalize_mac(expected_mac),
            network_mode="hostonly",
            created_at=datetime.now(UTC).isoformat(),
            interface=interface,
            kali_source=kali_source or route_source,
        )
        if not manifest.vm_uuid:
            raise LabVerificationError("VMware .vmx did not contain a VM UUID")
        self.verify_neighbor(manifest)
        path = self.manifest_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return manifest

    def load(self, name: str) -> LabManifest:
        """Perform the service-level operation needed to load.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        path = self.manifest_path(name)
        if not path.is_file():
            raise LabVerificationError(f"Lab manifest not found: {path}")
        try:
            return LabManifest(**json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise LabVerificationError(f"Invalid lab manifest: {exc}") from exc

    def verify_virtualbox(self, manifest: LabManifest) -> list[str]:
        """Perform the service-level operation needed to verify virtualbox.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        executable = shutil.which("VBoxManage")
        if not executable:
            raise LabVerificationError("VBoxManage is not installed or not on PATH")
        values = self._machine_values(
            self._run([executable, "showvminfo", manifest.vm_uuid, "--machinereadable"])
        )
        if values.get("UUID") != manifest.vm_uuid:
            raise LabVerificationError("VirtualBox VM UUID does not match the registered lab")
        non_isolated_nics = [
            value
            for key, value in values.items()
            if key.startswith("nic")
            and key.removeprefix("nic").isdigit()
            and value not in {"none", "hostonly"}
        ]
        if non_isolated_nics:
            raise LabVerificationError(
                "The registered VM has a non-host-only network adapter enabled"
            )
        matching_nic = False
        for key, value in values.items():
            number = key.removeprefix("nic")
            if not key.startswith("nic") or not number.isdigit() or value != "hostonly":
                continue
            current_mac = self._normalize_mac(values.get(f"macaddress{number}", ""))
            if current_mac == manifest.expected_mac:
                matching_nic = True
        if not matching_nic:
            raise LabVerificationError("Registered host-only adapter/MAC no longer matches")
        if values.get("VMState") != "running":
            raise LabVerificationError("The registered Metasploitable 2 VM is not running")
        snapshot_output = self._run(
            [executable, "snapshot", manifest.vm_uuid, "list", "--machinereadable"]
        )
        snapshots = re.findall(r'^SnapshotName(?:-\d+)?="([^"]+)"', snapshot_output, re.MULTILINE)
        if not snapshots:
            raise LabVerificationError("Create a clean VirtualBox snapshot before access testing")
        return snapshots

    def verify_vmware(self, manifest: LabManifest) -> list[str]:
        """Perform the service-level operation needed to verify vmware.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        vmx_path = Path(manifest.vm_identifier).expanduser().resolve()
        values = self._vmx_values(vmx_path)
        vm_uuid = values.get("uuid.bios") or values.get("uuid.location", "")
        if vm_uuid != manifest.vm_uuid:
            raise LabVerificationError("VMware VM UUID does not match the registered lab")
        non_isolated_nics = [
            value
            for key, value in values.items()
            if key.startswith("ethernet")
            and key.endswith(".connectionType")
            and value.lower() not in {"hostonly"}
        ]
        if non_isolated_nics:
            raise LabVerificationError(
                "The registered VM has a non-host-only network adapter enabled"
            )
        matching_nic = False
        for key, value in values.items():
            if not key.startswith("ethernet") or not key.endswith(".connectionType"):
                continue
            if value.lower() != "hostonly":
                continue
            number = key.removesuffix(".connectionType").removeprefix("ethernet")
            current_mac = values.get(f"ethernet{number}.generatedAddress") or values.get(
                f"ethernet{number}.address", ""
            )
            if self._normalize_mac(current_mac) == manifest.expected_mac:
                matching_nic = True
        if not matching_nic:
            raise LabVerificationError("Registered VMware host-only adapter/MAC no longer matches")
        route_interface, route_source = self._route_to_target(manifest.target)
        if manifest.interface and route_interface != manifest.interface:
            raise LabVerificationError(
                f"Target route uses {route_interface or 'unknown'}, expected {manifest.interface}"
            )
        if manifest.kali_source and route_source != manifest.kali_source:
            raise LabVerificationError(
                f"Target route source is {route_source or 'unknown'}, expected {manifest.kali_source}"
            )
        executable = shutil.which("vmrun")
        if not executable:
            raise LabVerificationError("vmrun is required for VMware runtime verification")
        running = self._run([executable, "list"])
        if str(vmx_path) not in running:
            raise LabVerificationError("The registered Metasploitable 2 VMware VM is not running")
        snapshot_output = self._run([executable, "listSnapshots", str(vmx_path)])
        snapshots = [
            line.strip()
            for line in snapshot_output.splitlines()[1:]
            if line.strip()
        ]
        if not snapshots:
            raise LabVerificationError("Create a clean VMware snapshot before access testing")
        return snapshots

    def verify_runtime(self, manifest: LabManifest) -> list[str]:
        """Perform the service-level operation needed to verify runtime.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        if manifest.provider == "virtualbox":
            return self.verify_virtualbox(manifest)
        if manifest.provider == "vmware":
            return self.verify_vmware(manifest)
        raise LabVerificationError("Only registered VirtualBox or VMware Metasploitable 2 labs are allowed")

    def verify_neighbor(self, manifest: LabManifest) -> None:
        """Perform the service-level operation needed to verify neighbor.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        executable = shutil.which("ip")
        if not executable:
            raise LabVerificationError("The ip command is required for MAC verification")
        output = self._run([executable, "neigh", "show", manifest.target])
        match = re.search(r"\blladdr\s+([0-9a-fA-F:.-]+)", output)
        if not match:
            raise LabVerificationError("No neighbor MAC found; ping or scan the registered VM first")
        if self._normalize_mac(match.group(1)) != manifest.expected_mac:
            raise LabVerificationError("Target IP resolves to a different MAC than the registered VM")

    def verify_scan(self, manifest: LabManifest, scan, findings: list) -> set[int]:
        """Perform the service-level operation needed to verify scan.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        if manifest.profile != self.PROFILE or manifest.provider not in {"virtualbox", "vmware"}:
            raise LabVerificationError("Only the registered Metasploitable 2 lab profile is allowed")
        if scan.target.target_value != manifest.target:
            raise LabVerificationError("Scan target does not match the registered lab IP")
        ports = {int(item.port) for item in findings if item.port is not None}
        expected = ports & self.EXPECTED_PORTS
        distinctive = ports & self.DISTINCTIVE_PORTS
        if len(expected) < 5 or len(distinctive) < 2:
            raise LabVerificationError(
                "Scan fingerprint is not sufficiently consistent with Metasploitable 2"
            )
        return ports

    @staticmethod
    def exercises(target: str, ports: set[int]) -> list[AccessExercise]:
        """Perform the service-level operation needed to exercises.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        catalog = [
            AccessExercise(
                "ssh_training_login", "SSH", 22,
                "Authenticated SSH training login",
                "Validate access using the documented Metasploitable 2 student account.",
                f"ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password msfadmin@{target}",
                "Enter the documented training password interactively; PTAS does not store it.",
            ),
            AccessExercise(
                "ftp_training_login", "FTP", 21,
                "Authenticated FTP training login",
                "Validate access to the intentionally vulnerable FTP service.",
                f"ftp {target}",
                "Enter the documented training username and password interactively.",
            ),
            AccessExercise(
                "telnet_training_login", "Telnet", 23,
                "Authenticated Telnet training login",
                "Demonstrate why clear-text remote administration is unsafe.",
                f"telnet {target}",
                "Use only the documented Metasploitable 2 training account.",
            ),
            AccessExercise(
                "smb_training_login", "SMB", 445,
                "Authenticated SMB share listing",
                "Validate authorized SMB access without modifying files.",
                f"smbclient -L //{target} -U msfadmin",
                "Enter the documented training password interactively.",
            ),
            AccessExercise(
                "mysql_training_login", "MySQL", 3306,
                "Interactive MySQL authentication test",
                "Validate database access with a separately approved training credential.",
                f"mysql --host {target} --port 3306 --user root --password",
                "Supply the lab credential interactively; do not place it in the command.",
            ),
            AccessExercise(
                "postgres_training_login", "PostgreSQL", 5432,
                "Interactive PostgreSQL authentication test",
                "Validate database access with a separately approved training credential.",
                f"psql --host {target} --port 5432 --username postgres",
                "Supply the lab credential interactively; do not place it in the command.",
            ),
        ]
        return [exercise for exercise in catalog if exercise.port in ports]
