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
    pass


@dataclass(frozen=True)
class LabManifest:
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
    key: str
    service: str
    port: int
    title: str
    purpose: str
    command: str
    credential_note: str


class Metasploitable2LabService:
    PROFILE = "metasploitable2"
    EXPECTED_PORTS = {
        21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099,
        1524, 2049, 2121, 3306, 3632, 5432, 5900, 6000, 6667, 8009, 8180,
    }
    DISTINCTIVE_PORTS = {21, 23, 139, 445, 1524, 2121, 3306, 5432, 6667, 8180}
    VMWARE_MAC_PREFIXES = {"00:05:69", "00:0c:29", "00:1c:14", "00:50:56"}

    # Store the project path and location used for isolated-lab identity manifests.
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir.resolve()
        self.lab_dir = self.project_dir / ".ptas" / "labs"

    # Require one non-loopback private IP before any access-testing lab can be registered.
    @staticmethod
    def _private_host(target: str) -> str:
        if "/" in target:
            raise LabVerificationError("Access testing requires one exact host, not a CIDR")
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise LabVerificationError("Access testing requires an exact private IP address") from exc
        if not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified:
            raise LabVerificationError("Access testing requires a non-loopback private lab IP")
        return str(address)

    # Normalise a virtual-machine MAC address into lowercase colon-separated notation.
    @staticmethod
    def _normalize_mac(value: str) -> str:
        compact = re.sub(r"[^0-9a-fA-F]", "", value).lower()
        if len(compact) != 12:
            raise LabVerificationError("VirtualBox did not return a valid VM MAC address")
        return ":".join(compact[index:index + 2] for index in range(0, 12, 2))

    # Parse VirtualBox machine-readable key/value output into a dictionary.
    @staticmethod
    def _machine_values(output: str) -> dict[str, str]:
        values = {}
        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"')
        return values

    # Read a VMware VMX file and parse its quoted configuration values.
    @staticmethod
    def _vmx_values(path: Path) -> dict[str, str]:
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

    # Run one bounded lab-verification command and convert failures into clear verification errors.
    @staticmethod
    def _run(command: list[str], timeout: int = 20) -> str:
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

    # Validate a lab name before mapping it to its JSON manifest path.
    def manifest_path(self, name: str) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,50}", name):
            raise LabVerificationError("Lab name may contain only letters, numbers, _ and -")
        return self.lab_dir / f"{name}.json"

    # Verify a host-only VirtualBox VM and save its exact identity as a lab manifest.
    def register_virtualbox(self, name: str, target: str, vm_identifier: str) -> LabManifest:
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
        # Bind the manifest to the exact host-only adapter instead of trusting only the target IP.
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
        # Replace a temporary file atomically so an interrupted write cannot leave partial JSON.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return manifest

    # Read the interface and source IP Linux would use to reach the lab target.
    def _route_to_target(self, target: str) -> tuple[str | None, str | None]:
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

    # Return the interface Kali uses for its default/internet route.
    def _default_route_interface(self) -> str | None:
        """Return the interface Kali uses for its default/internet route."""

        executable = shutil.which("ip")
        if not executable:
            raise LabVerificationError("The ip command is required for route verification")
        output = self._run([executable, "route", "show", "default"])
        match = re.search(r"\bdev\s+(\S+)", output)
        return match.group(1) if match else None

    # Read and normalize the MAC currently associated with a target IP.
    def _neighbor_mac(self, target: str) -> str:
        """Read and normalize the MAC currently associated with a target IP."""

        executable = shutil.which("ip")
        if not executable:
            raise LabVerificationError("The ip command is required for MAC verification")
        output = self._run([executable, "neigh", "show", target])
        match = re.search(r"\blladdr\s+([0-9a-fA-F:.-]+)", output)
        if not match:
            raise LabVerificationError(
                "No neighbor MAC found; ping or scan the Metasploitable IP first"
            )
        return self._normalize_mac(match.group(1))

    # Verify a host-only VMware VMX definition and save its exact identity.
    def register_vmware(
        self,
        name: str,
        target: str,
        vm_identifier: str,
        interface: str = "vmnet1",
        kali_source: str | None = None,
    ) -> LabManifest:
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
        # VMware may store a generated or manually assigned MAC; accept either identity field.
        nic_number = hostonly_nics[0]
        expected_mac = values.get(f"ethernet{nic_number}.generatedAddress") or values.get(
            f"ethernet{nic_number}.address", ""
        )
        # Prove Kali reaches the target over the expected lab interface before saving the manifest.
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
        # Write then replace so the registered identity is never left half-written.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return manifest

    # Register a VMware lab from inside a Kali guest using network identity.
    def register_vmware_network(
        self,
        name: str,
        target: str,
        interface: str | None = None,
        kali_source: str | None = None,
    ) -> LabManifest:
        """Register a VMware lab from inside a Kali guest using network identity.

        Kali normally cannot read the physical host's ``.vmx`` file. This mode
        therefore pins the exact private IP, isolated non-default route,
        interface, Kali source address, and VMware-owned neighbor MAC. The scan
        fingerprint and explicit access confirmation remain required later.
        """

        target = self._private_host(target)
        route_interface, route_source = self._route_to_target(target)
        if not route_interface or not route_source:
            raise LabVerificationError(
                "Could not determine the Kali route and source address for the target"
            )
        if interface and route_interface != interface:
            raise LabVerificationError(
                f"Target route uses {route_interface}, expected {interface}"
            )
        if kali_source and route_source != kali_source:
            raise LabVerificationError(
                f"Target route source is {route_source}, expected {kali_source}"
            )
        # Refuse Kali's internet/default route because this mode must remain on an isolated adapter.
        default_interface = self._default_route_interface()
        if default_interface and route_interface == default_interface:
            raise LabVerificationError(
                "The target uses Kali's default network interface; configure a separate "
                "VMware host-only adapter before registration"
            )
        # Pin the current neighbour MAC and require a VMware-owned prefix as a second identity signal.
        expected_mac = self._neighbor_mac(target)
        if expected_mac[:8] not in self.VMWARE_MAC_PREFIXES:
            raise LabVerificationError(
                f"Target MAC {expected_mac} does not use a recognized VMware prefix"
            )
        manifest = LabManifest(
            name=name,
            profile=self.PROFILE,
            provider="vmware-network",
            vm_identifier=f"{route_interface}:{target}",
            vm_uuid=f"network-mac:{expected_mac}",
            target=target,
            expected_mac=expected_mac,
            network_mode="isolated-private-route",
            created_at=datetime.now(UTC).isoformat(),
            interface=route_interface,
            kali_source=route_source,
        )
        path = self.manifest_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Persist the network identity atomically for later revalidation before access exercises.
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
        return manifest

    # Load and validate a previously registered lab manifest from disk.
    def load(self, name: str) -> LabManifest:
        path = self.manifest_path(name)
        if not path.is_file():
            raise LabVerificationError(f"Lab manifest not found: {path}")
        try:
            return LabManifest(**json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise LabVerificationError(f"Invalid lab manifest: {exc}") from exc

    # Confirm the current VirtualBox VM still matches its saved UUID, MAC, and isolation mode.
    def verify_virtualbox(self, manifest: LabManifest) -> list[str]:
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

    # Confirm the current VMware VM still matches its saved VMX identity and isolation mode.
    def verify_vmware(self, manifest: LabManifest) -> list[str]:
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

    # Confirm the target route and local interface still match the registered isolated lab.
    def verify_runtime(self, manifest: LabManifest) -> list[str]:
        # Provider-specific checks prove that the saved VM identity is still the active target.
        if manifest.provider == "virtualbox":
            return self.verify_virtualbox(manifest)
        if manifest.provider == "vmware":
            return self.verify_vmware(manifest)
        if manifest.provider == "vmware-network":
            target = self._private_host(manifest.target)
            route_interface, route_source = self._route_to_target(target)
            if route_interface != manifest.interface:
                raise LabVerificationError(
                    "Target route no longer uses the registered isolated interface"
                )
            if manifest.kali_source and route_source != manifest.kali_source:
                raise LabVerificationError(
                    "Kali source address no longer matches the registered lab"
                )
            default_interface = self._default_route_interface()
            if default_interface and route_interface == default_interface:
                raise LabVerificationError(
                    "Target route now uses Kali's default network interface"
                )
            self.verify_neighbor(manifest)
            return ["network identity baseline (snapshot managed on VMware host)"]
        raise LabVerificationError(
            "Only registered VirtualBox or VMware Metasploitable 2 labs are allowed"
        )

    # Confirm the target neighbour MAC still matches the registered virtual-machine identity.
    def verify_neighbor(self, manifest: LabManifest) -> None:
        if self._neighbor_mac(manifest.target) != manifest.expected_mac:
            raise LabVerificationError("Target IP resolves to a different MAC than the registered VM")

    # Require the scan target and distinctive open ports to match the Metasploitable 2 profile.
    def verify_scan(self, manifest: LabManifest, scan, findings: list) -> set[int]:
        if manifest.profile != self.PROFILE or manifest.provider not in {
            "virtualbox",
            "vmware",
            "vmware-network",
        }:
            raise LabVerificationError("Only the registered Metasploitable 2 lab profile is allowed")
        if scan.target.target_value != manifest.target:
            raise LabVerificationError("Scan target does not match the registered lab IP")
        # Require several expected and distinctive ports so a private IP alone cannot unlock lab mode.
        ports = {int(item.port) for item in findings if item.port is not None}
        expected = ports & self.EXPECTED_PORTS
        distinctive = ports & self.DISTINCTIVE_PORTS
        if len(expected) < 5 or len(distinctive) < 2:
            raise LabVerificationError(
                "Scan fingerprint is not sufficiently consistent with Metasploitable 2"
            )
        return ports

    # Build only the access exercises supported by services actually observed in the scan.
    @staticmethod
    def exercises(target: str, ports: set[int]) -> list[AccessExercise]:
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
