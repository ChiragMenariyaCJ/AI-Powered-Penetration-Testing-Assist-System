"""Build, execute, and parse bounded Nmap assessment commands."""

import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
import ipaddress
import os
import re
import tempfile
from typing import Optional

from Backend.config import settings


class NmapService:
    """Encapsulate the NmapService service behavior.

    Keeping this integration separate prevents external-tool details from leaking into
    use cases.
    """

    def __init__(self):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.nmap_command = settings.nmap_path
        self.timeout = settings.nmap_timeout

    def is_nmap_installed(self) -> bool:
        """Perform the service-level operation needed to is nmap installed.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            result = subprocess.run(
                [self.nmap_command, "-V"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def execute_scan(
        self,
        target: str,
        scan_type: str = "FULL",
        custom_args: Optional[str] = None,
    ) -> dict:
        """
        Execute Nmap scan on target and return results
        
        Args:
            target: Target IP, hostname, or network (CIDR)
            scan_type: FULL, QUICK, CUSTOM, VULNERABILITY, PORT_SCAN
            custom_args: Custom Nmap arguments
            
        Returns:
            dict with scan results or error
        """
        try:
            if not self.is_nmap_installed():
                return {
                    "status": "FAILED",
                    "error": "Nmap not installed on system",
                }

            target = self._validate_target(target)

            # Create temporary file for XML output
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", delete=False
            ) as tmp_file:
                xml_output_path = tmp_file.name

            try:
                # Build Nmap command based on scan type
                cmd = self._build_command(
                    target, scan_type, custom_args, xml_output_path
                )

                # Execute Nmap
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.timeout,
                    text=True,
                )

                if result.returncode != 0:
                    error = result.stderr.strip() or result.stdout.strip()
                    return {
                        "status": "FAILED",
                        "error": error or f"Nmap exited with code {result.returncode}",
                    }

                # Parse XML output
                if os.path.exists(xml_output_path):
                    parsed_result = self._parse_xml_output(xml_output_path)
                    parsed_result["raw_output"] = result.stdout
                    return parsed_result
                else:
                    return {
                        "status": "FAILED",
                        "error": "Nmap XML output not generated",
                    }

            finally:
                # Clean up temporary file
                if os.path.exists(xml_output_path):
                    try:
                        os.remove(xml_output_path)
                    except Exception:
                        pass

        except subprocess.TimeoutExpired:
            return {
                "status": "FAILED",
                "error": f"Scan timeout after {self.timeout} seconds",
            }
        except Exception as e:
            return {"status": "FAILED", "error": str(e)}

    def _build_command(
        self,
        target: str,
        scan_type: str,
        custom_args: Optional[str],
        xml_output: str,
    ) -> list:
        """Perform the service-level operation needed to build command.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        cmd = [self.nmap_command, "-oX", xml_output]

        if scan_type == "QUICK":
            cmd.extend(["-F", "-sV"])  # Fast scan with version detection
        elif scan_type == "FULL":
            # Keep the API service unprivileged; OS detection and SYN scans need root.
            cmd.extend(["-sV", "-sC"])
        elif scan_type == "VULNERABILITY":
            # Restrict checks to NSE scripts tagged both "vuln" and "safe".
            # This includes Vulners correlation and applicable non-destructive
            # checks that may explicitly report a VULNERABLE state.
            cmd.extend(["-sV", "--script", "(vuln and safe)"])
        elif scan_type == "PORT_SCAN":
            cmd.extend(["-sV"])  # Port scan with version detection
        elif scan_type == "CUSTOM" and custom_args:
            cmd.extend(custom_args.split())

        cmd.append(target)
        return cmd

    @staticmethod
    def _validate_target(target: str) -> str:
        """Perform the service-level operation needed to validate target.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        candidate = target.strip().rstrip(".")
        if (
            not candidate
            or candidate.startswith("-")
            or any(character.isspace() for character in candidate)
        ):
            raise ValueError("Target must be a single IP address, CIDR, or hostname")

        try:
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

        hostname_pattern = re.compile(
            r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )
        if not hostname_pattern.fullmatch(candidate):
            raise ValueError("Target must be a valid IP address, CIDR, or hostname")
        return candidate

    def _parse_xml_output(self, xml_file_path: str) -> dict:
        """Perform the service-level operation needed to parse xml output.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Extract scan information
            scan_info = {
                "status": "COMPLETED",
                "started_at": datetime.now(UTC).isoformat(),
                "hosts": [],
            }

            # Parse each host
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                if host_data:
                    scan_info["hosts"].append(host_data)

            # Extract scan summary
            run_stats = root.find("runstats")
            if run_stats:
                summary = run_stats.find("summary")
                if summary:
                    scan_info["scan_summary"] = {
                        "total": summary.get("total"),
                        "up": summary.get("up"),
                        "down": summary.get("down"),
                    }

            return scan_info

        except Exception as e:
            return {
                "status": "FAILED",
                "error": f"Failed to parse Nmap output: {str(e)}",
            }

    def _parse_host(self, host_elem) -> Optional[dict]:
        """Perform the service-level operation needed to parse host.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            # Get host status
            status_elem = host_elem.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                return None

            # Get host address
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                return None

            host_ip = addr_elem.get("addr")
            hostname = None

            # Get hostname if available
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hostname_elem = hostnames.find("hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name")

            # Parse ports
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_data = self._parse_port(port_elem)
                    if port_data:
                        ports.append(port_data)

            # Parse OS detection
            os_match = None
            os_elem = host_elem.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_match = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy"),
                    }

            return {
                "host_ip": host_ip,
                "hostname": hostname,
                "status": "UP",
                "open_ports": len([p for p in ports if p["state"] == "open"]),
                "ports": ports,
                "os_detection": os_match,
            }

        except Exception as e:
            return None

    def _parse_port(self, port_elem) -> Optional[dict]:
        """Perform the service-level operation needed to parse port.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            port_num = port_elem.get("portid")
            protocol = port_elem.get("protocol")

            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service_name = None
            service_version = None
            service_product = None
            service_extra = None
            service_cpes = []

            if service_elem is not None:
                service_name = service_elem.get("name")
                service_version = service_elem.get("version")
                service_product = service_elem.get("product")
                service_extra = service_elem.get("extrainfo")
                service_cpes = [
                    cpe.text for cpe in service_elem.findall("cpe") if cpe.text
                ]

            scripts = []
            for script_elem in port_elem.findall("script"):
                scripts.append(
                    {
                        "id": script_elem.get("id") or "unknown",
                        "output": script_elem.get("output") or "",
                    }
                )

            return {
                "port": int(port_num),
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": service_version,
                "product": service_product,
                "extrainfo": service_extra,
                "cpes": service_cpes,
                "scripts": scripts,
            }

        except Exception:
            return None

    def stop_scan(self, process_pid: int) -> bool:
        """Perform the service-level operation needed to stop scan.

        Inputs are converted to the external tool or renderer format and the normalized
        result is returned to the use case.
        """
        try:
            subprocess.run(
                ["kill", "-9", str(process_pid)],
                capture_output=True,
            )
            return True
        except Exception:
            return False
