
# This file handles nmap service.
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
import ipaddress
import os
import re
import tempfile
from typing import Optional

from Backend.config import settings


# Handle the nmap service.
class NmapService:

    # Set up this object.
    def __init__(self):
        self.nmap_command = settings.nmap_path
        self.timeout = settings.nmap_timeout

    # Check whether nmap installed.
    def is_nmap_installed(self) -> bool:
        try:
            result = subprocess.run(
                [self.nmap_command, "-V"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    # Run scan.
    def execute_scan(
        self,
        target: str,
        scan_type: str = "FULL",
        custom_args: Optional[str] = None,
    ) -> dict:
        try:
            if not self.is_nmap_installed():
                return {
                    "status": "FAILED",
                    "error": "Nmap not installed on system",
                }

            target = self._validate_target(target)

            # Use a temporary XML file because structured parsing is safer than scraping console text.
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", delete=False
            ) as tmp_file:
                xml_output_path = tmp_file.name

            try:
                # Build an argument list rather than a shell string to prevent shell interpretation.
                cmd = self._build_command(
                    target, scan_type, custom_args, xml_output_path
                )

                # Capture output and enforce the configured deadline so an unresponsive scan cannot hang the API.
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

                # Parse only the XML produced by this successful subprocess execution.
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
                # Remove the temporary scan evidence even when Nmap fails, times out, or parsing raises an error.
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

    # Build command.
    def _build_command(
        self,
        target: str,
        scan_type: str,
        custom_args: Optional[str],
        xml_output: str,
    ) -> list:
        cmd = [self.nmap_command, "-oX", xml_output]

        if scan_type == "QUICK":
            cmd.extend(["-F", "-sV"])  # Fast scan with version detection
        elif scan_type == "FULL":
            # Keep the API service unprivileged; OS detection and SYN scans need root.
            cmd.extend(["-sV", "-sC"])
        elif scan_type == "VULNERABILITY":
            # Use Vulners alone so this scan stays inside the project timeout.
            cmd.extend(
                [
                    "-F",
                    "-sV",
                    "-T4",
                    "--script",
                    "vulners",
                    "--script-timeout",
                    "30s",
                ]
            )
        elif scan_type == "PORT_SCAN":
            cmd.extend(["-sV"])  # Port scan with version detection
        elif scan_type == "CUSTOM" and custom_args:
            cmd.extend(custom_args.split())

        cmd.append(target)
        return cmd

    # Validate target.
    @staticmethod
    def _validate_target(target: str) -> str:
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

    # Read XML output.
    def _parse_xml_output(self, xml_file_path: str) -> dict:
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Start with a completed result because this parser is reached only after Nmap exits successfully.
            scan_info = {
                "status": "COMPLETED",
                "started_at": datetime.now(UTC).isoformat(),
                "hosts": [],
            }

            # Convert each host independently so one XML document can represent a network scan.
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                if host_data:
                    scan_info["hosts"].append(host_data)

            # Preserve Nmap's aggregate up/down counts for reports and API clients.
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

    # Read host.
    def _parse_host(self, host_elem) -> Optional[dict]:
        try:
            # Store Nmap's host-state reason so reports can explain why a host was considered reachable.
            status_elem = host_elem.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                return None

            # Prefer the first reported address and keep its address type for later display.
            addr_elem = host_elem.find("address")
            if addr_elem is None:
                return None

            host_ip = addr_elem.get("addr")
            hostname = None

            # Hostnames are optional, so retain an empty value when reverse lookup produced none.
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hostname_elem = hostnames.find("hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name")

            # Keep only structured port observations returned by the dedicated port parser.
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_data = self._parse_port(port_elem)
                    if port_data:
                        ports.append(port_data)

            # OS matches are optional evidence and must not be treated as guaranteed identification.
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

    # Read port.
    def _parse_port(self, port_elem) -> Optional[dict]:
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

    # Work with stop scan.
    def stop_scan(self, process_pid: int) -> bool:
        try:
            subprocess.run(
                ["kill", "-9", str(process_pid)],
                capture_output=True,
            )
            return True
        except Exception:
            return False
