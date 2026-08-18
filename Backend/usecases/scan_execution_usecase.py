from datetime import datetime
from fastapi import HTTPException, status

from Backend.repositories.scan_repository import ScanRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scope_validation_repository import (
    ScopeValidationRepository,
)
from Backend.usecases.scope_validation_usecase import ScopeValidationUseCase
from Backend.services.nmap_service import NmapService
from Backend.services.vulnerability_parser import VulnerabilityParser


class ScanExecutionUseCase:
    """Execute scans with Nmap and parse results"""

    def __init__(
        self,
        scan_repository: ScanRepository,
        target_repository: TargetRepository,
        scope_validation_repository: ScopeValidationRepository,
    ):
        self.scan_repository = scan_repository
        self.target_repository = target_repository
        self.scope_validation_repository = scope_validation_repository
        self.scope_validation_usecase = ScopeValidationUseCase(
            scope_validation_repository,
            None,
        )
        self.nmap_service = NmapService()
        self.vulnerability_parser = VulnerabilityParser()

    def execute_scan_on_target(self, scan_id: int, project_id: int) -> dict:
        """
        Execute Nmap scan on target and update scan record
        
        Args:
            scan_id: ID of scan record
            project_id: ID of project for scope validation
            
        Returns:
            dict with execution results
        """
        # Get scan details
        scan = self.scan_repository.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        # Get target details
        target = self.target_repository.get_target_by_id(scan.target_id)
        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        # Verify target is in scope
        scope_check = self.scope_validation_usecase.check_target_in_scope(
            project_id, target.target_value
        )
        if not scope_check["is_in_scope"]:
            self.scan_repository.update_scan(
                scan,
                {
                    "status": "FAILED",
                    "scan_result": f"Target {target.target_value} is out of scope. Blocked by rules: {', '.join(scope_check['blocked_by_rules'])}",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Target is out of scope. Blocked by: {', '.join(scope_check['blocked_by_rules'])}",
            )

        # Update scan status to RUNNING
        update_data = {
            "status": "RUNNING",
            "started_at": datetime.utcnow(),
        }
        self.scan_repository.update_scan(scan, update_data)

        try:
            # Execute Nmap scan
            nmap_result = self.nmap_service.execute_scan(
                target.target_value,
                scan.scan_type,
            )

            if nmap_result.get("status") == "FAILED":
                self.scan_repository.update_scan(
                    scan,
                    {
                        "status": "FAILED",
                        "scan_result": nmap_result.get("error"),
                        "completed_at": datetime.utcnow(),
                    },
                )
                return {
                    "status": "FAILED",
                    "error": nmap_result.get("error"),
                }

            # Parse vulnerabilities
            vulnerability_data = (
                self.vulnerability_parser.parse_scan_results(nmap_result)
            )

            # Update scan with results
            import json

            scan_result_json = json.dumps(vulnerability_data)

            self.scan_repository.update_scan(
                scan,
                {
                    "status": "COMPLETED",
                    "scan_result": scan_result_json,
                    "completed_at": datetime.utcnow(),
                },
            )

            return {
                "status": "COMPLETED",
                "scan_id": scan_id,
                "target": target.target_value,
                "vulnerabilities_found": vulnerability_data.get("summary", {}),
            }

        except Exception as e:
            self.scan_repository.update_scan(
                scan,
                {
                    "status": "FAILED",
                    "scan_result": f"Scan execution error: {str(e)}",
                    "completed_at": datetime.utcnow(),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Scan execution failed: {str(e)}",
            )

    def get_scan_results(self, scan_id: int) -> dict:
        """Retrieve parsed results from a completed scan"""
        scan = self.scan_repository.get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        if scan.status != "COMPLETED":
            return {
                "status": scan.status,
                "message": f"Scan is {scan.status.lower()}. Results not yet available.",
            }

        try:
            import json

            results = json.loads(scan.scan_result)
            return results
        except Exception:
            return {
                "status": "ERROR",
                "raw_result": scan.scan_result,
            }

    def validate_nmap_availability(self) -> dict:
        """Check if Nmap is installed and available"""
        is_available = self.nmap_service.is_nmap_installed()
        return {
            "nmap_available": is_available,
            "message": "Nmap is ready for scans"
            if is_available
            else "Nmap is not installed on this system",
        }
