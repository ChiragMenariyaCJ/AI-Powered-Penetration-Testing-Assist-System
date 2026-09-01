
# This file handles scan usecase.
from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scan_repository import ScanRepository


# Handle the scan use case.
@trace_usecase
class ScanUseCase:

    # Set up this object.
    def __init__(
        self,
        scan_repository: ScanRepository,
        target_repository: TargetRepository,
    ):
        self.scan_repository = scan_repository
        self.target_repository = target_repository

    # Create scan.
    def create_scan(self, request):
        target = self.target_repository.get_target_by_id(request.target_id)

        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target not found",
            )

        return self.scan_repository.create_scan(
            target_id=request.target_id,
            scan_name=request.scan_name,
            scan_type=request.scan_type,
            status=request.status,
        )

    # Get all scans.
    def get_all_scans(self, target_id: int | None = None):
        if target_id is not None:
            target = self.target_repository.get_target_by_id(target_id)

            if not target:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Target not found",
                )

            scans = self.scan_repository.get_scans_by_target_id(target_id)
        else:
            scans = self.scan_repository.get_all_scans()

        return {
            "count": len(scans),
            "scans": scans,
        }

    # Get scan by ID.
    def get_scan_by_id(self, scan_id: int):
        scan = self.scan_repository.get_scan_by_id(scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        return scan

    # Update scan.
    def update_scan(self, scan_id: int, request):
        scan = self.scan_repository.get_scan_by_id(scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        update_data = request.model_dump(exclude_unset=True)

        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update",
            )

        return self.scan_repository.update_scan(
            scan,
            update_data,
        )

    # Delete scan.
    def delete_scan(self, scan_id: int):
        scan = self.scan_repository.get_scan_by_id(scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        deleted_scan = {
            "id": scan.id,
            "target_id": scan.target_id,
            "scan_name": scan.scan_name,
        }

        self.scan_repository.delete_scan(scan)

        return {
            "message": "Scan deleted successfully",
            "scan": deleted_scan,
        }
