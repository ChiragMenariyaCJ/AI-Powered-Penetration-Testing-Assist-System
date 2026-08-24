"""Business rules for creating and managing scan records."""

from fastapi import HTTPException, status

from Backend.api_logging import trace_usecase
from Backend.repositories.target_repository import TargetRepository
from Backend.repositories.scan_repository import ScanRepository


@trace_usecase
class ScanUseCase:

    """Apply scan business rules between controllers and persistence.

    The use case validates related state and coordinates repositories or services.
    """
    # Store the repositories and services used to enforce this feature’s business rules.
    def __init__(
        self,
        scan_repository: ScanRepository,
        target_repository: TargetRepository,
    ):
        self.scan_repository = scan_repository
        self.target_repository = target_repository

    # Validate related records and coordinate repositories to create scan.
    def create_scan(self, request):
        """Apply business validation and orchestration needed to create scan.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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

    # Validate related records and coordinate repositories to get all scans.
    def get_all_scans(self, target_id: int | None = None):
        """Apply business validation and orchestration needed to get all scans.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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

    # Validate related records and coordinate repositories to get scan by id.
    def get_scan_by_id(self, scan_id: int):
        """Apply business validation and orchestration needed to get scan by id.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
        scan = self.scan_repository.get_scan_by_id(scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        return scan

    # Validate related records and coordinate repositories to update scan.
    def update_scan(self, scan_id: int, request):
        """Apply business validation and orchestration needed to update scan.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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

    # Validate related records and coordinate repositories to delete scan.
    def delete_scan(self, scan_id: int):
        """Apply business validation and orchestration needed to delete scan.

        Invalid related records or state produce a clear HTTP error; valid work is
        delegated to repositories or services.
        """
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
