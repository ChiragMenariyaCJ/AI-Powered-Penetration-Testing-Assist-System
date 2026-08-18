from sqlalchemy.orm import Session

from Backend.repositories.project_repository import ProjectRepository
from Backend.repositories.target_repository import TargetRepository
from Backend.usecases.target_usecase import TargetUseCase


class TargetController:

    def __init__(self, db: Session):
        target_repository = TargetRepository(db)
        project_repository = ProjectRepository(db)

        self.target_usecase = TargetUseCase(
            target_repository,
            project_repository,
        )

    def create_target(self, request):
        return self.target_usecase.create_target(request)

    def get_all_targets(self, project_id: int | None = None):
        return self.target_usecase.get_all_targets(project_id)

    def get_target_by_id(self, target_id: int):
        return self.target_usecase.get_target_by_id(target_id)

    def update_target(self, target_id: int, request):
        return self.target_usecase.update_target(target_id, request)

    def delete_target(self, target_id: int):
        return self.target_usecase.delete_target(target_id)
