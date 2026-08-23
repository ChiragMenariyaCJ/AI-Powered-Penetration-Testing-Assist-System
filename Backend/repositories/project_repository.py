"""Database operations for project records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.project_model import Project


@trace_repository
class ProjectRepository:

    def __init__(self, db: Session):
        self.db = db

    def create_project(
        self,
        user_id: int,
        project_name: str,
        description: str | None,
        status: str,
    ) -> Project:
        project = Project(
            user_id=user_id,
            project_name=project_name,
            description=description,
            status=status,
        )

        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)

        return project

    def get_all_projects(self) -> list[Project]:
        return self.db.query(Project).order_by(Project.id.desc()).all()

    def get_projects_by_user_id(self, user_id: int) -> list[Project]:
        return (
            self.db.query(Project)
            .filter(Project.user_id == user_id)
            .order_by(Project.id.desc())
            .all()
        )

    def get_project_by_id(self, project_id: int) -> Project | None:
        return (
            self.db.query(Project)
            .filter(Project.id == project_id)
            .first()
        )

    def update_project(
        self,
        project: Project,
        update_data: dict,
    ) -> Project:
        for field, value in update_data.items():
            setattr(project, field, value)

        self.db.commit()
        self.db.refresh(project)

        return project

    def delete_project(self, project: Project) -> None:
        self.db.delete(project)
        self.db.commit()
