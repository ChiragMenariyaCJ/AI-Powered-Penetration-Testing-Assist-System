"""Database operations for project records."""

from sqlalchemy.orm import Session

from Backend.api_logging import trace_repository
from Backend.models.project_model import Project


@trace_repository
class ProjectRepository:

    """Provide database operations for project records.

    This layer owns SQLAlchemy queries and transaction boundaries for the feature.
    """
    # Store the request-scoped SQLAlchemy session used by this repository’s queries.
    def __init__(self, db: Session):
        self.db = db

    # Create and commit the requested project record.
    def create_project(
        self,
        user_id: int,
        project_name: str,
        description: str | None,
        status: str,
    ) -> Project:
        """Create and commit the requested project record.

        The committed instance is refreshed so generated database values are available
        to callers.
        """
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

    # Query all projects with SQLAlchemy without changing stored database state.
    def get_all_projects(self) -> list[Project]:
        """Query project data for get all projects.

        This read operation returns matching model instances without changing database
        state.
        """
        return self.db.query(Project).order_by(Project.id.desc()).all()

    # Query projects by user id with SQLAlchemy without changing stored database state.
    def get_projects_by_user_id(self, user_id: int) -> list[Project]:
        """Query project data for get projects by user id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Project)
            .filter(Project.user_id == user_id)
            .order_by(Project.id.desc())
            .all()
        )

    # Query project by id with SQLAlchemy without changing stored database state.
    def get_project_by_id(self, project_id: int) -> Project | None:
        """Query project data for get project by id.

        This read operation returns matching model instances without changing database
        state.
        """
        return (
            self.db.query(Project)
            .filter(Project.id == project_id)
            .first()
        )

    # Persist the state change required to update project.
    def update_project(
        self,
        project: Project,
        update_data: dict,
    ) -> Project:
        """Persist the state change required to update project.

        The transaction is committed and refreshed before the updated record is
        returned.
        """
        for field, value in update_data.items():
            setattr(project, field, value)

        self.db.commit()
        self.db.refresh(project)

        return project

    # Delete the supplied project record and commit the transaction.
    def delete_project(self, project: Project) -> None:
        """Delete the supplied project record and commit the transaction.

        Callers must validate that the record exists before invoking this persistence
        operation.
        """
        self.db.delete(project)
        self.db.commit()
