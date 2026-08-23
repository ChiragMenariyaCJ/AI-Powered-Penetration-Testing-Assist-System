"""Configure SQLAlchemy's engine, sessions, and declarative model base."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from Backend.config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()


def get_db():
    """Provide one database session per API request and always close it."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
