
# This file handles database.
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


# Get db.
def get_db():

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
