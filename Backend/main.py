"""Create and configure the PTAS FastAPI application."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from Backend.api_logging import LoggedRoute
from Backend.config import settings
from Backend.database import Base, engine

# Import every model before create_all so SQLAlchemy knows about every table.
from Backend.models.project_model import Project  # noqa: F401
from Backend.models.recommendation_model import Recommendation  # noqa: F401
from Backend.models.report_model import Report  # noqa: F401
from Backend.models.scan_model import Scan  # noqa: F401
from Backend.models.scope_validation_model import ScopeValidation  # noqa: F401
from Backend.models.target_model import Target  # noqa: F401
from Backend.models.user_model import User  # noqa: F401
from Backend.models.vulnerability_model import Vulnerability  # noqa: F401

from Backend.routes.auth_routes import router as auth_router
from Backend.routes.project_routes import router as project_router
from Backend.routes.recommendation_routes import router as recommendation_router
from Backend.routes.report_routes import router as report_router
from Backend.routes.scan_execution_routes import router as scan_execution_router
from Backend.routes.scan_routes import router as scan_router
from Backend.routes.scope_validation_routes import router as scope_validation_router
from Backend.routes.target_routes import router as target_router
from Backend.routes.user_routes import router as user_router
from Backend.routes.vulnerability_routes import router as vulnerability_router


logger = logging.getLogger("uvicorn.error")

# Keeping route metadata in one table makes API registration easy to inspect.
ROUTERS = (
    (auth_router, "/api/auth", "Authentication"),
    (user_router, "/api/users", "Users"),
    (project_router, "/api/projects", "Projects"),
    (target_router, "/api/targets", "Targets"),
    (scan_router, "/api/scans", "Scans"),
    (vulnerability_router, "/api/vulnerabilities", "Vulnerabilities"),
    (recommendation_router, "/api/recommendations", "Recommendations"),
    (report_router, "/api/reports", "Reports"),
    (scan_execution_router, "/api/scan-execution", "Scan Execution"),
    (scope_validation_router, "/api/scope-validation", "Scope Validation"),
)


# ---------------------------------------------------------------------------
# Application startup and shutdown
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Perform the lifespan operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    Base.metadata.create_all(bind=engine)
    logger.info(
        "PTAS API ready | database tables checked | environment=%s",
        settings.app_env,
    )
    yield


# ---------------------------------------------------------------------------
# FastAPI and middleware configuration
# ---------------------------------------------------------------------------


app = FastAPI(
    title="AI-Powered Penetration Testing Assist System API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

# Apply detailed request logging to root routes and all included routers.
app.router.route_class = LoggedRoute

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register every feature router with the same logging and CORS configuration.
for router, prefix, tag in ROUTERS:
    app.include_router(router, prefix=prefix, tags=[tag])


# ---------------------------------------------------------------------------
# Root and health endpoints
# ---------------------------------------------------------------------------


@app.get("/")
def home():
    """Perform the home operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    return {"message": "PTAS Backend API is running"}


@app.get("/health/live", include_in_schema=False)
def liveness():
    """Perform the liveness operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    return {"status": "ok"}


@app.get("/health/ready", include_in_schema=False)
def readiness():
    """Perform the readiness operation.

    The type hints describe accepted inputs and the value returned to the caller.
    """

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ready"}
