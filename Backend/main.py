from fastapi import FastAPI

from Backend.database import Base, engine
from Backend.models.user_model import User
from Backend.models.project_model import Project
from Backend.models.target_model import Target
from Backend.models.scan_model import Scan
from Backend.models.scope_validation_model import ScopeValidation
from Backend.routes.user_routes import router as user_router
from Backend.routes.auth_routes import router as auth_router
from Backend.routes.project_routes import router as project_router
from Backend.routes.target_routes import router as target_router
from Backend.routes.scan_routes import router as scan_router
from Backend.routes.scope_validation_routes import router as scope_validation_router

app = FastAPI(
    title="AI-Powered Penetration Testing Assist System API",
    version="1.0.0"
)

Base.metadata.create_all(bind=engine)

app.include_router(
    auth_router,
    prefix="/api/auth",
    tags=["Authentication"],
)

app.include_router(
    user_router,
    prefix="/api/users",
    tags=["Users"],
)

app.include_router(
    project_router,
    prefix="/api/projects",
    tags=["Projects"],
)

app.include_router(
    target_router,
    prefix="/api/targets",
    tags=["Targets"],
)

app.include_router(
    scan_router,
    prefix="/api/scans",
    tags=["Scans"],
)

app.include_router(
    scope_validation_router,
    prefix="/api/scope-validation",
    tags=["Scope Validation"],
)

@app.get("/")
def home():
    return {
        "message": "PTAS Backend API is running"
    }