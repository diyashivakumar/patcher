"""PatchProof API -- Find the Flaw. Prove the Fix.

Run:  uvicorn app.main:app --reload --port 8000     (from the backend/ directory)
Docs: http://localhost:8000/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.errors import install_error_handlers
from app.routes import findings, health, patches, projects, reports, scans, verification


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PatchProof API",
        version="0.1.0",
        description="Evidence-driven vulnerability detection, patching and Proof-of-Fix verification. "
                    "All endpoints are under /api.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.FRONTEND_ORIGIN.split(",") if o.strip()],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    install_error_handlers(app)
    for module in (health, projects, scans, findings, patches, verification, reports):
        app.include_router(module.router, prefix="/api")
    return app


app = create_app()
