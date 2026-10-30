"""Test setup.

The real app requires Neon PostgreSQL. These unit/API tests swap in an in-memory
SQLite engine (TEST-ONLY) so they run without network or credentials. The models
use portable types (Uuid, JSON->JSONB variant) so the same code runs on both.
Project files go to a per-test temporary STORAGE_DIR.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.database import get_db
from app.main import app
from app.models import Base


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "STORAGE_DIR", tmp_path / "storage")
    monkeypatch.setattr(get_settings(), "OLLAMA_BASE_URL", "http://127.0.0.1:9")  # nothing listens here
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _enforce_fks(dbapi_conn, _record):  # SQLite ignores foreign keys unless asked; Postgres never does
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
