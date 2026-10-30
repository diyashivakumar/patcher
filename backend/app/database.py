"""Database engine and session management for Neon PostgreSQL."""
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


class DatabaseNotConfigured(RuntimeError):
    pass


def normalize_database_url(url: str) -> str:
    """Use the psycopg (v3) driver and require SSL for Neon hosts."""
    if not url:
        raise DatabaseNotConfigured("DATABASE_URL is not set. Copy .env.example to .env and add your Neon URL.")
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    parsed = make_url(url)
    if parsed.drivername in ("postgresql", "postgresql+psycopg2"):
        parsed = parsed.set(drivername="postgresql+psycopg")
    if not parsed.drivername.startswith("postgresql"):
        raise DatabaseNotConfigured("PatchProof's main database must be PostgreSQL (Neon).")
    if parsed.host and "neon.tech" in parsed.host and "sslmode" not in parsed.query:
        parsed = parsed.update_query_dict({"sslmode": "require"})
    return parsed.render_as_string(hide_password=False)


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(
            normalize_database_url(get_settings().DATABASE_URL),
            pool_pre_ping=True,    # Neon suspends idle computes; re-check pooled connections
            pool_recycle=300,
        )
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_db() -> Iterator[Session]:
    get_engine()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
