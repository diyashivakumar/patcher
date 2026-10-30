"""Application settings, loaded from environment variables or a .env file.

Never hardcode credentials here. Copy .env.example to .env and fill it in.
"""
import sys
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = ""

    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = ""
    OLLAMA_TIMEOUT_SECONDS: float = 60.0

    FRONTEND_ORIGIN: str = "http://localhost:5173"

    STORAGE_DIR: Path = BACKEND_DIR / "storage"
    FIXTURES_DIR: Path = REPO_ROOT / "fixtures"

    # Interpreter used to run Dipto's runner (python -m testing.runner). Must have Flask installed.
    TESTING_PYTHON: str = sys.executable
    VERIFICATION_TIMEOUT_SECONDS: int = 120

    MAX_UPLOAD_MB: int = 10
    MAX_EXTRACTED_MB: int = 50
    MAX_UPLOAD_FILES: int = 2000


@lru_cache
def get_settings() -> Settings:
    return Settings()
