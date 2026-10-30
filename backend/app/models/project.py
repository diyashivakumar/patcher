from sqlalchemy import BigInteger, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin


class Project(IdMixin, TimestampMixin, Base):
    """A codebase under analysis. Source files live on disk under STORAGE_DIR, not in the database."""

    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "fixture" | "upload"
    fixture_name: Mapped[str | None] = mapped_column(String(100))
    file_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    scans = relationship("Scan", back_populates="project", order_by="Scan.created_at.desc()",
                         cascade="all, delete-orphan")
