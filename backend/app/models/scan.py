import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class Scan(IdMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"),
                                                  index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # RUNNING | COMPLETED | FAILED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    warnings: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", order_by="Finding.line_start",
                            cascade="all, delete-orphan")
