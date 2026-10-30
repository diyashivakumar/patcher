import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class Patch(IdMixin, TimestampMixin, Base):
    """A proposed code change. Status flow:
    PROPOSED -> APPLIED -> VERIFIED | REJECTED ; APPLIED/VERIFIED/REJECTED -> ROLLED_BACK
    """

    __tablename__ = "patches"

    finding_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("findings.id", ondelete="CASCADE"),
                                                  index=True, nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"),
                                                  index=True, nullable=False)
    strategy: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    original_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    patched_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    validation: Mapped[dict] = mapped_column(JsonType, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(100))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    backup_path: Mapped[str | None] = mapped_column(String(500))

    finding = relationship("Finding", back_populates="patches")
    verification_runs = relationship("VerificationRun", back_populates="patch",
                                     order_by="VerificationRun.created_at.desc()")
