import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class VerificationRun(IdMixin, TimestampMixin, Base):
    """One execution of the testing framework's runner.

    kind="baseline"      -> original code only (Attack Replay: reproduce the exploit)
    kind="proof_of_fix"  -> original vs patched copy, with a verdict
    """

    __tablename__ = "verification_runs"

    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"),
                                                  index=True, nullable=False)
    patch_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("patches.id", ondelete="SET NULL"),
                                                       index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    scenario: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # COMPLETED | ERROR
    verdict: Mapped[str | None] = mapped_column(String(30), index=True)
    verdict_reasons: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    original_vulnerability_reproduced: Mapped[bool | None] = mapped_column(Boolean)
    exploit_blocked_after_patch: Mapped[bool | None] = mapped_column(Boolean)
    regressions_pass_after_patch: Mapped[bool | None] = mapped_column(Boolean)
    phase_summaries: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    raw_output: Mapped[dict | None] = mapped_column(JsonType)
    # Runner schema 1.1 (NULL for runs recorded before the Gauntlet existed)
    gauntlet: Mapped[dict | None] = mapped_column(JsonType)
    forensics: Mapped[dict | None] = mapped_column(JsonType)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    patch = relationship("Patch", back_populates="verification_runs")
    test_results = relationship("VerificationTestResult", back_populates="run",
                                order_by="VerificationTestResult.position", cascade="all, delete-orphan")


class VerificationTestResult(IdMixin, TimestampMixin, Base):
    __tablename__ = "verification_test_results"

    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("verification_runs.id", ondelete="CASCADE"),
                                              index=True, nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False)  # security | regression
    test_id: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False)  # passed | failed | error
    expected: Mapped[str] = mapped_column(Text, nullable=False)
    actual: Mapped[str] = mapped_column(Text, nullable=False)
    exploit_succeeded: Mapped[bool | None] = mapped_column(Boolean)
    evidence: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    privilege_map: Mapped[dict | None] = mapped_column(JsonType)

    run = relationship("VerificationRun", back_populates="test_results")
