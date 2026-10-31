import uuid

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class RegressionCase(IdMixin, TimestampMixin, Base):
    """A confirmed Gauntlet bypass preserved as a reusable test.

    Saved automatically when a verification run reports a bypass, then passed to the runner
    (--extra-variants) on every later verification of the same fixture + scenario. The runner
    re-validates each case against its safety allowlist before executing it.
    """

    __tablename__ = "regression_cases"
    __table_args__ = (UniqueConstraint("fixture_name", "scenario", "fingerprint", name="uq_regression_case_input"),)

    fixture_name: Mapped[str] = mapped_column(String(100), nullable=False)
    scenario: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    variation: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    input: Mapped[dict] = mapped_column(JsonType, nullable=False)
    check: Mapped[dict | None] = mapped_column(JsonType)
    source_variant_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("verification_runs.id", ondelete="SET NULL"))
    source_patch_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("patches.id", ondelete="SET NULL"))
    original_outcome: Mapped[dict] = mapped_column(JsonType, nullable=False)
    patched_outcome: Mapped[dict] = mapped_column(JsonType, nullable=False)
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_seen_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("verification_runs.id", ondelete="SET NULL"))
