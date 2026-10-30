import uuid

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class AuditLog(IdMixin, TimestampMixin, Base):
    """Append-only record of security-relevant actions (approvals, applies, rollbacks, runs)."""

    __tablename__ = "audit_logs"

    project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="SET NULL"),
                                                         index=True)
    entity_type: Mapped[str] = mapped_column(String(30), nullable=False)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    details: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)


def record(db, action, entity_type, entity_id=None, project_id=None, actor="system", **details):
    db.add(AuditLog(action=action, entity_type=entity_type, entity_id=entity_id,
                    project_id=project_id, actor=actor, details=details))
