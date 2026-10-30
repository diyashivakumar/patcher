import uuid

from sqlalchemy import ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class Finding(IdMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"),
                                               index=True, nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"),
                                                  index=True, nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "sqli" | "idor"
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), index=True, nullable=False)
    severity_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), nullable=False)
    cwe: Mapped[str] = mapped_column(String(20), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    code_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    snippet_start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict] = mapped_column(JsonType, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    detection_method: Mapped[str] = mapped_column(Text, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    patches = relationship("Patch", back_populates="finding", order_by="Patch.created_at.desc()",
                           cascade="all, delete-orphan")
