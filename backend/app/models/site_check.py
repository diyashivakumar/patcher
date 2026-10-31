from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, JsonType, TimestampMixin


class SiteCheck(IdMixin, TimestampMixin, Base):
    """A non-invasive external website configuration check. Stores only metadata, never bodies/secrets."""

    __tablename__ = "site_checks"

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    host: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # COMPLETED | ERROR
    final_url: Mapped[str | None] = mapped_column(String(2048))
    resolved_ips: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    redirect_chain: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    posture: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    checks: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
