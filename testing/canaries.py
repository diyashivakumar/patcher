"""Canary record registry for Data Exposure Forensics.

Each canary is a fabricated private document seeded by fixtures/seed/student_portal.sql.
Every field embeds its own marker  CANARY-STUDENT-<X>-<NNN>:<FIELD>  so response inspection
can prove exactly which record and which field was returned -- no inference from HTTP status.

`authorized_actors` mirrors the PrivilegeMap rules (owner, or a teacher assigned to the owner).
"""
import re
from dataclasses import dataclass, field

FIELD_SENSITIVITY = {"title": "confidential", "body": "restricted"}


@dataclass(frozen=True)
class CanaryRecord:
    record_id: str            # stable synthetic identifier shown in the ledger
    db_id: int                # documents.id in the fixture DB
    owner: str                # synthetic owner actor
    record_type: str
    marker: str               # base canary marker
    authorized_actors: tuple  # actors allowed to read it under the PrivilegeMap
    fields: dict = field(default_factory=lambda: dict(FIELD_SENSITIVITY))

    def field_marker(self, name):
        return f"{self.marker}:{name.upper()}"


CANARY_RECORDS = (
    CanaryRecord("DOC-101", 101, "alice", "student_counselling_record", "CANARY-STUDENT-A-101", ("alice", "ms_rivera")),
    CanaryRecord("DOC-202", 202, "bob", "student_counselling_record", "CANARY-STUDENT-B-202", ("bob",)),
    CanaryRecord("DOC-303", 303, "carol", "student_counselling_record", "CANARY-STUDENT-C-303", ("carol",)),
)
BY_MARKER = {r.marker: r for r in CANARY_RECORDS}
BY_RECORD_ID = {r.record_id: r for r in CANARY_RECORDS}
MARKER_RE = re.compile(r"CANARY-STUDENT-[A-Z]-\d{3}(?::([A-Z]+))?")


def registry():
    """JSON-safe description of the canaries (no secrets; all synthetic)."""
    return [{"record_id": r.record_id, "db_id": r.db_id, "owner": r.owner, "record_type": r.record_type,
             "marker": r.marker, "authorized_actors": list(r.authorized_actors),
             "fields": [{"name": n, "sensitivity": s, "marker": r.field_marker(n)} for n, s in r.fields.items()]}
            for r in CANARY_RECORDS]
