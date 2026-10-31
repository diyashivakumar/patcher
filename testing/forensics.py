"""Data Exposure Forensics: inspect an ACTUAL response body for canary markers.

Exposure is established only from markers present in the body. HTTP status is recorded but
never used on its own: a 200 with no markers is not an exposure, and a 403 whose body still
contains markers IS one.

Only the matched markers and field names are kept as evidence -- never the response body.
"""
from testing.canaries import BY_MARKER, MARKER_RE

# Request-level outcomes
REJECTED = "rejected"
NO_PROTECTED_DATA = "accepted_no_protected_data"
RECORD_EXPOSED = "protected_record_exposed"
PARTIAL_EXPOSURE = "partial_field_exposure"
MULTIPLE_EXPOSED = "multiple_records_exposed"
INCONCLUSIVE = "inconclusive"

# Record-level ledger statuses
LEDGER_EXPOSED = "protected_record_exposed"
LEDGER_PARTIAL = "partial_field_exposure"
LEDGER_AUTHORIZED = "authorized_access"


def inspect(body, status_code, actor):
    """Return {"outcome", "records": [per-record findings]} for one response."""
    found = {}  # marker -> set of field names
    for m in MARKER_RE.finditer(body or ""):
        base = m.group(0).split(":")[0]
        if base not in BY_MARKER:
            continue
        fields = found.setdefault(base, set())
        if m.group(1):
            fields.add(m.group(1).lower())

    records = []
    for base, fields in sorted(found.items()):
        rec = BY_MARKER[base]
        authorized = actor in rec.authorized_actors
        all_fields = set(rec.fields)
        status = LEDGER_AUTHORIZED if authorized else (LEDGER_EXPOSED if fields >= all_fields else LEDGER_PARTIAL)
        records.append({
            "record_id": rec.record_id,
            "record_owner": rec.owner,
            "record_type": rec.record_type,
            "authorized": authorized,
            "exposed_fields": sorted(fields),
            "field_sensitivity": {f: rec.fields[f] for f in sorted(fields)},
            "canary_match": [rec.marker] + [rec.field_marker(f) for f in sorted(fields)],
            "exposure_status": status,
        })

    protected = [r for r in records if not r["authorized"]]
    if status_code is None or status_code >= 500:
        outcome = INCONCLUSIVE if not protected else (MULTIPLE_EXPOSED if len(protected) > 1 else protected[0]["exposure_status"])
    elif len(protected) > 1:
        outcome = MULTIPLE_EXPOSED
    elif protected:
        outcome = protected[0]["exposure_status"]
    elif status_code >= 400:
        outcome = REJECTED
    else:
        outcome = NO_PROTECTED_DATA
    return {"outcome": outcome, "records": records}
