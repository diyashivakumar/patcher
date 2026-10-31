"""Breach Exposure summary ("breach bill") from a chain forensics ledger.

Pure, deterministic, no I/O. It turns the attack-chain ledger (record ids, fields, owners) and the
stolen-credential labels into a human summary: records exposed, distinct fields, and categories
(identity / credentials / private_content).

DPDP reference lines are STATIC and illustrative. Every rupee figure is a statutory MAXIMUM penalty
under the Digital Personal Data Protection Act, 2023, not a prediction or an actual fine. The caveat
below is attached to every figure; callers must display it inline.
"""

PENALTY_CAVEAT = "maximum statutory penalty — illustrative, not legal advice"

# Statutory maxima from the DPDP Act, 2023 (Schedule). Static reference only.
DPDP_REFERENCES = [
    {"provision": "Failure to take reasonable security safeguards to prevent a personal data breach "
                  "(DPDP Act, 2023)",
     "statutory_maximum_inr": 2_500_000_000,  # ₹250 crore
     "statutory_maximum_label": "₹250 crore",
     "caveat": PENALTY_CAVEAT},
    {"provision": "Failure to notify the Data Protection Board and affected Data Principals of a breach "
                  "(DPDP Act, 2023)",
     "statutory_maximum_inr": 2_000_000_000,  # ₹200 crore
     "statutory_maximum_label": "₹200 crore",
     "caveat": PENALTY_CAVEAT},
]

# Canary fields are synthetic student counselling notes -> private content.
_PRIVATE_CONTENT_FIELDS = {"title", "body"}


def summarize(chain):
    """chain: the dict from testing/scenarios/chain.py run_chain (ledger, stolen, final_records)."""
    ledger = chain.get("ledger", []) or []
    stolen = chain.get("stolen", []) or []

    records = sorted({row["record_id"] for row in ledger})
    owners = sorted({row["record_owner"] for row in ledger})
    fields = sorted({f"{row['record_id']}.{f}" for row in ledger for f in row.get("exposed_fields", [])})
    stolen_credentials = sorted({s for s in stolen if s.startswith("api_token:")})

    categories = {
        "credentials": {
            "label": "Credentials stolen",
            "count": len(stolen_credentials),
            "items": stolen_credentials,
            "detail": "Synthetic API session tokens leaked via SQL injection.",
        },
        "identity": {
            "label": "Identities exposed",
            "count": len(owners),
            "items": owners,
            "detail": "Distinct synthetic record owners whose private records were reachable.",
        },
        "private_content": {
            "label": "Private records exposed",
            "count": len(records),
            "items": records,
            "detail": "Synthetic student counselling records read without authorisation.",
        },
    }

    private_fields = sorted({f for f in fields if f.rsplit(".", 1)[-1] in _PRIVATE_CONTENT_FIELDS})
    return {
        "records_exposed": len(records),
        "records": records,
        "fields_exposed": len(fields),
        "fields": fields,
        "private_fields_exposed": len(private_fields),
        "owners_affected": owners,
        "credentials_stolen": len(stolen_credentials),
        "categories": categories,
        "any_exposure": bool(records or stolen_credentials),
        "dpdp_references": DPDP_REFERENCES,
        "penalty_caveat": PENALTY_CAVEAT,
    }
