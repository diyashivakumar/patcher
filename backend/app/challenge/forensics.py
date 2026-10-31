"""Data Exposure Forensics for PatchProof.

Inspects actual HTTP response bodies for protected synthetic canary markers.
Assigns DATA LEAK if protected data appears in unauthorized or attack responses,
regardless of the HTTP status code (e.g. 200, 403, or 500).
"""
import re
from app.challenge.schemas import ForensicsEvidence

# Synthetic canary markers defined in fixtures/seed/student_portal.sql
CANARY_PATTERNS = [
    r"SYNTHETIC-PRIVATE-ALICE",
    r"SYNTHETIC-PRIVATE-BOB",
    r"tok-alice-SYNTHETIC",
    r"tok-bob-SYNTHETIC",
    r"tok-rivera-SYNTHETIC",
    r"tok-okafor-SYNTHETIC",
    r"Alice Private Diary",
    r"Bob Private Grades",
]


def scan_response_forensics(response_bodies: list[str]) -> ForensicsEvidence:
    """Scan a collection of attack/unauthorized response bodies for leaked canaries."""
    detected_markers: set[str] = set()
    leaked_excerpts: list[str] = []
    inspected = len(response_bodies)
    clean = 0

    for body in response_bodies:
        if not body:
            clean += 1
            continue
        found_in_body = False
        for pat in CANARY_PATTERNS:
            matches = re.findall(pat, body, flags=re.IGNORECASE)
            if matches:
                found_in_body = True
                for m in matches:
                    detected_markers.add(m)
                # Extract excerpt around match
                idx = body.lower().find(matches[0].lower())
                start = max(0, idx - 40)
                end = min(len(body), idx + len(matches[0]) + 40)
                excerpt = body[start:end].replace("\n", " ").strip()
                if excerpt and excerpt not in leaked_excerpts:
                    leaked_excerpts.append(f"...{excerpt}...")
        if not found_in_body:
            clean += 1

    return ForensicsEvidence(
        canary_detected=len(detected_markers) > 0,
        detected_markers=sorted(detected_markers),
        leaked_excerpts=leaked_excerpts[:5],
        inspected_responses=inspected,
        clean_responses=clean,
    )
