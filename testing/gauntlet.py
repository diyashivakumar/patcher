"""Exploit Variant Gauntlet: controlled variations of each exploit, run against BOTH app copies.

Every variant is a fixed, harmless, read-only request against the local fixture via the
Flask test client (network is blocked by the harness). Two kinds:

  attack  -- must NOT expose any protected canary record to the actor.
  legit   -- an authorised request that must keep working (a deny-everything patch fails these).

Exploitation is decided from evidence in the actual response, never from the HTTP status alone:
  * canary markers of a protected record (Data Exposure Forensics), or
  * record identity: an unauthorised actor received the requested canary record's own id with a
    2xx response, even if its fields were transformed/encoded (QA finding: base64 "redaction" passed), or
  * an injection probe (SQLi): output that only EXECUTED attacker SQL can produce -- a UNION constant
    marker, or rows returned for a literal term that matches nothing (QA finding: an output filter that
    hid marked rows while staying injectable passed).
Classification needs both phases (see classify()):

  attack: original not exploited          -> invalid       (variant does not reproduce the flaw)
          original + patched exploited    -> bypass        (surviving bypass)
          patched errored (5xx/exception) -> inconclusive  (cannot confirm the block)
          otherwise                       -> blocked
  legit:  patched works                   -> works
          otherwise                       -> regression_failed
"""
import hashlib
import json
import re
from urllib.parse import parse_qs

from testing.canaries import CANARY_RECORDS
from testing.forensics import INCONCLUSIVE, MULTIPLE_EXPOSED, NO_PROTECTED_DATA, RECORD_EXPOSED, REJECTED, inspect
from testing.harness import ACTORS

ATTACK, LEGIT = "attack", "legit"

# --------------------------------------------------------------------------- variants
# input: {"actor", "method", "path", "params"}  or  {"actor", "method", "path", "raw_query"}
# legit checks: {"type": "authorized_record", "record_id"} | {"type": "public_titles", "titles": [...]}

SQLI_VARIANTS = [
    ("sqli.gv.original", ATTACK, "Original payload", "Tautology used by the baseline exploit.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' OR 1=1 --"}}),
    ("sqli.gv.whitespace", ATTACK, "Whitespace variation", "Extra spaces between tokens.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "'    OR    1=1    --"}}),
    ("sqli.gv.case", ATTACK, "Case variation", "Mixed-case SQL keyword.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' oR 1=1 --"}}),
    ("sqli.gv.inline_comment", ATTACK, "SQL comment variation", "Inline /**/ comments instead of spaces.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "'/**/OR/**/1=1/**/--"}}),
    ("sqli.gv.url_encoded", ATTACK, "URL-encoded variation", "Payload sent percent-encoded in the raw query string.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "raw_query": "q=%27%20OR%201%3D1%20--"}),
    ("sqli.gv.double_url_encoded", ATTACK, "Double URL-encoded variation",
     "Encoded twice; the server decodes once, so the app receives literal %27 text. Expected to be INVALID.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "raw_query": "q=%2527%2520OR%25201%253D1%2520--"}),
    ("sqli.gv.position_reopen", ATTACK, "Input-position variation",
     "Closes the LIKE literal and re-opens it, so no trailing comment is needed.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' OR title LIKE '"}}),
    ("sqli.gv.union_body", ATTACK, "UNION column variation", "Appends a read-only UNION that returns document bodies.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' UNION SELECT id, body FROM documents --"}}),
    ("sqli.gv.union_probe", ATTACK, "UNION execution probe",
     "Injects a UNION that returns a constant marker. Only executed SQL can put the marker in a result row.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' UNION SELECT 424242, 'PPROOF-PROBE-UNION' --"}},
     {"type": "union_marker", "marker": "PPROOF-PROBE-UNION"}),
    ("sqli.gv.boolean_probe", ATTACK, "Boolean execution probe",
     "Literal text matches no title; only executed SQL (OR id = 3) returns document 3.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "pproof-no-such-title' OR id = 3 --"}},
     {"type": "rows_with_ids", "ids": [3]}),
    ("sqli.gv.legit_keyword", LEGIT, "Legitimate keyword search", "A normal search must still return public documents.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "Notes"}},
     {"type": "public_titles", "titles": ["Algebra Notes"]}),
    ("sqli.gv.legit_apostrophe", LEGIT, "Legitimate search with apostrophe", "Real input containing a quote must work.",
     {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "O'Brien"}},
     {"type": "public_titles", "titles": ["O'Brien Reading List"]}),
]

IDOR_VARIANTS = [
    ("idor.gv.a_reads_b", ATTACK, "Student A → Student B", "alice requests DOC-202.",
     {"actor": "alice", "method": "GET", "path": "/documents/202"}),
    ("idor.gv.a_reads_c", ATTACK, "Student A → Student C", "alice requests DOC-303 (different resource id).",
     {"actor": "alice", "method": "GET", "path": "/documents/303"}),
    ("idor.gv.b_reads_a", ATTACK, "Student B → Student A", "bob requests DOC-101.",
     {"actor": "bob", "method": "GET", "path": "/documents/101"}),
    ("idor.gv.c_reads_b", ATTACK, "Student C → Student B", "carol requests DOC-202.",
     {"actor": "carol", "method": "GET", "path": "/documents/202"}),
    ("idor.gv.teacher_unassigned", ATTACK, "Teacher → unassigned student", "ms_rivera (teaches alice only) requests DOC-202.",
     {"actor": "ms_rivera", "method": "GET", "path": "/documents/202"}),
    ("idor.gv.other_teacher", ATTACK, "Other teacher → Student A", "mr_okafor (no students) requests DOC-101.",
     {"actor": "mr_okafor", "method": "GET", "path": "/documents/101"}),
    ("idor.gv.anon_reads_a", ATTACK, "Anonymous → Student A", "No token, requests DOC-101.",
     {"actor": "anonymous", "method": "GET", "path": "/documents/101"}),
    ("idor.gv.anon_reads_c", ATTACK, "Anonymous → Student C", "No token, requests DOC-303.",
     {"actor": "anonymous", "method": "GET", "path": "/documents/303"}),
    ("idor.gv.leading_zero_id", ATTACK, "Resource-id format variation", "alice requests /documents/0202 (leading zero).",
     {"actor": "alice", "method": "GET", "path": "/documents/0202"}),
    ("idor.gv.legit_a_own", LEGIT, "Student A → own record", "alice must still read DOC-101.",
     {"actor": "alice", "method": "GET", "path": "/documents/101"}, {"type": "authorized_record", "record_id": "DOC-101"}),
    ("idor.gv.legit_b_own", LEGIT, "Student B → own record", "bob must still read DOC-202.",
     {"actor": "bob", "method": "GET", "path": "/documents/202"}, {"type": "authorized_record", "record_id": "DOC-202"}),
    ("idor.gv.legit_c_own", LEGIT, "Student C → own record", "carol must still read DOC-303.",
     {"actor": "carol", "method": "GET", "path": "/documents/303"}, {"type": "authorized_record", "record_id": "DOC-303"}),
    ("idor.gv.legit_teacher_assigned", LEGIT, "Assigned teacher → Student A", "ms_rivera must still read DOC-101.",
     {"actor": "ms_rivera", "method": "GET", "path": "/documents/101"}, {"type": "authorized_record", "record_id": "DOC-101"}),
]


def _to_dict(row, source="builtin"):
    vid, kind, name, desc, inp, *rest = row
    return {"variant_id": vid, "scenario": vid.split(".")[0], "kind": kind, "variation": name, "description": desc,
            "input": inp, "check": rest[0] if rest else None, "source": source}


BUILTIN = {"sqli": [_to_dict(r) for r in SQLI_VARIANTS], "idor": [_to_dict(r) for r in IDOR_VARIANTS]}

# --------------------------------------------------------------------------- validation
PATHS = {"sqli": re.compile(r"^/search$"), "idor": re.compile(r"^/documents/\d{1,6}$")}
FORBIDDEN_SQL = re.compile(r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|DETACH|PRAGMA|VACUUM|LOAD_EXTENSION)\b|;", re.I)


def fingerprint(scenario, inp):
    canonical = json.dumps({"scenario": scenario, "input": inp}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _query_value(inp):
    if "raw_query" in inp:
        return " ".join(v for vals in parse_qs(inp["raw_query"]).values() for v in vals)
    return " ".join(str(v) for v in (inp.get("params") or {}).values())


def validate_variant(v):
    """Strict allowlist for saved/extra variants. Raises ValueError. Returns a normalised copy."""
    scenario = v.get("scenario")
    if scenario not in PATHS:
        raise ValueError(f"unsupported scenario {scenario!r}")
    kind = v.get("kind")
    if kind not in (ATTACK, LEGIT):
        raise ValueError("kind must be attack or legit")
    inp = v.get("input") or {}
    if set(inp) - {"actor", "method", "path", "params", "raw_query"}:
        raise ValueError("unexpected input keys")
    if inp.get("method") != "GET":
        raise ValueError("only GET requests are allowed")
    if inp.get("actor") not in ACTORS:
        raise ValueError("unknown synthetic actor")
    if not PATHS[scenario].match(str(inp.get("path", ""))):
        raise ValueError("path is outside the practice app's tested routes")
    params = inp.get("params") or {}
    if set(params) - {"q"}:
        raise ValueError("only the q parameter is allowed")
    if "raw_query" in inp:
        # QA finding: "q=x&admin=1" used to pass because only the prefix was checked.
        pairs = parse_qs(str(inp["raw_query"]), keep_blank_values=True)
        if set(pairs) != {"q"} or len(pairs["q"]) != 1:
            raise ValueError("only a single q parameter is allowed")
    q = _query_value(inp)
    if len(q) > 200 or len(str(inp.get("raw_query", ""))) > 400:
        raise ValueError("input too long")
    if FORBIDDEN_SQL.search(q):
        raise ValueError("input contains a state-changing SQL keyword or statement separator")
    check = v.get("check")
    if kind == LEGIT and not isinstance(check, dict):
        raise ValueError("legit variants need a check")
    if check is not None:
        _validate_check(kind, check)
    return {**v, "input": inp}


PROBE_MARKER = re.compile(r"^PPROOF-PROBE-[A-Z0-9-]{1,40}$")


def _validate_check(kind, check):
    allowed = {LEGIT: {"authorized_record", "public_titles"}, ATTACK: {"union_marker", "rows_with_ids"}}[kind]
    t = check.get("type") if isinstance(check, dict) else None
    if t not in allowed:
        raise ValueError(f"check type {t!r} not allowed for {kind} variants")
    if t == "union_marker" and not PROBE_MARKER.match(str(check.get("marker", ""))):
        raise ValueError("probe marker must look like PPROOF-PROBE-<A-Z0-9->")
    if t == "rows_with_ids" and not (isinstance(check.get("ids"), list) and check["ids"]
                                     and all(isinstance(i, int) and 0 < i < 10**6 for i in check["ids"])):
        raise ValueError("rows_with_ids needs a list of positive integer ids")
    if t == "public_titles" and not (isinstance(check.get("titles"), list)
                                     and all(isinstance(x, str) and len(x) <= 200 for x in check["titles"])):
        raise ValueError("public_titles needs a list of short strings")
    if t == "authorized_record" and not isinstance(check.get("record_id"), str):
        raise ValueError("authorized_record needs a record_id")


# --------------------------------------------------------------------------- execution
def _send(client, inp):
    headers = {}
    token = ACTORS[inp["actor"]]
    if token:
        headers["X-User-Token"] = token
    if "raw_query" in inp:
        return client.open(f'{inp["path"]}?{inp["raw_query"]}', method=inp["method"], headers=headers)
    return client.open(inp["path"], method=inp["method"], headers=headers, query_string=inp.get("params") or {})


def _legit_ok(check, status, body_json, forensic):
    if status != 200:
        return False
    if check["type"] == "authorized_record":
        return any(r["record_id"] == check["record_id"] and r["authorized"] for r in forensic["records"])
    if check["type"] == "public_titles":
        titles = {str(row.get("title")) for row in body_json or [] if isinstance(row, dict)} if isinstance(body_json, list) else set()
        return set(check["titles"]) <= titles and not any(not r["authorized"] for r in forensic["records"])
    return False


def run_variant(client, v):
    """Execute one variant against one app copy. Never stores the response body."""
    base = {k: v[k] for k in ("variant_id", "scenario", "kind", "variation", "description", "input", "check", "source")}
    base["fingerprint"] = fingerprint(v["scenario"], v["input"])
    if v.get("regression_case_id"):
        base["regression_case_id"] = v["regression_case_id"]
    try:
        resp = _send(client, v["input"])
        body = resp.get_data(as_text=True)
        status = resp.status_code
    except Exception as exc:  # noqa: BLE001
        return {**base, "status_code": None, "error": f"{type(exc).__name__}: {exc}", "exploited": False,
                "legit_ok": False, "exposure_outcome": INCONCLUSIVE, "exposures": [], "response_bytes": 0}
    actor = v["input"]["actor"]
    body_json = resp.get_json(silent=True)
    forensic = inspect(body, status, actor)
    for rec in forensic["records"]:
        rec["detection"] = "canary_marker"
    identity = _record_identity_exposure(v["input"], status, body_json, forensic)
    if identity:
        forensic["records"].append(identity)
        protected = sum(not r["authorized"] for r in forensic["records"])
        forensic["outcome"] = MULTIPLE_EXPOSED if protected > 1 else RECORD_EXPOSED
    probe_hit = _probe_hit(v.get("check"), body_json) if v["kind"] == ATTACK else False
    exploited = probe_hit or any(not r["authorized"] for r in forensic["records"])
    outcome = forensic["outcome"]
    if probe_hit and outcome in (NO_PROTECTED_DATA, REJECTED):
        outcome = INJECTION_EXECUTED
    legit = _legit_ok(v["check"], status, body_json, forensic) if v["kind"] == LEGIT else None
    return {**base, "status_code": status, "error": None, "response_bytes": len(body.encode()),
            "exploited": exploited, "legit_ok": legit, "exposure_outcome": outcome, "injection_probe_hit": probe_hit,
            "exposures": forensic["records"]}


INJECTION_EXECUTED = "injection_executed"
DOC_PATH = re.compile(r"^/documents/(\d+)$")


def _probe_hit(check, body_json):
    """True when the response contains output that only executed injected SQL can produce."""
    if not isinstance(check, dict):
        return False
    rows = body_json if isinstance(body_json, list) else []
    if check.get("type") == "union_marker":
        return any(isinstance(r, dict) and check["marker"] in map(str, r.values()) for r in rows)
    if check.get("type") == "rows_with_ids":
        return any(isinstance(r, dict) and r.get("id") in check["ids"] for r in rows)
    return False


def _record_identity_exposure(inp, status, body_json, forensic):
    """Unauthorised actor received the requested canary record itself (by id), even if its fields are transformed."""
    m = DOC_PATH.match(inp.get("path", ""))
    if not m or status is None or status >= 400 or not isinstance(body_json, dict):
        return None
    rec = next((r for r in CANARY_RECORDS if r.db_id == int(m.group(1))), None)
    if rec is None or inp["actor"] in rec.authorized_actors or body_json.get("id") != rec.db_id:
        return None
    if any(r["record_id"] == rec.record_id for r in forensic["records"]):
        return None  # already proven by its markers
    fields = sorted(f for f in rec.fields if body_json.get(f) not in (None, ""))
    return {"record_id": rec.record_id, "record_owner": rec.owner, "record_type": rec.record_type, "authorized": False,
            "exposed_fields": fields, "field_sensitivity": {f: rec.fields[f] for f in fields},
            "canary_match": [], "exposure_status": "record_returned_markers_not_visible", "detection": "record_identity"}


def variants_for(scenario, extra=()):
    """Built-in variants for the scenario plus validated saved cases (deduplicated by fingerprint).

    The composed `chain` scenario carries its own ledger (testing/scenarios/chain.py) and has no
    per-request gauntlet variants, so it returns [].
    """
    scenarios = [s for s in (["sqli", "idor"] if scenario == "all" else [scenario]) if s in BUILTIN]
    out = [dict(v) for s in scenarios for v in BUILTIN[s]]
    by_fp = {fingerprint(v["scenario"], v["input"]): v for v in out}
    for raw in extra:
        if raw.get("scenario") not in scenarios:
            continue
        v = validate_variant(raw)
        fp = fingerprint(v["scenario"], v["input"])
        if fp in by_fp:  # same request as a built-in variant: just link the saved case
            by_fp[fp]["regression_case_id"] = v.get("regression_case_id")
            continue
        v = {**v, "variant_id": f'{v["scenario"]}.saved.{fp[:8]}', "source": "saved_regression_case",
             "variation": v.get("variation", "Saved regression case"), "description": v.get("description", ""),
             "check": v.get("check")}
        by_fp[fp] = v
        out.append(v)
    return out


# --------------------------------------------------------------------------- differential classification
BLOCKED, BYPASS, INVALID, INCONCLUSIVE_CASE, WORKS, REGRESSION_FAILED = (
    "blocked", "bypass", "invalid", "inconclusive", "works", "regression_failed")


def _errored(r):
    return r is None or r["error"] is not None or r["status_code"] is None or r["status_code"] >= 500


def classify(before, after):
    if before["kind"] == LEGIT:
        if after and after["legit_ok"]:
            return WORKS, "Legitimate request still returns the expected data after the patch."
        return REGRESSION_FAILED, ("Legitimate request no longer works after the patch "
                                   f"(HTTP {after['status_code'] if after else 'n/a'}, outcome {after['exposure_outcome'] if after else 'n/a'}).")
    if not before["exploited"]:
        why = "errored" if _errored(before) else "returned no protected canary data"
        return INVALID, f"Variant did not reproduce the vulnerability on the original app ({why}); it cannot prove anything about the patch."
    if after is None or after["error"]:
        return INCONCLUSIVE_CASE, "The patched app could not be evaluated for this variant."
    if after["exploited"]:
        leaked = sorted({r["record_id"] for r in after["exposures"] if not r["authorized"]})
        if after.get("injection_probe_hit") and not leaked:
            return BYPASS, "The patched app still EXECUTED the injected SQL (probe output present in the response)."
        return BYPASS, f"The patched app still returned protected canary records {leaked} for this variant."
    if _errored(after):
        return INCONCLUSIVE_CASE, f"No protected data returned, but the patched app answered HTTP {after['status_code']}; the block cannot be confirmed."
    if before.get("injection_probe_hit"):
        return BLOCKED, "Injected SQL executed on the original app; the patched app did not execute it (no probe output)."
    return BLOCKED, "Reproduced on the original app; no protected canary data returned by the patched app."


def build_gauntlet(before_variants, after_variants):
    after_by_id = {v["variant_id"]: v for v in after_variants}
    cases = []
    for b in before_variants:
        a = after_by_id.get(b["variant_id"])
        status, reason = classify(b, a)
        cases.append({"variant_id": b["variant_id"], "scenario": b["scenario"], "kind": b["kind"],
                      "variation": b["variation"], "description": b["description"], "input": b["input"],
                      "check": b.get("check"),
                      "fingerprint": b["fingerprint"], "source": b["source"],
                      "regression_case_id": b.get("regression_case_id"),
                      "expected": ("Authorised data still returned" if b["kind"] == LEGIT
                                   else "Injected SQL must not execute (no probe output)" if (b.get("check") or {}).get("type") in ("union_marker", "rows_with_ids")
                                   else "No protected canary data returned"),
                      "status": status, "reason": reason,
                      "before": _phase_view(b), "after": _phase_view(a)})
    counts = {s: sum(c["status"] == s for c in cases) for s in (BLOCKED, BYPASS, INVALID, INCONCLUSIVE_CASE, WORKS, REGRESSION_FAILED)}
    valid_attacks = sum(c["kind"] == ATTACK and c["status"] != INVALID for c in cases)
    return {"cases": cases, "counts": counts, "valid_attack_variants": valid_attacks,
            "bypasses": [c["variant_id"] for c in cases if c["status"] == BYPASS],
            "requires_review": counts[BYPASS] > 0 or counts[REGRESSION_FAILED] > 0 or counts[INCONCLUSIVE_CASE] > 0}


def _phase_view(r):
    if r is None:
        return None
    return {"status_code": r["status_code"], "error": r["error"], "exploited": r["exploited"], "legit_ok": r["legit_ok"],
            "exposure_outcome": r["exposure_outcome"], "response_bytes": r["response_bytes"],
            "injection_probe_hit": r.get("injection_probe_hit", False),
            "records": [{"record_id": e["record_id"], "authorized": e["authorized"], "exposed_fields": e["exposed_fields"],
                         "exposure_status": e["exposure_status"], "detection": e.get("detection", "canary_marker")}
                        for e in r["exposures"]]}


# --------------------------------------------------------------------------- forensics ledger
def ledger(phase_name, scenario, variants):
    """Record-level ledger rows for one phase (only canary appearances; no bodies)."""
    rows = []
    for v in variants:
        for e in v["exposures"]:
            rows.append({"phase": phase_name, "scenario": scenario if scenario != "all" else v["scenario"],
                         "evidence_ref": f"{phase_name}/{v['variant_id']}", "variant_id": v["variant_id"],
                         "actor": v["input"]["actor"], "request": f'{v["input"]["method"]} {v["input"]["path"]}',
                         "status_code": v["status_code"], **e})
    return rows


def forensics_summary(rows):
    protected = [r for r in rows if not r["authorized"]]
    return {
        "unauthorized_records_exposed": sorted({r["record_id"] for r in protected}),
        "protected_fields_exposed": sorted({f'{r["record_id"]}.{f}' for r in protected for f in r["exposed_fields"]}),
        "legitimate_records_accessible": sorted({r["record_id"] for r in rows if r["authorized"]}),
        "exposure_events": len(protected),
    }


def build_forensics(before_rows, after_rows):
    b, a = forensics_summary(before_rows), forensics_summary(after_rows)
    return {
        "phases": {"before_patch": {**b, "ledger": before_rows}, "after_patch": {**a, "ledger": after_rows}},
        "comparison": {
            "records_no_longer_exposed": sorted(set(b["unauthorized_records_exposed"]) - set(a["unauthorized_records_exposed"])),
            "records_still_exposed": sorted(set(b["unauthorized_records_exposed"]) & set(a["unauthorized_records_exposed"])),
            "fields_no_longer_exposed": sorted(set(b["protected_fields_exposed"]) - set(a["protected_fields_exposed"])),
            "fields_still_exposed": sorted(set(b["protected_fields_exposed"]) & set(a["protected_fields_exposed"])),
            "legitimate_access_kept": sorted(set(b["legitimate_records_accessible"]) & set(a["legitimate_records_accessible"])),
            "legitimate_access_lost": sorted(set(b["legitimate_records_accessible"]) - set(a["legitimate_records_accessible"])),
        },
    }
