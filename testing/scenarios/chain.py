"""Attack-chain scenario: compose the EXISTING SQLi and IDOR steps into one ordered story.

This introduces no new attack payloads. It reuses:
  * the SQLi UNION step from scenarios/sqli.py  (' UNION SELECT id, api_token FROM users --)
  * the IDOR document read from scenarios/idor.py (GET /documents/<id> with X-User-Token)
  * forensics.py / canaries.py for exposure detection (no reinvented oracle)

Sequence (each step runs only if the previous one was reached):
  1. sqli_token_theft   -- UNION injection; parse which synthetic api_tokens leaked.
  2. token_replay       -- replay one stolen token as X-User-Token (the real header `call` sends).
  3. idor_document_walk -- with that token, read each canary document; record which other
                           users' canary records became reachable (the broken ownership check).

If step 1 returns no token (e.g. after the SQLi fix), steps 2-3 are marked reached=False and the
ledger is empty, so the chain visibly stops.

Each step records: step_id, name, reached, succeeded, stolen (artifact labels like "api_token:bob"),
and the canary record ids seen. The chain is a single security TestCase; its rich per-step detail
and ledger ride in the test evidence under evidence["chain"].
"""
from testing.canaries import CANARY_RECORDS
from testing.forensics import inspect
from testing.harness import ACTORS, call, json_or_none
from testing.scenarios import SECURITY, TestCase

# The exact UNION payload already shipped in scenarios/sqli.py::_union (reused, not a new payload).
UNION_PAYLOAD = "' UNION SELECT id, api_token FROM users --"
CANARY_IDS = [r.db_id for r in CANARY_RECORDS]


def _token_to_actor():
    return {tok: actor for actor, tok in ACTORS.items() if tok}


def _step_token_theft(client):
    """Step 1: UNION injection, detect which synthetic tokens leaked (match against known actors)."""
    resp, evidence = call(client, "GET", "/search", params={"q": UNION_PAYLOAD})
    body = resp.get_data(as_text=True)
    reverse = _token_to_actor()
    stolen_actors = sorted(actor for tok, actor in reverse.items() if tok in body)
    stolen = [f"api_token:{a}" for a in stolen_actors]
    succeeded = bool(stolen_actors)
    actual = (f"UNION injection leaked {len(stolen_actors)} synthetic api_token(s): {stolen_actors}"
              if succeeded else f"No api_token leaked (HTTP {resp.status_code}); injection did not return credentials")
    return {
        "step_id": "chain.sqli_token_theft", "name": "SQLi: steal API tokens via UNION",
        "reached": True, "succeeded": succeeded, "stolen": stolen, "canary_ids": [],
        "actor": "anonymous", "status_code": resp.status_code, "actual": actual,
        "evidence": evidence, "_stolen_actors": stolen_actors,
    }


def _step_token_replay(client, stolen_actors):
    """Step 2: replay a stolen token; confirm the app accepts it as that user."""
    reached = bool(stolen_actors)
    if not reached:
        return {"step_id": "chain.token_replay", "name": "Replay stolen session token",
                "reached": False, "succeeded": False, "stolen": [], "canary_ids": [],
                "actor": None, "status_code": None,
                "actual": "Not reached: no token was stolen in step 1.", "evidence": {}, "_actor": None}
    actor = stolen_actors[0]  # deterministic (sorted)
    resp, evidence = call(client, "GET", "/documents/mine", actor=actor)
    succeeded = resp.status_code == 200
    actual = (f"Stolen token for '{actor}' accepted; the app treats the attacker as {actor} (HTTP 200)."
              if succeeded else f"Stolen token for '{actor}' not accepted (HTTP {resp.status_code}).")
    return {"step_id": "chain.token_replay", "name": f"Replay stolen token ({actor})",
            "reached": True, "succeeded": succeeded, "stolen": [f"api_token:{actor}"], "canary_ids": [],
            "actor": actor, "status_code": resp.status_code, "actual": actual,
            "evidence": evidence, "_actor": actor if succeeded else None}


def _step_document_walk(client, actor):
    """Step 3: with the stolen token, read canary documents; record cross-user exposure via forensics."""
    if not actor:
        return {"step_id": "chain.idor_document_walk", "name": "IDOR: walk documents with stolen token",
                "reached": False, "succeeded": False, "stolen": [], "canary_ids": [],
                "actor": None, "status_code": None,
                "actual": "Not reached: no usable stolen token.", "evidence": {}, "ledger": []}, []
    ledger, seen, requests = [], [], []
    for db_id in CANARY_IDS:
        resp, _ = call(client, "GET", f"/documents/{db_id}", actor=actor)
        body = resp.get_data(as_text=True)
        found = inspect(body, resp.status_code, actor)
        requests.append({"document": db_id, "status_code": resp.status_code})
        for rec in found["records"]:
            if rec["record_id"] not in seen:
                seen.append(rec["record_id"])
            if not rec["authorized"]:
                ledger.append({
                    "step_id": "chain.idor_document_walk", "actor": actor,
                    "request": f"GET /documents/{db_id}", "status_code": resp.status_code,
                    "record_id": rec["record_id"], "record_owner": rec["record_owner"],
                    "record_type": rec["record_type"], "exposed_fields": rec["exposed_fields"],
                    "field_sensitivity": rec["field_sensitivity"], "exposure_status": rec["exposure_status"],
                    "canary_match": rec["canary_match"], "detection": rec.get("detection", "canary_marker"),
                    "authorized": False,
                })
    cross_user = sorted({row["record_id"] for row in ledger})
    succeeded = bool(cross_user)
    actual = (f"Stolen '{actor}' token read other users' canary records {cross_user} via the broken "
              f"ownership check." if succeeded else f"No other user's canary record was reachable as '{actor}'.")
    return {"step_id": "chain.idor_document_walk", "name": "IDOR: walk documents with stolen token",
            "reached": True, "succeeded": succeeded, "stolen": [], "canary_ids": seen,
            "actor": actor, "status_code": 200, "actual": actual,
            "evidence": {"requests": requests}, "ledger": ledger}, ledger


def run_chain(client):
    """Execute the full chain against one app copy. Returns a structured, JSON-safe result."""
    s1 = _step_token_theft(client)
    stolen_actors = s1.pop("_stolen_actors")
    s2 = _step_token_replay(client, stolen_actors)
    actor = s2.pop("_actor")
    s3, ledger = _step_document_walk(client, actor)
    steps = [s1, s2, s3]
    reached_final = s3["reached"]
    final_records = sorted({row["record_id"] for row in ledger})
    chain_succeeded = s3["succeeded"]
    return {
        "steps": steps,
        "ledger": ledger,
        "stolen": sorted({label for st in steps for label in st["stolen"]}),
        "reached_final": reached_final,
        "steps_reached": sum(1 for st in steps if st["reached"]),
        "final_records": final_records,
        "chain_succeeded": chain_succeeded,
    }


def _chain_test(client):
    chain = run_chain(client)
    # Security-test convention: passes when the attack is blocked (chain did NOT reach cross-user data).
    exploited = chain["chain_succeeded"]
    passed = not exploited
    if exploited:
        actual = (f"Full kill-chain succeeded: stole {chain['stolen']}, then read {chain['final_records']} "
                  "belonging to other users.")
    elif chain["steps_reached"] == 1:
        actual = "Chain stopped at step 1: no credentials were stolen (SQLi blocked)."
    else:
        actual = f"Chain reached {chain['steps_reached']} step(s) but exposed no other user's records."
    return {"passed": passed, "exploit_succeeded": exploited, "actual": actual,
            "evidence": {"chain": chain}}


TESTS = [
    TestCase(
        "chain.sqli_to_idor", "chain", SECURITY,
        "SQLi -> stolen token -> IDOR document walk",
        "Composes the existing SQLi UNION step and IDOR document read to show how one flaw enables another.",
        "No cross-user canary record reachable (chain blocked at some step)",
        _chain_test,
    ),
]
