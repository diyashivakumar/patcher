"""Kill-chain impact matrix: run the composed `chain` scenario against four copies of the fixture.

Copies: original, SQLi-patched-only, IDOR-patched-only, both-patched. The patched copies are produced
with the EXISTING deterministic patch generator (no new patches). Each copy is run through the SAME
subprocess sandbox as the Proof-of-Fix flow (app.verification.adapter). The Proof-of-Fix verdict flow
and verdict logic are not touched.

For each copy we report how far the chain reached and a breach-bill summary. The "best single fix" is
the single patch whose chain reaches the fewest steps (tie-break: fewest records exposed).
"""
import shutil
import tempfile
from pathlib import Path

from app.config import get_settings
from app.patching.generator import generate_patch
from app.reports import breach_bill
from app.scanner.engine import scan_directory
from app.services import storage
from app.verification import adapter
from app.verification.engine import _copy_tree

COPIES = [
    ("original", "No fix", []),
    ("sqli_patched", "SQLi fix only", ["sqli"]),
    ("idor_patched", "IDOR fix only", ["idor"]),
    ("both_patched", "Both fixes", ["sqli", "idor"]),
]
STRATEGY = {"sqli": "parameterized_query", "idor": "ownership_check"}


class ChainImpactError(Exception):
    pass


def _base_dir(project):
    """Pristine vulnerable source: a fixture project's original copy, or the bundled fixture."""
    if project is not None:
        if project.source_type != "fixture" or project.fixture_name not in storage.FIXTURES:
            raise ChainImpactError("Chain impact runs only on bundled practice fixtures.")
        return storage.original_dir(project.id)
    base = Path(get_settings().FIXTURES_DIR) / storage.FIXTURES["student_portal"]["path"]
    if not (base / "app.py").is_file():
        raise ChainImpactError("Bundled student_portal fixture is missing.")
    return base


def _patch_snippets(base_dir):
    """Generate the sqli and idor patches once from the pristine source (snippet replacements)."""
    findings, _, _ = scan_directory(base_dir)
    by_type = {}
    for f in findings:
        if f.vuln_type in STRATEGY and f.vuln_type not in by_type:
            text = (Path(base_dir) / f.file_path).read_text(encoding="utf-8")
            proposal = generate_patch(f.vuln_type, f.evidence, text, f.file_path, STRATEGY[f.vuln_type])
            by_type[f.vuln_type] = (f.file_path, proposal.original_snippet, proposal.patched_snippet)
    return by_type


def _write_copy(base_dir, dest, patches, apply_types):
    _copy_tree(base_dir, dest)
    for vuln_type in apply_types:
        if vuln_type not in patches:
            raise ChainImpactError(f"Could not generate the {vuln_type} patch for this fixture.")
        rel, original, patched = patches[vuln_type]
        target = dest / rel
        text = target.read_text(encoding="utf-8")
        if text.count(original) != 1:
            raise ChainImpactError(f"Patch snippet for {vuln_type} did not match the copy exactly.")
        target.write_text(text.replace(original, patched, 1), encoding="utf-8")


def _slim_steps(chain):
    """Per-step view for the graph; drops request/response evidence (no bodies leave the runner)."""
    return [{"step_id": s["step_id"], "name": s["name"], "reached": s["reached"], "succeeded": s["succeeded"],
             "stolen": s["stolen"], "canary_ids": s["canary_ids"], "actor": s.get("actor"),
             "status_code": s.get("status_code"), "actual": s["actual"]} for s in chain["steps"]]


def run_chain_impact(project=None):
    base_dir = _base_dir(project)
    patches = _patch_snippets(base_dir)
    matrix = []
    with tempfile.TemporaryDirectory(prefix="patchproof-chain-") as tmp:
        root = Path(tmp)
        for key, label, apply_types in COPIES:
            _write_copy(base_dir, root / key, patches, apply_types)
            chain = adapter.run_chain(root / key)
            matrix.append({
                "copy_id": key,
                "label": label,
                "applied_fixes": apply_types,
                "steps_reached": chain["steps_reached"],
                "reached_final": chain["reached_final"],
                "chain_succeeded": chain["chain_succeeded"],
                "stolen": chain["stolen"],
                "final_records": chain["final_records"],
                "steps": _slim_steps(chain),
                "ledger": chain["ledger"],
                "breach_bill": breach_bill.summarize(chain),
            })
    return {
        "scenario": "chain",
        "total_steps": len(matrix[0]["steps"]) if matrix else 0,
        "matrix": matrix,
        "best_single_fix": _best_single_fix(matrix),
        "canary_records": storage_canary_note(),
    }


def _best_single_fix(matrix):
    """The single fix that stops the chain earliest. None if the original chain never succeeded."""
    rows = {m["copy_id"]: m for m in matrix}
    if not rows.get("original", {}).get("chain_succeeded"):
        return None
    singles = [rows[c] for c in ("sqli_patched", "idor_patched") if c in rows]
    if not singles:
        return None
    best = min(singles, key=lambda m: (m["steps_reached"], m["breach_bill"]["records_exposed"]))
    return {"copy_id": best["copy_id"], "label": best["label"], "applied_fixes": best["applied_fixes"],
            "steps_reached": best["steps_reached"], "records_exposed": best["breach_bill"]["records_exposed"]}


def storage_canary_note():
    return "All records, tokens and penalties shown are synthetic and illustrative."
