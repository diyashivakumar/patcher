"""Verification report (JSON + HTML) built from stored, executed results.

This is a verification report for a local practice environment, not a formal
security certification.
"""
import html

from app.models import Finding, Patch, Project, Scan, VerificationRun

LIMITATIONS = [
    "Static analysis covers two vulnerability classes (SQL injection, IDOR) in supported Python/Flask "
    "code patterns only. Code outside those patterns is not analysed; absence of findings is not proof of security.",
    "Dynamic verification runs only against the bundled, synthetic practice fixture in an isolated local "
    "copy. Uploaded code is never executed.",
    "Exploit tests are harmless, read-only payloads chosen for the fixture. Passing them shows these specific "
    "attacks are blocked, not that every possible variant is.",
    "Regression tests cover the behaviours defined in the PrivilegeMap and search scenarios, not the "
    "complete application.",
    "Any AI text shown in the UI is advisory and played no part in detection, patching or this verdict.",
    "The Exploit Variant Gauntlet runs a fixed set of validated variants; surviving them does not prove resistance "
    "to every possible payload. Invalid variants (not reproducible on the original app) are never counted as blocks.",
    "Data Exposure Forensics detects only the synthetic canary records seeded into the practice app, from markers "
    "in actual responses. It is not a complete analysis of everything a real database could expose.",
]


def build_report(run: VerificationRun, project: Project):
    patch: Patch | None = run.patch
    finding: Finding | None = patch.finding if patch else None
    scan: Scan | None = finding.scan if finding else None
    by_phase = {}
    for t in run.test_results:
        by_phase.setdefault(t.phase, {"security": [], "regression": []})[t.category].append({
            "test_id": t.test_id, "name": t.name, "status": t.status, "expected": t.expected,
            "actual": t.actual, "exploit_succeeded": t.exploit_succeeded, "evidence": t.evidence,
            "privilege_map": t.privilege_map,
        })
    return {
        "report_id": str(run.id),
        "report_type": "PatchProof verification report (not a security certification)",
        "generated_at": run.completed_at.isoformat() if run.completed_at else None,
        "project": {"id": str(project.id), "name": project.name, "source_type": project.source_type,
                    "fixture_name": project.fixture_name},
        "scan": {"id": str(scan.id), "started_at": scan.started_at.isoformat(),
                 "files_scanned": scan.files_scanned, "findings_count": scan.findings_count} if scan else None,
        "finding": {
            "id": str(finding.id), "title": finding.title, "vuln_type": finding.vuln_type, "cwe": finding.cwe,
            "severity": finding.severity, "severity_rationale": finding.severity_rationale,
            "confidence": finding.confidence, "file_path": finding.file_path,
            "line_start": finding.line_start, "line_end": finding.line_end,
            "code_snippet": finding.code_snippet, "evidence": finding.evidence,
            "explanation": finding.explanation, "impact": finding.impact,
        } if finding else None,
        "patch": {
            "id": str(patch.id), "strategy": patch.strategy, "status": patch.status, "rationale": patch.rationale,
            "diff": patch.diff, "approved_by": patch.approved_by,
            "approved_at": patch.approved_at.isoformat() if patch.approved_at else None,
        } if patch else None,
        "verification": {
            "kind": run.kind, "scenario": run.scenario, "status": run.status, "verdict": run.verdict,
            "verdict_reasons": run.verdict_reasons,
            "original_vulnerability_reproduced": run.original_vulnerability_reproduced,
            "exploit_blocked_after_patch": run.exploit_blocked_after_patch,
            "regressions_pass_after_patch": run.regressions_pass_after_patch,
            "phase_summaries": run.phase_summaries, "error": run.error, "duration_ms": run.duration_ms,
            "tests": by_phase,
        },
        "gauntlet": _gauntlet_summary(run.gauntlet),
        "forensics": _forensics_summary(run.forensics),
        "known_limitations": LIMITATIONS,
    }


def _gauntlet_summary(g):
    if not g:
        return None
    return {
        "counts": g["counts"], "valid_attack_variants": g["valid_attack_variants"], "requires_review": g["requires_review"],
        "cases": [{"variant_id": c["variant_id"], "kind": c["kind"], "variation": c["variation"], "input": c["input"],
                   "status": c["status"], "reason": c["reason"], "regression_case_id": c.get("regression_case_id"),
                   "before_outcome": (c["before"] or {}).get("exposure_outcome"),
                   "after_outcome": (c["after"] or {}).get("exposure_outcome")} for c in g["cases"]],
    }


def _forensics_summary(f):
    """Ledger rows carry only record ids, field names and canary markers -- never response bodies."""
    if not f:
        return None
    return {"phases": f.get("phases"), "comparison": f.get("comparison"), "canary_records": f.get("canary_records")}


def _gauntlet_html(g):
    if not g:
        return "<h2>Exploit Variant Gauntlet</h2><p>Not recorded for this run.</p>"
    c = g["counts"]
    rows = "".join(
        f"<tr class='{_e('failed' if x['status'] in ('bypass', 'regression_failed') else 'passed' if x['status'] in ('blocked', 'works') else '')}'>"
        f"<td>{_e(x['variation'])}<div class='muted'>{_e(x['variant_id'])}</div></td><td><code>{_e(x['input'])}</code></td>"
        f"<td>{_e(x['before_outcome'])}</td><td>{_e(x['after_outcome'])}</td><td><b>{_e(x['status'].upper())}</b><div class='muted'>{_e(x['reason'])}</div></td></tr>"
        for x in g["cases"])
    return (f"<h2>Exploit Variant Gauntlet</h2><p>{c['blocked']} blocked · {c['bypass']} bypass · {c['works']} legitimate OK · "
            f"{c['regression_failed']} legitimate broken · {c['invalid']} invalid (not counted) · {c['inconclusive']} inconclusive</p>"
            "<table><tr><th>Variant</th><th>Input</th><th>Original app</th><th>Patched app</th><th>Result</th></tr>"
            f"{rows}</table>")


def _forensics_html(f):
    if not f or not f.get("phases"):
        return "<h2>Data Exposure Forensics</h2><p>Not recorded for this run.</p>"
    blocks = []
    for name, ph in f["phases"].items():
        ledger = "".join(
            f"<tr class='{'passed' if r['authorized'] else 'failed'}'><td>{_e(r['actor'])}</td><td>{_e(r['record_id'])} ({_e(r['record_owner'])})</td>"
            f"<td>{_e(', '.join(r['exposed_fields']))}</td><td>{_e(r['exposure_status'])}</td><td class='muted'>{_e(r['evidence_ref'])}</td></tr>"
            for r in ph.get("ledger", []))
        blocks.append(
            f"<h3>{_e(name.replace('_', ' ').title())}</h3><p>Unauthorised records exposed: <b>{_e(', '.join(ph['unauthorized_records_exposed']) or 'none')}</b> · "
            f"protected fields: {_e(', '.join(ph['protected_fields_exposed']) or 'none')} · legitimately accessible: {_e(', '.join(ph['legitimate_records_accessible']) or 'none')}</p>"
            f"<table><tr><th>Actor</th><th>Record (owner)</th><th>Fields returned</th><th>Status</th><th>Evidence</th></tr>{ledger or '<tr><td colspan=5>No canary data in any response</td></tr>'}</table>")
    comp = f.get("comparison") or {}
    summary = "".join(f"<li>{_e(k.replace('_', ' '))}: {_e(', '.join(v) or 'none')}</li>" for k, v in comp.items())
    return f"<h2>Data Exposure Forensics</h2><ul>{summary}</ul>{''.join(blocks)}"


def _e(value):
    return html.escape("" if value is None else str(value))


def _tests_table(tests):
    rows = "".join(
        f"<tr class='{_e(t['status'])}'><td>{_e(t['name'])}<div class='muted'>{_e(t['test_id'])}</div></td>"
        f"<td>{_e(t['expected'])}</td><td>{_e(t['actual'])}</td><td><b>{_e(t['status'].upper())}</b></td></tr>"
        for t in tests
    )
    return ("<table><tr><th>Test</th><th>Expected</th><th>Observed</th><th>Result</th></tr>"
            f"{rows or '<tr><td colspan=4>No tests executed</td></tr>'}</table>")


def render_html(report):
    v, f, p = report["verification"], report["finding"], report["patch"]
    phases = "".join(
        f"<h3>{_e(name.replace('_', ' ').title())}</h3><h4>Security (exploit) tests</h4>{_tests_table(groups['security'])}"
        f"<h4>Regression (legitimate behaviour) tests</h4>{_tests_table(groups['regression'])}"
        for name, groups in v["tests"].items()
    )
    finding_html = (
        f"<h2>Finding</h2><p><b>{_e(f['title'])}</b> ({_e(f['cwe'])}) — severity <b>{_e(f['severity'])}</b>, "
        f"confidence {_e(f['confidence'])}</p><p>{_e(f['severity_rationale'])}</p>"
        f"<p>Location: <code>{_e(f['file_path'])}:{f['line_start']}-{f['line_end']}</code></p>"
        f"<pre>{_e(f['code_snippet'])}</pre><p>{_e(f['explanation'])}</p><p><b>Impact:</b> {_e(f['impact'])}</p>"
    ) if f else ""
    patch_html = (
        f"<h2>Patch</h2><p>Strategy <code>{_e(p['strategy'])}</code>, status <b>{_e(p['status'])}</b>, "
        f"approved by {_e(p['approved_by'])} at {_e(p['approved_at'])}</p><p>{_e(p['rationale'])}</p>"
        f"<pre>{_e(p['diff'])}</pre>"
    ) if p else ""
    verdict = v["verdict"] or ("REPRODUCED" if v["original_vulnerability_reproduced"] else "BASELINE")
    reasons = "".join(f"<li>{_e(r)}</li>" for r in v["verdict_reasons"])
    limits = "".join(f"<li>{_e(x)}</li>" for x in report["known_limitations"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PatchProof Verification Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2933;background:#fff}}
pre{{background:#f4f5f7;padding:.75rem;overflow-x:auto;font-size:.85rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.9rem}}
td,th{{border:1px solid #d9dde3;padding:.4rem .5rem;text-align:left;vertical-align:top}}
tr.passed td:last-child{{color:#137333}} tr.failed td:last-child,tr.error td:last-child{{color:#b3261e}}
.verdict{{display:inline-block;padding:.3rem .8rem;border-radius:999px;font-weight:700;background:#eef}}
.VERIFIED{{background:#e6f4ea;color:#137333}} .FAILED{{background:#fce8e6;color:#b3261e}}
.PARTIALLY_VERIFIED{{background:#fef7e0;color:#8a5a00}} .muted{{color:#6b7280;font-size:.8rem}}
</style></head><body>
<h1>PatchProof Verification Report</h1>
<p class="muted">{_e(report['report_type'])}. Report {_e(report['report_id'])}, generated {_e(report['generated_at'])}.</p>
<p>Project: <b>{_e(report['project']['name'])}</b> ({_e(report['project']['source_type'])})</p>
<h2>Verdict: <span class="verdict {_e(verdict)}">{_e(verdict)}</span></h2>
<ul>{reasons}</ul>
<p>Scenario <code>{_e(v['scenario'])}</code> · run status {_e(v['status'])} · {_e(v['duration_ms'])} ms
{f"<br>Error: {_e(v['error'])}" if v['error'] else ""}</p>
{finding_html}{patch_html}
{_gauntlet_html(report.get("gauntlet"))}
{_forensics_html(report.get("forensics"))}
<h2>Executed tests</h2>{phases or "<p>No test results were recorded.</p>"}
<h2>Known limitations</h2><ul>{limits}</ul>
</body></html>"""
