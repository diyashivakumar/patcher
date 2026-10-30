"""Turn ORM objects into response schemas, adding derived fields."""
from collections import Counter

from app.models import Finding, Patch, Project, Scan, VerificationRun
from app.patching.generator import STRATEGIES
from app.schemas.finding import FindingDetail, PatchBrief
from app.schemas.patch import PatchOut, RunBrief
from app.schemas.project import ProjectDetail, ProjectOut
from app.schemas.scan import ScanSummary
from app.schemas.verification import TestResultOut, VerificationRunDetail
from app.verification.engine import supported_scenarios

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def scan_out(scan: Scan) -> ScanSummary:
    counts = Counter(f.severity for f in scan.findings)
    out = ScanSummary.model_validate(scan)
    out.severity_counts = {s: counts.get(s, 0) for s in SEVERITY_ORDER}
    return out


def project_out(project: Project, detail=False, upload_skipped=None):
    scenarios = supported_scenarios(project)
    cls = ProjectDetail if detail else ProjectOut
    out = cls.model_validate(project)
    out.verification_scenarios = scenarios
    out.verification_supported = bool(scenarios)
    out.scan_count = len(project.scans)
    out.latest_scan = scan_out(project.scans[0]) if project.scans else None
    if detail:
        out.scans = [scan_out(s) for s in project.scans]
        out.upload_skipped = upload_skipped or []
    return out


def finding_out(finding: Finding, project: Project) -> FindingDetail:
    out = FindingDetail.model_validate(finding)
    out.patches = [PatchBrief.model_validate(p) for p in finding.patches]
    out.available_strategies = STRATEGIES.get(finding.vuln_type, [])
    out.verification_supported = finding.vuln_type in supported_scenarios(project)
    return out


def patch_out(patch: Patch) -> PatchOut:
    return PatchOut(
        **{k: getattr(patch, k) for k in PatchOut.model_fields
           if k not in ("vuln_type", "is_demo_bad_patch", "verification_runs")},
        vuln_type=patch.finding.vuln_type,
        is_demo_bad_patch=patch.strategy == "deny_all_demo",
        verification_runs=[RunBrief.model_validate(r) for r in patch.verification_runs],
    )


def run_out(run: VerificationRun) -> VerificationRunDetail:
    out = VerificationRunDetail.model_validate(run)
    out.patch_status = run.patch.status if run.patch else None
    out.test_results = [TestResultOut.model_validate(t) for t in run.test_results]
    return out
