// TypeScript mirror of the backend's Pydantic schemas. Source of truth: docs/api_contract.md

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type VulnType = "sqli" | "idor";
export type Verdict = "VERIFIED" | "PARTIALLY_VERIFIED" | "FAILED";
export type PatchStatus = "PROPOSED" | "APPLIED" | "VERIFIED" | "REJECTED" | "ROLLED_BACK";

export interface ApiErrorBody {
  error: { code: string; message: string; details: unknown };
}

export interface FixtureInfo {
  name: string;
  title: string;
  description: string;
  verification_scenarios: VulnType[];
}

export interface ScanSummary {
  id: string;
  project_id: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  started_at: string;
  completed_at: string | null;
  files_scanned: number;
  findings_count: number;
  severity_counts: Record<Severity, number>;
  warnings: string[];
  error: string | null;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  source_type: "fixture" | "upload";
  fixture_name: string | null;
  file_count: number;
  total_bytes: number;
  verification_supported: boolean;
  verification_scenarios: VulnType[];
  scan_count: number;
  latest_scan: ScanSummary | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectDetail extends Project {
  scans: ScanSummary[];
  upload_skipped: { path: string; reason: string }[];
}

export interface Finding {
  id: string;
  scan_id: string;
  project_id: string;
  vuln_type: VulnType;
  title: string;
  severity: Severity;
  severity_rationale: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  cwe: string;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet: string;
  snippet_start_line: number;
  evidence: Record<string, unknown>;
  explanation: string;
  impact: string;
  remediation: string;
  detection_method: string;
  created_at: string;
}

export interface PatchBrief {
  id: string;
  strategy: string;
  status: PatchStatus;
  created_at: string;
}

export interface FindingDetail extends Finding {
  patches: PatchBrief[];
  available_strategies: string[];
  verification_supported: boolean;
}

export interface AIExplanation {
  available: boolean;
  model: string | null;
  text: string | null;
  message: string;
  advisory: string;
}

export interface RunBrief {
  id: string;
  kind: "baseline" | "proof_of_fix";
  status: string;
  verdict: Verdict | null;
  created_at: string;
}

export interface Patch {
  id: string;
  finding_id: string;
  project_id: string;
  vuln_type: VulnType;
  strategy: string;
  is_demo_bad_patch: boolean;
  status: PatchStatus;
  file_path: string;
  line_start: number;
  line_end: number;
  original_snippet: string;
  patched_snippet: string;
  diff: string;
  rationale: string;
  validation: {
    syntax_ok: boolean;
    target_finding_cleared: boolean;
    remaining_findings_in_file?: number;
    note?: string;
    error?: string;
  };
  approved_by: string | null;
  approved_at: string | null;
  applied_at: string | null;
  rolled_back_at: string | null;
  created_at: string;
  verification_runs: RunBrief[];
}

export interface TestEvidence {
  request?: { method: string; path: string; params: Record<string, string>; actor: string };
  response?: { status_code: number; body_excerpt: string };
  traceback?: string;
}

export interface PrivilegeMapEntry {
  rule_id: string;
  actor: string;
  resource: string;
  expected: "ALLOW" | "DENY";
  observed: "ALLOW" | "DENY" | "UNEXPECTED";
  reason: string;
}

export interface TestResult {
  phase: "before_patch" | "after_patch" | "baseline";
  category: "security" | "regression";
  test_id: string;
  name: string;
  description: string;
  status: "passed" | "failed" | "error";
  expected: string;
  actual: string;
  exploit_succeeded: boolean | null;
  evidence: TestEvidence;
  privilege_map: PrivilegeMapEntry | null;
}

export interface PhaseSummary {
  exploit_reproduced: boolean;
  load_error: string | null;
  duration_ms: number;
  security_tests: { total: number; passed: number; failed: number; errors: number };
  regression_tests: { total: number; passed: number; failed: number; errors: number };
}

export interface VerificationRun {
  id: string;
  project_id: string;
  patch_id: string | null;
  kind: "baseline" | "proof_of_fix";
  scenario: VulnType;
  status: "COMPLETED" | "ERROR" | "RUNNING";
  verdict: Verdict | null;
  verdict_reasons: string[];
  original_vulnerability_reproduced: boolean | null;
  exploit_blocked_after_patch: boolean | null;
  regressions_pass_after_patch: boolean | null;
  phase_summaries: Record<string, PhaseSummary>;
  error: string | null;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
  created_at: string;
}

export interface VerificationRunDetail extends VerificationRun {
  patch_status: PatchStatus | null;
  test_results: TestResult[];
  /** Runner schema 1.1. null/absent for runs recorded before the Gauntlet existed. */
  gauntlet?: Gauntlet | null;
  forensics?: Forensics | null;
}

// ---------------------------------------------------------------- Exploit Variant Gauntlet (runner 1.1)
export type GauntletStatus = "blocked" | "bypass" | "invalid" | "inconclusive" | "works" | "regression_failed";

export interface VariantInput {
  actor: string;
  method: string;
  path: string;
  params?: Record<string, string>;
  raw_query?: string;
}

export interface VariantPhaseView {
  status_code: number | null;
  error: string | null;
  exploited: boolean;
  legit_ok: boolean | null;
  exposure_outcome: string;
  response_bytes: number;
  /** SQLi execution probe output was found in the response (runner QA oracle). */
  injection_probe_hit?: boolean;
  records: { record_id: string; authorized: boolean; exposed_fields: string[]; exposure_status: string; detection?: "canary_marker" | "record_identity" }[];
}

export interface GauntletCase {
  variant_id: string;
  scenario: VulnType;
  kind: "attack" | "legit";
  variation: string;
  description: string;
  input: VariantInput;
  fingerprint: string;
  source: "builtin" | "saved_regression_case";
  regression_case_id: string | null;
  expected: string;
  status: GauntletStatus;
  reason: string;
  before: VariantPhaseView | null;
  after: VariantPhaseView | null;
}

export interface Gauntlet {
  cases: GauntletCase[];
  counts: Record<GauntletStatus, number>;
  valid_attack_variants: number;
  bypasses: string[];
  requires_review: boolean;
}

// ---------------------------------------------------------------- Data Exposure Forensics (runner 1.1)
export interface LedgerRow {
  phase: string;
  scenario: VulnType;
  evidence_ref: string;
  variant_id: string;
  actor: string;
  request: string;
  status_code: number | null;
  record_id: string;
  record_owner: string;
  record_type: string;
  authorized: boolean;
  exposed_fields: string[];
  field_sensitivity: Record<string, string>;
  canary_match: string[];
  exposure_status: string;
  /** How the exposure was proven: canary markers in the body, or the record itself (by id) served to the actor. */
  detection?: "canary_marker" | "record_identity";
  verification_run_id?: string;
}

export interface ForensicsPhase {
  unauthorized_records_exposed: string[];
  protected_fields_exposed: string[];
  legitimate_records_accessible: string[];
  exposure_events: number;
  ledger: LedgerRow[];
}

export interface CanaryRecordInfo {
  record_id: string;
  db_id: number;
  owner: string;
  record_type: string;
  marker: string;
  authorized_actors: string[];
  fields: { name: string; sensitivity: string; marker: string }[];
}

export interface Forensics {
  canary_records: CanaryRecordInfo[];
  phases: Record<string, ForensicsPhase>;
  comparison?: {
    records_no_longer_exposed: string[];
    records_still_exposed: string[];
    fields_no_longer_exposed: string[];
    fields_still_exposed: string[];
    legitimate_access_kept: string[];
    legitimate_access_lost: string[];
  };
}

export interface RegressionCase {
  id: string;
  fixture_name: string;
  scenario: VulnType;
  fingerprint: string;
  kind: string;
  variation: string;
  description: string;
  input: VariantInput;
  source_variant_id: string;
  source_run_id: string | null;
  source_patch_id: string | null;
  original_outcome: VariantPhaseView;
  patched_outcome: VariantPhaseView;
  times_seen: number;
  last_seen_run_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface ReportListItem {
  report_id: string;
  kind: "baseline" | "proof_of_fix";
  scenario: VulnType;
  status: string;
  verdict: Verdict | null;
  original_vulnerability_reproduced: boolean | null;
  project_id: string;
  patch_id: string | null;
  patch_strategy: string | null;
  created_at: string;
}

/** GET /reports/{id} (JSON). Mirrors backend/app/reports/generator.py build_report(). */
export interface Report {
  report_id: string;
  report_type: string;
  generated_at: string | null;
  project: { id: string; name: string; source_type: string; fixture_name: string | null };
  scan: { id: string; started_at: string; files_scanned: number; findings_count: number } | null;
  finding: {
    id: string; title: string; vuln_type: VulnType; cwe: string; severity: Severity; severity_rationale: string;
    confidence: string; file_path: string; line_start: number; line_end: number; code_snippet: string;
    evidence: Record<string, unknown>; explanation: string; impact: string;
  } | null;
  patch: {
    id: string; strategy: string; status: PatchStatus; rationale: string; diff: string;
    approved_by: string | null; approved_at: string | null;
  } | null;
  verification: {
    kind: "baseline" | "proof_of_fix"; scenario: VulnType; status: string; verdict: Verdict | null;
    verdict_reasons: string[]; original_vulnerability_reproduced: boolean | null;
    exploit_blocked_after_patch: boolean | null; regressions_pass_after_patch: boolean | null;
    phase_summaries: Record<string, PhaseSummary>; error: string | null; duration_ms: number | null;
    tests: Record<string, { security: unknown[]; regression: unknown[] }>;
  };
  known_limitations: string[];
}

// ---------------------------------------------------------------- Kill-chain impact (challenge)
export interface ChainStep {
  step_id: string;
  name: string;
  reached: boolean;
  succeeded: boolean;
  stolen: string[];
  canary_ids: string[];
  actor: string | null;
  status_code: number | null;
  actual: string;
}

export interface BreachBill {
  records_exposed: number;
  records: string[];
  fields_exposed: number;
  fields: string[];
  private_fields_exposed: number;
  owners_affected: string[];
  credentials_stolen: number;
  categories: Record<string, { label: string; count: number; items: string[]; detail: string }>;
  any_exposure: boolean;
  dpdp_references: { provision: string; statutory_maximum_inr: number; statutory_maximum_label: string; caveat: string }[];
  penalty_caveat: string;
}

export interface ChainMatrixRow {
  copy_id: string;
  label: string;
  applied_fixes: string[];
  steps_reached: number;
  reached_final: boolean;
  chain_succeeded: boolean;
  stolen: string[];
  final_records: string[];
  steps: ChainStep[];
  ledger: LedgerRow[];
  breach_bill: BreachBill;
}

export interface ChainImpactResult {
  scenario: string;
  total_steps: number;
  matrix: ChainMatrixRow[];
  best_single_fix: { copy_id: string; label: string; applied_fixes: string[]; steps_reached: number; records_exposed: number } | null;
  canary_records: string;
}

export interface DashboardSummary {
  /** Findings in each project's latest scan without a VERIFIED patch (absent from older backends). */
  open_findings?: number;
  open_findings_by_severity?: Record<Severity, number>;
  total_projects: number;
  total_scans: number;
  total_findings: number;
  findings_by_severity: Record<Severity, number>;
  patches_generated: number;
  patches_verified: number;
  patches_rejected: number;
  verification_runs_by_verdict: Record<Verdict, number>;
  recent_scans: {
    id: string;
    project_id: string;
    project_name: string;
    status: string;
    findings_count: number;
    started_at: string;
  }[];
}

// ---------------------------------------------------------------- Windows Port Inspector
export type PortRisk = "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface PortEntry {
  protocol: string;
  local_address: string;
  port: number | null;
  pid: number | null;
  process_name: string;
  process_path: string | null;
  binding_scope: "localhost" | "specific_interface" | "all_interfaces";
  risk: PortRisk;
  risk_reason: string;
}

export interface PortSummary {
  total: number;
  tcp: number;
  udp: number;
  localhost: number;
  external: number;
  by_risk: Record<PortRisk, number>;
}

export interface HostPortsResult {
  supported: boolean;
  os: string;
  inspected_at: string;
  scope_note: string;
  warning: string | null;
  entries: PortEntry[];
  summary: PortSummary;
}

// ---------------------------------------------------------------- Live Website Security Check
export interface SiteCheckItem {
  name: string;
  status: "PASS" | "WARNING" | "INFO" | "ERROR";
  evidence: string | null;
  explanation: string;
  remediation: string | null;
  checked_at: string | null;
}

export interface SiteCheck {
  id: string;
  url: string;
  host: string;
  authorized: boolean;
  status: "COMPLETED" | "ERROR";
  final_url: string | null;
  resolved_ips: string[];
  redirect_chain: { url: string; status: number }[];
  posture: { counts?: Record<string, number>; summary?: string };
  checks: SiteCheckItem[];
  error: string | null;
  disclaimer: string;
  created_at: string;
  updated_at: string;
}

export interface OllamaStatus {
  available: boolean;
  base_url: string;
  model: string | null;
  model_installed: boolean;
  installed_models: string[];
  message: string;
}

export interface Health {
  status: "ok" | "degraded";
  database: string;
  version: string;
}
