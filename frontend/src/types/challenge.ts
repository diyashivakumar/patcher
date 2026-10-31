export type VerdictType =
  | "GENUINE"
  | "FAKE_FIX"
  | "BYPASSED"
  | "OVER_RESTRICTIVE"
  | "DATA_LEAK"
  | "REJECTED_UNSAFE_CODE"
  | "INCONCLUSIVE";

export type GauntletTestEvidence = {
  payload_id: string;
  name: string;
  payload: string;
  category: "original_exploit" | "variant_gauntlet" | "regression";
  expected: string;
  actual: string;
  passed: boolean;
  exploit_succeeded?: boolean;
  response_status?: number;
  evidence_snippet?: string;
};

export type ForensicsEvidence = {
  canary_detected: boolean;
  detected_markers: string[];
  leaked_excerpts: string[];
  inspected_responses: number;
  clean_responses: number;
};

export type Candidate = {
  id: string;
  challenge_id: string;
  name: string;
  source_type: "ollama" | "cached" | "judge_submission" | "reference";
  model_name?: string;
  source_code: string;
  diff: string;
  safety_status: "PASSED" | "REJECTED";
  safety_reason?: string;
  verdict: VerdictType;
  verdict_rationale: string;
  convicting_test_id?: string;
  security_passed: boolean;
  regression_passed: boolean;
  gauntlet_passed: boolean;
  forensics_clean: boolean;
  gauntlet_results: GauntletTestEvidence[];
  forensics_results?: ForensicsEvidence;
  created_at: string;
};

export type ChallengeTrial = {
  id: string;
  project_id: string;
  finding_id: string;
  vuln_type: string;
  target_function: string;
  file_path: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  total_candidates: number;
  scoreboard: string;
  verdict_counts: Record<string, number>;
  candidates: Candidate[];
  created_at: string;
};

export type FindingOption = {
  id: string;
  project_id: string;
  vuln_type: string;
  title: string;
  severity: string;
  file_path: string;
  line_start: number;
  line_end: number;
  target_function: string;
};
