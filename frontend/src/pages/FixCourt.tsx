import { useEffect, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Award,
  CheckCircle2,
  Code2,
  Copy,
  Eye,
  Flame,
  Gavel,
  Lock,
  Play,
  RefreshCw,
  Scale,
  ShieldAlert,
  ShieldCheck,
  X,
  XCircle,
} from "lucide-react";
import { CodeBlock } from "../components/CodeBlock";
import { Button, Card, ErrorBox, PageHeader } from "../components/ui";
import { api } from "../services/api";
import type { Candidate, ChallengeTrial, FindingOption, VerdictType } from "../types/challenge";

export function FixCourt() {
  const [findings, setFindings] = useState<FindingOption[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [trial, setTrial] = useState<ChallengeTrial | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Trial Options
  const [useCache, setUseCache] = useState<boolean>(true);
  const [candidateCount, setCandidateCount] = useState<number>(6);

  // Modal / Inspection state
  const [inspectCandidate, setInspectCandidate] = useState<Candidate | null>(null);
  const [evidenceTab, setEvidenceTab] = useState<"diff" | "gauntlet" | "forensics" | "safety">("diff");

  // Judge Mode
  const [showJudgeMode, setShowJudgeMode] = useState<boolean>(false);
  const [judgeCode, setJudgeCode] = useState<string>("");
  const [judgeName, setJudgeName] = useState<string>("");
  const [judgeSubmitting, setJudgeSubmitting] = useState<boolean>(false);
  const [judgeError, setJudgeError] = useState<string | null>(null);

  // Load available findings on mount
  useEffect(() => {
    api
      .listCourtFindings()
      .then((data) => {
        setFindings(data);
        if (data.length > 0 && !selectedFindingId) {
          setSelectedFindingId(data[0].id);
        }
      })
      .catch((err) => {
        setError(err.message || "Failed to load findings for Fix Court");
      });
  }, []);

  const handleRunTrial = async () => {
    if (!selectedFindingId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.runCourtTrial(selectedFindingId, candidateCount, useCache);
      setTrial(res);
    } catch (err: any) {
      setError(err.message || "Failed to run Fix Court trial");
    } finally {
      setLoading(false);
    }
  };

  const handleJudgeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFindingId || !judgeCode.trim()) return;
    setJudgeSubmitting(true);
    setJudgeError(null);
    try {
      const candidate = await api.submitJudgePatch(selectedFindingId, judgeCode, judgeName.trim() || undefined);
      // Prepend to current trial candidates
      if (trial) {
        const updated = {
          ...trial,
          candidates: [candidate, ...trial.candidates],
          total_candidates: trial.total_candidates + 1,
        };
        // Update verdict counts
        const v = candidate.verdict;
        updated.verdict_counts = {
          ...updated.verdict_counts,
          [v]: (updated.verdict_counts[v] || 0) + 1,
        };
        const genuine = updated.verdict_counts["GENUINE"] || 0;
        updated.scoreboard = `${genuine} / ${updated.total_candidates} GENUINE`;
        setTrial(updated);
      }
      setInspectCandidate(candidate);
      setEvidenceTab("diff");
      setJudgeCode("");
      setJudgeName("");
      setShowJudgeMode(false);
    } catch (err: any) {
      setJudgeError(err.message || "Judge submission failed safety or execution tests");
    } finally {
      setJudgeSubmitting(false);
    }
  };

  const selectedFinding = findings.find((f) => f.id === selectedFindingId);

  const getVerdictStyle = (verdict: VerdictType) => {
    switch (verdict) {
      case "GENUINE":
        return {
          bg: "bg-emerald-950/40 border-emerald-500/40 text-emerald-400",
          badge: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40",
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
          label: "GENUINE FIX",
          desc: "Passes original exploit, all Gauntlet variants, regressions, and canary forensics.",
        };
      case "FAKE_FIX":
        return {
          bg: "bg-rose-950/40 border-rose-500/40 text-rose-400",
          badge: "bg-rose-500/20 text-rose-300 border border-rose-500/40",
          icon: <XCircle className="w-5 h-5 text-rose-400" />,
          label: "FAKE FIX",
          desc: "Appears modified but the original demonstration exploit still succeeds.",
        };
      case "BYPASSED":
        return {
          bg: "bg-amber-950/40 border-amber-500/40 text-amber-400",
          badge: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
          label: "BYPASSED",
          desc: "Blocks original payload but fails against Exploit Variant Gauntlet techniques.",
        };
      case "OVER_RESTRICTIVE":
        return {
          bg: "bg-blue-950/40 border-blue-500/40 text-blue-400",
          badge: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
          icon: <Lock className="w-5 h-5 text-blue-400" />,
          label: "OVER-RESTRICTIVE",
          desc: "Stops the attack but breaks legitimate application workflows and authorised access.",
        };
      case "DATA_LEAK":
        return {
          bg: "bg-purple-950/40 border-purple-500/40 text-purple-400",
          badge: "bg-purple-500/20 text-purple-300 border border-purple-500/40",
          icon: <Flame className="w-5 h-5 text-purple-400" />,
          label: "DATA LEAK",
          desc: "Canary Forensics detected protected synthetic tokens in the HTTP response.",
        };
      case "REJECTED_UNSAFE_CODE":
        return {
          bg: "bg-zinc-900 border-zinc-700 text-zinc-400",
          badge: "bg-zinc-800 text-zinc-300 border border-zinc-700",
          icon: <ShieldAlert className="w-5 h-5 text-zinc-400" />,
          label: "REJECTED: UNSAFE",
          desc: "Blocked by AST Safety Gate before execution (eval, forbidden imports, syntax).",
        };
      default:
        return {
          bg: "bg-zinc-900 border-zinc-700 text-zinc-400",
          badge: "bg-zinc-800 text-zinc-300 border border-zinc-700",
          icon: <AlertCircle className="w-5 h-5 text-zinc-400" />,
          label: "INCONCLUSIVE",
          desc: "Execution was inconclusive or encountered an unhandled harness fault.",
        };
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fix Court"
        subtitle="Put AI-written security fixes on trial. Verify whether ChatGPT, Copilot, and LLM patches genuinely eliminate vulnerabilities without bypasses, data leaks, or breaking legitimate users."
      />

      {error && <ErrorBox error={new Error(error)} onRetry={() => setError(null)} />}

      {/* Control Strip & Trial Launch */}
      <Card className="p-5 border-zinc-800 bg-zinc-950/70">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div className="md:col-span-2">
            <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
              1. Vulnerability Finding Under Trial
            </label>
            <select
              value={selectedFindingId}
              onChange={(e) => setSelectedFindingId(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700 text-zinc-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-zinc-500"
            >
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  [{f.severity}] {f.title} ({f.target_function}())
                </option>
              ))}
            </select>
          </div>

          <div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                  Engine
                </label>
                <select
                  value={useCache ? "cached" : "ollama"}
                  onChange={(e) => setUseCache(e.target.value === "cached")}
                  className="w-full bg-zinc-900 border border-zinc-700 text-zinc-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-zinc-500"
                >
                  <option value="cached">Benchmark Batch</option>
                  <option value="ollama">Local Ollama</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                  Batch Size
                </label>
                <select
                  value={candidateCount}
                  onChange={(e) => setCandidateCount(Number(e.target.value))}
                  className="w-full bg-zinc-900 border border-zinc-700 text-zinc-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-zinc-500"
                >
                  <option value={4}>4 Fixes</option>
                  <option value={6}>6 Fixes</option>
                  <option value={8}>8 Fixes</option>
                </select>
              </div>
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              variant="primary"
              className="flex-1 flex items-center justify-center gap-2"
              onClick={handleRunTrial}
              disabled={loading || !selectedFindingId}
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Convening Court...
                </>
              ) : (
                <>
                  <Gavel className="w-4 h-4" />
                  Put Fixes on Trial
                </>
              )}
            </Button>
            <Button
              variant="secondary"
              onClick={() => setShowJudgeMode(!showJudgeMode)}
              title="Submit your own code to face the court"
            >
              <Code2 className="w-4 h-4 text-emerald-400" />
            </Button>
          </div>
        </div>

        {/* Pitch Quote Strip */}
        <div className="mt-4 pt-4 border-t border-zinc-800/80 flex items-center justify-between text-xs text-zinc-400">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-emerald-500" />
            <span className="italic font-serif text-zinc-300">
              "Developers paste fixes straight from ChatGPT and Copilot. Nobody checks whether those fixes actually work. We do."
            </span>
          </div>
          <div className="text-zinc-500 hidden sm:block">
            Evaluating: AST Safety Gate &bull; Exploit Gauntlet &bull; Synthetic Canary Forensics &bull; Functional Regressions
          </div>
        </div>
      </Card>

      {/* Judge Mode Collapsible Drawer */}
      {showJudgeMode && (
        <Card className="p-5 border-emerald-900/50 bg-emerald-950/20 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Gavel className="w-5 h-5 text-emerald-400" />
              <h3 className="font-semibold text-zinc-100">Judge Mode: Trial Your Own AI or Manual Fix</h3>
            </div>
            <button onClick={() => setShowJudgeMode(false)} className="text-zinc-400 hover:text-zinc-200">
              <X className="w-5 h-5" />
            </button>
          </div>

          <p className="text-xs text-zinc-400">
            Paste a replacement function generated by ChatGPT, Claude, Copilot, or hand-written by a developer.
            The code will undergo immediate AST safety checking, isolated sandbox injection, and the Exploit Variant Gauntlet.
          </p>

          {judgeError && <ErrorBox error={new Error(judgeError)} onRetry={() => setJudgeError(null)} />}

          <form onSubmit={handleJudgeSubmit} className="space-y-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Candidate Label (Optional)</label>
              <input
                type="text"
                placeholder="e.g. ChatGPT-4o suggested regex"
                value={judgeName}
                onChange={(e) => setJudgeName(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-1.5 text-sm text-zinc-200"
              />
            </div>

            <div>
              <label className="block text-xs text-zinc-400 mb-1">
                Replacement Python Function (must start with{" "}
                <code className="text-emerald-400 font-mono">def {selectedFinding?.target_function || "search"}(...):</code>)
              </label>
              <textarea
                rows={6}
                value={judgeCode}
                onChange={(e) => setJudgeCode(e.target.value)}
                placeholder={`def ${selectedFinding?.target_function || "search"}(${selectedFinding?.vuln_type === "idor" ? "doc_id" : ""}):\n    # Your replacement implementation here\n    pass`}
                className="w-full bg-zinc-900 border border-zinc-800 rounded p-3 font-mono text-xs text-zinc-200 focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button variant="secondary" type="button" onClick={() => setShowJudgeMode(false)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit" disabled={judgeSubmitting || !judgeCode.trim()}>
                {judgeSubmitting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                Put Candidate on Trial
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Trial Results & Courtroom Scoreboard */}
      {trial && (
        <div className="space-y-6">
          {/* Main Scoreboard Banner */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-xs uppercase tracking-wider text-zinc-400 font-mono">Courtroom Verdict</span>
                <div className="text-3xl font-bold tracking-tight text-zinc-100 flex items-center gap-3 mt-1">
                  <Award className="w-8 h-8 text-emerald-400" />
                  <span>{trial.scoreboard}</span>
                </div>
                <div className="text-xs text-zinc-400 mt-1">
                  Target: <span className="font-mono text-zinc-300">{trial.file_path}</span> &bull; Function:{" "}
                  <span className="font-mono text-emerald-400">{trial.target_function}()</span>
                </div>
              </div>

              {/* Verdict Distribution Pills */}
              <div className="flex flex-wrap gap-2">
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  {trial.verdict_counts["GENUINE"] || 0} Genuine
                </span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
                  {trial.verdict_counts["FAKE_FIX"] || 0} Fake Fix
                </span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                  {trial.verdict_counts["BYPASSED"] || 0} Bypassed
                </span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                  {trial.verdict_counts["OVER_RESTRICTIVE"] || 0} Over-Restrictive
                </span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                  {trial.verdict_counts["DATA_LEAK"] || 0} Data Leak
                </span>
                <span className="px-2.5 py-1 text-xs font-semibold rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                  {trial.verdict_counts["REJECTED_UNSAFE_CODE"] || 0} Unsafe Code
                </span>
              </div>
            </div>
          </div>

          {/* Candidate Courtroom Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {trial.candidates.map((candidate) => {
              const style = getVerdictStyle(candidate.verdict);
              return (
                <div
                  key={candidate.id}
                  className={`border rounded-lg p-4 flex flex-col justify-between transition-all hover:border-zinc-500 ${style.bg}`}
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h4 className="font-semibold text-sm text-zinc-100">{candidate.name}</h4>
                        <div className="text-xs text-zinc-400 font-mono mt-0.5">
                          {candidate.model_name || candidate.source_type}
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 text-xs font-bold rounded ${style.badge}`}>
                        {style.label}
                      </span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed min-h-[36px]">
                      {candidate.verdict_rationale}
                    </p>

                    {/* Verification Indicators */}
                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-2 border-t border-zinc-800/60 font-mono">
                      <div className="flex items-center gap-1.5">
                        {candidate.safety_status === "PASSED" ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                        )}
                        <span className={candidate.safety_status === "PASSED" ? "text-zinc-300" : "text-zinc-500"}>
                          AST Safety
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {candidate.security_passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                        )}
                        <span className={candidate.security_passed ? "text-zinc-300" : "text-rose-400"}>
                          Exploit Blocked
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {candidate.gauntlet_passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        )}
                        <span className={candidate.gauntlet_passed ? "text-zinc-300" : "text-amber-400"}>
                          Gauntlet Variants
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5">
                        {candidate.forensics_clean ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                        )}
                        <span className={candidate.forensics_clean ? "text-zinc-300" : "text-purple-400"}>
                          Canary Clean
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 mt-3 border-t border-zinc-800/80 flex items-center justify-between">
                    <span className="text-[11px] text-zinc-500">
                      {candidate.gauntlet_results.length} tests run
                    </span>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setInspectCandidate(candidate);
                        setEvidenceTab("diff");
                      }}
                      className="text-xs flex items-center gap-1"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Inspect Evidence
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Candidate Detailed Evidence Modal */}
      {inspectCandidate && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
              <div className="flex items-center gap-3">
                <Gavel className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="font-semibold text-zinc-100 flex items-center gap-2">
                    <span>{inspectCandidate.name}</span>
                    <span
                      className={`px-2 py-0.5 text-xs font-bold rounded ${
                        getVerdictStyle(inspectCandidate.verdict).badge
                      }`}
                    >
                      {inspectCandidate.verdict}
                    </span>
                  </h3>
                  <div className="text-xs text-zinc-400 font-mono">
                    Model: {inspectCandidate.model_name || inspectCandidate.source_type} &bull; Safety:{" "}
                    {inspectCandidate.safety_status}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setInspectCandidate(null)}
                className="text-zinc-400 hover:text-zinc-200 p-1 rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex border-b border-zinc-800 bg-zinc-900/30 px-4 text-xs font-medium">
              <button
                onClick={() => setEvidenceTab("diff")}
                className={`py-2.5 px-3 border-b-2 transition-colors ${
                  evidenceTab === "diff"
                    ? "border-emerald-500 text-emerald-400"
                    : "border-transparent text-zinc-400 hover:text-zinc-200"
                }`}
              >
                Unified Diff & Source
              </button>
              <button
                onClick={() => setEvidenceTab("gauntlet")}
                className={`py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
                  evidenceTab === "gauntlet"
                    ? "border-emerald-500 text-emerald-400"
                    : "border-transparent text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>Exploit Gauntlet Tests</span>
                <span className="px-1.5 py-0.2 rounded-full bg-zinc-800 text-[10px]">
                  {inspectCandidate.gauntlet_results.length}
                </span>
              </button>
              <button
                onClick={() => setEvidenceTab("forensics")}
                className={`py-2.5 px-3 border-b-2 transition-colors flex items-center gap-1.5 ${
                  evidenceTab === "forensics"
                    ? "border-emerald-500 text-emerald-400"
                    : "border-transparent text-zinc-400 hover:text-zinc-200"
                }`}
              >
                <span>Canary Forensics</span>
                {inspectCandidate.forensics_results?.canary_detected && (
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                )}
              </button>
              <button
                onClick={() => setEvidenceTab("safety")}
                className={`py-2.5 px-3 border-b-2 transition-colors ${
                  evidenceTab === "safety"
                    ? "border-emerald-500 text-emerald-400"
                    : "border-transparent text-zinc-400 hover:text-zinc-200"
                }`}
              >
                AST Safety Gate
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-4 overflow-y-auto space-y-4 flex-1">
              {/* Rationale Banner */}
              <div className="p-3 bg-zinc-900 border border-zinc-800 rounded text-xs text-zinc-300">
                <span className="font-semibold text-zinc-200">Court Rationale: </span>
                {inspectCandidate.verdict_rationale}
              </div>

              {/* Tab: Diff */}
              {evidenceTab === "diff" && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-zinc-400">
                    <span>Target Function Replacement</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(inspectCandidate.source_code)}
                      className="flex items-center gap-1 hover:text-zinc-200"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      Copy Code
                    </button>
                  </div>
                  {inspectCandidate.diff ? (
                    <CodeBlock code={inspectCandidate.diff} title="Replacement Diff" />
                  ) : (
                    <CodeBlock code={inspectCandidate.source_code} title="Function Source" />
                  )}
                </div>
              )}

              {/* Tab: Gauntlet */}
              {evidenceTab === "gauntlet" && (
                <div className="space-y-3">
                  {inspectCandidate.gauntlet_results.length === 0 ? (
                    <div className="text-center py-8 text-zinc-500 text-xs">
                      No gauntlet execution was performed (candidate was blocked by AST Safety Gate).
                    </div>
                  ) : (
                    <div className="overflow-x-auto border border-zinc-800 rounded">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-zinc-900/80 text-zinc-400 border-b border-zinc-800">
                          <tr>
                            <th className="p-2.5">Status</th>
                            <th className="p-2.5">Category</th>
                            <th className="p-2.5">Payload / Action</th>
                            <th className="p-2.5">HTTP Code</th>
                            <th className="p-2.5">Evidence Details</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800/60 font-mono text-[11px]">
                          {inspectCandidate.gauntlet_results.map((t) => (
                            <tr key={t.payload_id} className="hover:bg-zinc-900/40">
                              <td className="p-2.5">
                                {t.passed ? (
                                  <span className="inline-flex items-center gap-1 text-emerald-400">
                                    <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 text-rose-400">
                                    <XCircle className="w-3.5 h-3.5" /> FAIL
                                  </span>
                                )}
                              </td>
                              <td className="p-2.5 text-zinc-300 uppercase">{t.category.replace("_", " ")}</td>
                              <td className="p-2.5 max-w-[200px] truncate text-zinc-200" title={t.payload}>
                                {t.payload || "N/A"}
                              </td>
                              <td className="p-2.5 text-zinc-400">{t.response_status || "—"}</td>
                              <td className="p-2.5 text-zinc-400 max-w-[300px] truncate" title={t.evidence_snippet || ""}>
                                {t.actual || t.evidence_snippet || "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Forensics */}
              {evidenceTab === "forensics" && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 bg-zinc-900 border border-zinc-800 rounded">
                      <div className="text-xs text-zinc-400">Forensics Cleanliness</div>
                      <div className="text-lg font-bold mt-1 flex items-center gap-2">
                        {inspectCandidate.forensics_clean ? (
                          <span className="text-emerald-400 flex items-center gap-1.5">
                            <ShieldCheck className="w-5 h-5" /> CLEAN (No Leaks)
                          </span>
                        ) : (
                          <span className="text-rose-400 flex items-center gap-1.5">
                            <Flame className="w-5 h-5" /> SYNTHETIC DATA LEAK
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="p-3 bg-zinc-900 border border-zinc-800 rounded">
                      <div className="text-xs text-zinc-400">Protected Canaries Detected</div>
                      <div className="text-lg font-bold text-zinc-200 mt-1">
                        {inspectCandidate.forensics_results?.detected_markers.length || 0}
                      </div>
                    </div>
                  </div>

                  {inspectCandidate.forensics_results?.detected_markers &&
                    inspectCandidate.forensics_results.detected_markers.length > 0 && (
                      <div className="p-3 bg-rose-950/30 border border-rose-900/50 rounded space-y-2">
                        <div className="text-xs font-semibold text-rose-300">Convicting Canary Tokens Discovered:</div>
                        <div className="flex flex-wrap gap-1.5">
                          {inspectCandidate.forensics_results.detected_markers.map((m, i) => (
                            <span key={i} className="px-2 py-0.5 bg-rose-900/40 text-rose-200 font-mono text-[11px] rounded">
                              {m}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              )}

              {/* Tab: Safety */}
              {evidenceTab === "safety" && (
                <div className="space-y-3">
                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-300">Python AST Safety Validator</span>
                      <span
                        className={`px-2 py-0.5 text-xs font-bold rounded ${
                          inspectCandidate.safety_status === "PASSED"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        }`}
                      >
                        {inspectCandidate.safety_status}
                      </span>
                    </div>
                    {inspectCandidate.safety_reason && (
                      <div className="text-xs text-rose-300 font-mono">{inspectCandidate.safety_reason}</div>
                    )}
                  </div>

                  <div className="text-xs text-zinc-400 leading-relaxed">
                    Fix Court strictly forbids candidates containing dangerous builtins (<code>eval</code>, <code>exec</code>, <code>open</code>), dangerous standard modules (<code>os</code>, <code>subprocess</code>, <code>socket</code>, <code>shutil</code>), or dynamic attribute execution (<code>getattr</code>, <code>__subclasses__</code>).
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3 border-t border-zinc-800 bg-zinc-900/40 flex justify-end">
              <Button variant="secondary" onClick={() => setInspectCandidate(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
