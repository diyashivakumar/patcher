import { lazy } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { Empty } from "./components/ui";
import { AppLayout } from "./layouts/AppLayout";

// Route-level code splitting: each page is its own chunk, loaded on first visit.
// The app shell (AppLayout) stays in the main bundle so navigation feels instant,
// and a Suspense fallback inside the shell shows a loader only in the content area.
const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const Projects = lazy(() => import("./pages/Projects").then((m) => ({ default: m.Projects })));
const ProjectDetail = lazy(() => import("./pages/ProjectDetail").then((m) => ({ default: m.ProjectDetail })));
const GitHubImport = lazy(() => import("./pages/GitHubImport").then((m) => ({ default: m.GitHubImport })));
const PortInspector = lazy(() => import("./pages/PortInspector").then((m) => ({ default: m.PortInspector })));
const WebsiteCheck = lazy(() => import("./pages/WebsiteCheck").then((m) => ({ default: m.WebsiteCheck })));
const Scanner = lazy(() => import("./pages/Scanner").then((m) => ({ default: m.Scanner })));
const ScanResults = lazy(() => import("./pages/ScanResults").then((m) => ({ default: m.ScanResults })));
const Findings = lazy(() => import("./pages/Findings").then((m) => ({ default: m.Findings })));
const FindingDetail = lazy(() => import("./pages/FindingDetail").then((m) => ({ default: m.FindingDetail })));
const PatchReview = lazy(() => import("./pages/PatchReview").then((m) => ({ default: m.PatchReview })));
const AttackReplayLab = lazy(() => import("./pages/AttackReplayLab").then((m) => ({ default: m.AttackReplayLab })));
const Gauntlet = lazy(() => import("./pages/Gauntlet").then((m) => ({ default: m.Gauntlet })));
const Forensics = lazy(() => import("./pages/Forensics").then((m) => ({ default: m.Forensics })));
const KillChain = lazy(() => import("./pages/KillChain").then((m) => ({ default: m.KillChain })));
const VerificationResult = lazy(() => import("./pages/VerificationResult").then((m) => ({ default: m.VerificationResult })));
const Reports = lazy(() => import("./pages/Reports").then((m) => ({ default: m.Reports })));

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="projects" element={<Projects />} />
        <Route path="projects/:projectId" element={<ProjectDetail />} />
        <Route path="import/github" element={<GitHubImport />} />
        <Route path="host/ports" element={<PortInspector />} />
        <Route path="website-check" element={<WebsiteCheck />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="scans/:scanId" element={<ScanResults />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:findingId" element={<FindingDetail />} />
        <Route path="patches/:patchId" element={<PatchReview />} />
        <Route path="replay" element={<AttackReplayLab />} />
        <Route path="gauntlet" element={<Gauntlet />} />
        <Route path="forensics" element={<Forensics />} />
        <Route path="kill-chain" element={<KillChain />} />
        <Route path="verification/:runId" element={<VerificationResult />} />
        <Route path="reports" element={<Reports />} />
        <Route path="*" element={<Empty>Page not found. <Link className="text-sky-400" to="/">Go to dashboard</Link></Empty>} />
      </Route>
    </Routes>
  );
}
