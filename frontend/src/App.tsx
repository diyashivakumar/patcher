import { Link, Route, Routes } from "react-router-dom";
import { Empty } from "./components/ui";
import { AppLayout } from "./layouts/AppLayout";
import { AttackReplayLab } from "./pages/AttackReplayLab";
import { Dashboard } from "./pages/Dashboard";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { FixCourt } from "./pages/FixCourt";
import { LocalPC } from "./pages/LocalPC";
import { PatchReview } from "./pages/PatchReview";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Projects } from "./pages/Projects";
import { Reports } from "./pages/Reports";
import { Scanner } from "./pages/Scanner";
import { ScanResults } from "./pages/ScanResults";
import { VerificationResult } from "./pages/VerificationResult";

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="projects" element={<Projects />} />
        <Route path="projects/:projectId" element={<ProjectDetail />} />
        <Route path="court" element={<FixCourt />} />
        <Route path="local-pc" element={<LocalPC />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="scans/:scanId" element={<ScanResults />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:findingId" element={<FindingDetail />} />
        <Route path="patches/:patchId" element={<PatchReview />} />
        <Route path="replay" element={<AttackReplayLab />} />
        <Route path="verification/:runId" element={<VerificationResult />} />
        <Route path="reports" element={<Reports />} />
        <Route path="*" element={<Empty>Page not found. <Link className="text-sky-400" to="/">Go to dashboard</Link></Empty>} />
      </Route>
    </Routes>
  );
}
