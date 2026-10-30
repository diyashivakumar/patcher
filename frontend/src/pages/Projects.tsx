import { FolderGit2, Package, Plus, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button, Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

const inputCls =
  "w-full rounded-xl border border-slate-700/80 bg-slate-900 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 transition focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/20";

export function Projects() {
  const projects = useApi(() => api.listProjects());
  const fixtures = useApi(() => api.fixtures());
  const navigate = useNavigate();
  const create = useAction();
  const upload = useAction();
  const [name, setName] = useState("Student Portal Demo");
  const [fixture, setFixture] = useState("student_portal");
  const [upName, setUpName] = useState("");
  const [upDesc, setUpDesc] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [tab, setTab] = useState<"fixture" | "upload">("fixture");

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    const p = await create.run(() => api.createProject({ name, fixture_name: fixture }));
    if (p) navigate(`/projects/${p.id}`);
  };
  const onUpload = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    const p = await upload.run(() => api.uploadProject(upName, upDesc, file));
    if (p) navigate(`/projects/${p.id}`);
  };

  return (
    <>
      <PageHeader
        title="Projects"
        subtitle="A project is a copy of a codebase that PatchProof scans, patches and verifies."
      />

      {/* Create project card with tabs */}
      <Card className="mb-6 animate-fade-in">
        <div className="mb-5 flex gap-1 rounded-xl bg-slate-950/60 p-1">
          <button
            type="button"
            onClick={() => setTab("fixture")}
            className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-sm font-medium transition-all ${
              tab === "fixture"
                ? "bg-slate-800 text-sky-300 shadow-sm"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            <Package className="h-4 w-4" /> Practice fixture
          </button>
          <button
            type="button"
            onClick={() => setTab("upload")}
            className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-sm font-medium transition-all ${
              tab === "upload"
                ? "bg-slate-800 text-sky-300 shadow-sm"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            <Upload className="h-4 w-4" /> Upload ZIP
          </button>
        </div>

        {tab === "fixture" ? (
          <form onSubmit={onCreate} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-widest text-slate-500">
                Fixture
              </label>
              <select className={inputCls} value={fixture} onChange={(e) => setFixture(e.target.value)}>
                {fixtures.data?.map((f) => (
                  <option key={f.name} value={f.name}>{f.title}</option>
                ))}
              </select>
              {fixtures.data?.find((f) => f.name === fixture)?.description && (
                <p className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-400 leading-relaxed">
                  {fixtures.data?.find((f) => f.name === fixture)?.description}
                </p>
              )}
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-widest text-slate-500">
                Project name
              </label>
              <input
                className={inputCls}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Project name"
                required
              />
            </div>
            <ErrorBox error={create.error} />
            <div className="flex items-center gap-3">
              <Button type="submit" busy={create.busy} disabled={!fixtures.data?.length}>
                <Plus className="h-4 w-4" /> Create project
              </Button>
              <p className="text-xs text-slate-500">
                Fixtures support full Proof-of-Fix verification (exploit replay + regression tests).
              </p>
            </div>
          </form>
        ) : (
          <form onSubmit={onUpload} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-widest text-slate-500">
                  Project name
                </label>
                <input
                  className={inputCls}
                  value={upName}
                  onChange={(e) => setUpName(e.target.value)}
                  placeholder="My App"
                  required
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-widest text-slate-500">
                  Description (optional)
                </label>
                <input
                  className={inputCls}
                  value={upDesc}
                  onChange={(e) => setUpDesc(e.target.value)}
                  placeholder="Short description"
                />
              </div>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-semibold uppercase tracking-widest text-slate-500">
                ZIP file
              </label>
              <label className="flex cursor-pointer flex-col items-center gap-2 rounded-xl border border-dashed border-slate-700 bg-slate-950/40 p-6 text-center transition hover:border-sky-500/50 hover:bg-sky-500/[0.03]">
                <Upload className="h-6 w-6 text-slate-500" />
                <div>
                  <span className="text-sm text-slate-300">{file ? file.name : "Drop a ZIP or click to browse"}</span>
                  <p className="mt-0.5 text-xs text-slate-600">Max 10 MB · .zip only · .env files stripped</p>
                </div>
                <input
                  type="file"
                  accept=".zip"
                  required
                  className="sr-only"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </label>
            </div>
            <ErrorBox error={upload.error} />
            <Button type="submit" busy={upload.busy} disabled={!file}>
              <Upload className="h-4 w-4" /> Upload & create
            </Button>
          </form>
        )}
      </Card>

      {/* All projects */}
      <Card
        title={
          <span className="inline-flex items-center gap-2">
            <FolderGit2 className="h-4 w-4 text-sky-400" />
            All projects
          </span>
        }
        className="animate-fade-in"
      >
        <ErrorBox error={projects.error} onRetry={projects.reload} />
        {projects.loading && <Loading />}
        {projects.data?.length === 0 && <Empty>No projects yet. Create one above to get started.</Empty>}
        {!!projects.data?.length && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead>
                <tr className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="pb-3">Name</th>
                  <th className="pb-3">Source</th>
                  <th className="pb-3">Files</th>
                  <th className="pb-3">Scans</th>
                  <th className="pb-3">Latest findings</th>
                  <th className="pb-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {projects.data.map((p) => (
                  <tr key={p.id} className="border-t border-slate-800/60 group">
                    <td className="py-3">
                      <Link
                        className="font-medium text-sky-400 transition group-hover:text-sky-300 hover:underline"
                        to={`/projects/${p.id}`}
                      >
                        {p.name}
                      </Link>
                    </td>
                    <td className="py-3">
                      <Pill
                        className={
                          p.verification_supported
                            ? "bg-sky-500/10 text-sky-300 ring-sky-500/30"
                            : "bg-slate-700/30 text-slate-300 ring-slate-600"
                        }
                      >
                        {p.source_type === "fixture" ? "Fixture · verifiable" : "Upload · scan only"}
                      </Pill>
                    </td>
                    <td className="py-3 tabular-nums text-slate-400">{p.file_count}</td>
                    <td className="py-3 tabular-nums text-slate-400">{p.scan_count}</td>
                    <td className="py-3 tabular-nums">
                      {p.latest_scan ? (
                        <span className={p.latest_scan.findings_count > 0 ? "text-rose-300" : "text-emerald-300"}>
                          {p.latest_scan.findings_count}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-3 text-xs text-slate-500 tabular-nums">{fmtDate(p.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
