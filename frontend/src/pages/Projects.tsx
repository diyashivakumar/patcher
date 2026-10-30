import { Package, Upload } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  fmtDate,
  Loading,
  PageHeader,
  Pill,
} from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

const input =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none";

const MAX_UPLOAD_MB = 10; // mirrors backend MAX_UPLOAD_MB default

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
  const [fileError, setFileError] = useState("");

  // Fast feedback only; the backend re-validates everything (size, type, traversal, bombs, secrets).
  const pickFile = (f: File | null) => {
    setFile(null);
    setFileError("");
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".zip"))
      return setFileError("Only .zip archives are accepted.");
    if (f.size > MAX_UPLOAD_MB * 1024 * 1024)
      return setFileError(
        `The ZIP is ${(f.size / 1048576).toFixed(1)} MB; the limit is ${MAX_UPLOAD_MB} MB.`,
      );
    if (f.size === 0) return setFileError("The selected file is empty.");
    setFile(f);
  };

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    const p = await create.run(() =>
      api.createProject({ name, fixture_name: fixture }),
    );
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
      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title={
            <span className="inline-flex items-center gap-2">
              <Package className="h-4 w-4 text-sky-400" />
              New project from practice fixture
            </span>
          }
        >
          <form onSubmit={onCreate} className="space-y-3">
            <select
              aria-label="Practice fixture"
              className={input}
              value={fixture}
              onChange={(e) => setFixture(e.target.value)}
            >
              {fixtures.data?.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.title}
                </option>
              ))}
            </select>
            <p className="text-xs text-slate-400">
              {fixtures.data?.find((f) => f.name === fixture)?.description}
            </p>
            <input
              aria-label="Fixture project name"
              className={input}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Project name"
              required
            />
            <ErrorBox error={create.error} />
            <Button
              type="submit"
              busy={create.busy}
              disabled={!fixtures.data?.length}
            >
              Create project
            </Button>
            <p className="text-xs text-slate-500">
              Fixtures support full Proof-of-Fix verification (exploit replay +
              regression tests).
            </p>
          </form>
        </Card>
        <Card
          title={
            <span className="inline-flex items-center gap-2">
              <Upload className="h-4 w-4 text-sky-400" />
              Upload a ZIP of Python code
            </span>
          }
        >
          <form onSubmit={onUpload} className="space-y-3">
            <input
              aria-label="Upload project name"
              className={input}
              value={upName}
              onChange={(e) => setUpName(e.target.value)}
              placeholder="Project name"
              required
            />
            <input
              aria-label="Upload description"
              className={input}
              value={upDesc}
              onChange={(e) => setUpDesc(e.target.value)}
              placeholder="Description (optional)"
            />
            <input
              aria-label="Python project ZIP archive"
              type="file"
              accept=".zip"
              required
              onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
              className="block w-full text-sm text-slate-400 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-slate-200"
            />
            {fileError && <p className="text-sm text-rose-300">{fileError}</p>}
            <ErrorBox error={upload.error} />
            <Button type="submit" busy={upload.busy} disabled={!file}>
              Upload & create
            </Button>
            <p className="text-xs text-slate-500">
              Max 10 MB. Uploaded code is scanned and can be patched, but is
              never executed. Secrets like .env are discarded.
            </p>
          </form>
        </Card>
      </div>

      <Card title="All projects" className="mt-6">
        <ErrorBox error={projects.error} onRetry={projects.reload} />
        {projects.loading && <Loading />}
        {projects.data?.length === 0 && <Empty>No projects yet.</Empty>}
        {!!projects.data?.length && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {projects.data.map((p) => (
              <Link
                key={p.id}
                to={`/projects/${p.id}`}
                className="project-tile"
              >
                <div className="flex items-center justify-between gap-3">
                  <Package size={21} className="text-sky-400" />
                  <Pill className="border-command-border text-slate-400">
                    {p.source_type === "fixture" ? "FIXTURE" : "UPLOAD"}
                  </Pill>
                </div>
                <h3 className="mt-5 text-base font-medium text-white">
                  {p.name}
                </h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">
                  {p.description ?? "Source code investigation target"}
                </p>
                <div className="mt-5 grid grid-cols-3 gap-3 border-y border-command-border py-4 text-xs">
                  <div>
                    <b className="text-slate-200">{p.file_count}</b>
                    <span className="mt-1 block text-[10px] text-slate-500">
                      Files
                    </span>
                  </div>
                  <div>
                    <b className="text-slate-200">{p.scan_count}</b>
                    <span className="mt-1 block text-[10px] text-slate-500">
                      Scans
                    </span>
                  </div>
                  <div>
                    <b
                      className={
                        p.latest_scan?.findings_count
                          ? "text-amber-300"
                          : "text-slate-200"
                      }
                    >
                      {p.latest_scan?.findings_count ?? "—"}
                    </b>
                    <span className="mt-1 block text-[10px] text-slate-500">
                      Latest findings
                    </span>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap justify-between gap-2 text-[10px] text-slate-500">
                  <span>
                    {p.verification_supported
                      ? "Proof-of-Fix supported"
                      : "Static analysis only"}
                  </span>
                  <span>{(p.total_bytes / 1024).toFixed(1)} KB</span>
                </div>
                <time
                  className="mt-3 block font-mono text-[9px] text-slate-500"
                  dateTime={p.created_at}
                >
                  {fmtDate(p.created_at)}
                </time>
                <span className="panel-link mt-4">Open investigation →</span>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
