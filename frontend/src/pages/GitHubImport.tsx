import { Github, Search, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button, Card, ErrorBox, PageHeader, Pill } from "../components/ui";
import { useAction } from "../hooks/useApi";
import { api } from "../services/api";
import type { GitHubRepoInfo } from "../types/api";

const input = "w-full rounded-lg border border-line bg-surface-2/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-brand focus:outline-none";

export function GitHubImport() {
  const [url, setUrl] = useState("");
  const [info, setInfo] = useState<GitHubRepoInfo | null>(null);
  const [branch, setBranch] = useState("");
  const [name, setName] = useState("");
  const lookup = useAction();
  const importRepo = useAction();
  const navigate = useNavigate();

  const onLookup = async (e: FormEvent) => {
    e.preventDefault();
    setInfo(null);
    const r = await lookup.run(() => api.githubRepoInfo(url.trim()));
    if (r) {
      setInfo(r);
      setBranch(r.default_branch);
      setName(r.full_name);
    }
  };

  const onImport = async () => {
    const p = await importRepo.run(() => api.importGithub({ url: url.trim(), branch, name: name.trim() || undefined }));
    if (p) navigate(`/projects/${p.id}`);
  };

  return (
    <>
      <PageHeader
        title="GitHub Repository Import"
        subtitle="Import a public GitHub repository as a project. PatchProof downloads the branch archive and runs it through the same validation and scanning pipeline as a ZIP upload — the imported code is never executed."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={<span className="inline-flex items-center gap-2"><Github className="h-4 w-4 text-brand" /> Repository</span>}>
          <form onSubmit={onLookup} className="space-y-3">
            <input className={input} value={url} onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/owner/repository" required />
            <ErrorBox error={lookup.error} />
            <Button type="submit" variant="secondary" busy={lookup.busy} disabled={!url.trim()}>
              <Search className="h-4 w-4" /> {lookup.busy ? "Looking up…" : "Look up repository"}
            </Button>
            <div className="flex items-start gap-2 rounded-lg border border-line/20 bg-surface-2/30 p-3 text-xs text-slate-500">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>Only <span className="font-mono">github.com</span> public repositories are accepted — lookalike domains are rejected. No token is required, and <span className="font-mono">.git</span>, secrets and non-source files are dropped by the pipeline.</span>
            </div>
          </form>
        </Card>

        <Card title="Import">
          {!info ? (
            <p className="py-6 text-center text-sm text-slate-500">Look up a repository to choose a branch and import it.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <a href={info.html_url} target="_blank" rel="noreferrer" className="font-semibold text-brand hover:underline">{info.full_name}</a>
                <Pill className="bg-verified/15 text-verified ring-verified/40">public</Pill>
              </div>
              {info.description && <p className="text-sm text-slate-400">{info.description}</p>}
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">Branch</label>
                <select className={input} value={branch} onChange={(e) => setBranch(e.target.value)}>
                  {info.branches.map((b) => (
                    <option key={b.name} value={b.name}>{b.name}{b.name === info.default_branch ? " (default)" : ""}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-slate-400">Project name</label>
                <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder={info.full_name} />
              </div>
              <ErrorBox error={importRepo.error} />
              <Button busy={importRepo.busy} onClick={onImport}>
                {importRepo.busy ? "Importing…" : `Import ${branch}`}
              </Button>
              <p className="text-xs text-slate-500">Max 10 MB archive. The code is stored and scanned, but never run.</p>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
