# PatchProof Threat Model

Scope: the PatchProof platform itself (frontend, backend, runner), run locally by a hackathon team for demonstrations. The deliberately vulnerable fixture is an intended target, not an asset to protect.

## Assets

| Asset | Why it matters |
|---|---|
| Neon credentials (`DATABASE_URL`) | Full access to PatchProof's records |
| Integrity of verification results | The whole value of the product is a trustworthy verdict |
| Uploaded source code | May be a teammate's or user's private code |
| Host machine | Runs the backend and the test subprocess |
| Audit log | Records who approved which patch |

## Threat actors

1. **A malicious ZIP uploader** trying to write outside the storage dir, exhaust disk or memory, or get code executed.
2. **A malicious or buggy patched app** (for example a bad patch that hangs or tries network calls during verification).
3. **A local network attacker** reaching the dev API (it is unauthenticated).
4. **A prompt-injection payload** inside scanned code that reaches the optional LLM.
5. **Accidental insiders**: a teammate committing secrets or pointing the runner at a real system.

## Attack surfaces and mitigations

| Surface | Threat | Mitigation (where) |
|---|---|---|
| `POST /projects/upload` | Zip-slip / path traversal | Rejects absolute paths, drive letters and `..` components; `safe_join` resolves and checks every target (`services/storage.py`) |
| | Symlink escape | Symlink entries rejected |
| | ZIP bomb / disk exhaustion | ≤10 MB upload, ≤50 MB extracted, ≤2000 files, compression ratio ≤100, actual bytes checked against declared size |
| | Secrets stored | `.env*`, keys, certs and `secrets.*` are dropped and reported in `upload_skipped` |
| | Code execution | Uploaded code is only parsed with `ast`, never imported or run. Verification is refused for uploads |
| Scanner | Huge or malicious files | Files over 1 MB and symlinks are skipped; `ast.parse` does not execute code |
| Patch apply | Overwriting changed code | Applies only if the exact original lines are present; atomic write; per-patch backup; explicit `approved: true` + approver name; audit log |
| Verification runner | Hang / resource abuse | Separate subprocess, `VERIFICATION_TIMEOUT_SECONDS` timeout, CPU and memory rlimits on POSIX (`verification/adapter.py`) |
| | Secret exposure to tested code | The subprocess gets a minimal env (PATH, temp dirs, Windows system vars) with no `DATABASE_URL` |
| | Network exploitation of real systems | Runner blocks outbound `connect`/`connect_ex`/`sendto`/`sendmsg`/`create_connection` and DNS lookups (QA-verified); requests use Flask's in-process test client; only local fixture copies are targeted |
| | Tampered or forged results | Backend validates the JSON schema and counts; any anomaly gives `ERROR` + `FAILED`, and a patch is never marked verified on error |
| | Damage to stored project | Runner receives temp **copies** of `original/` and `source/` |
| Fixture data | Real personal data leakage | Seed data is fully synthetic; a fresh SQLite DB is created per phase and deleted |
| Main DB | SQL injection in PatchProof itself | SQLAlchemy ORM with bound parameters throughout |
| | Credential leakage | Env-only configuration; `.env` git-ignored; Neon TLS enforced (`sslmode=require` added for neon.tech hosts) |
| HTML report | Stored XSS from code snippets | All values HTML-escaped; served with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` |
| Frontend | XSS | React escapes by default; no `dangerouslySetInnerHTML` |
| CORS | Cross-site calls from other origins | Allow-list from `FRONTEND_ORIGIN`; only GET and POST; only the `Content-Type` header |
| Ollama | Prompt injection / hallucination | AI output is display-only text, length-capped and labelled advisory; never used for detection, severity, patching or verdicts; the app works when Ollama is down |

## Security assumptions

- The backend binds to localhost during development and demos. **There is no authentication.** The approver name is self-declared and is meant for audit trails, not access control. Do not expose the API to untrusted networks.
- The bundled fixture and the runner are trusted, team-authored code.
- The machine running PatchProof is trusted. On Windows there are no OS-level CPU or memory limits for the runner, only the timeout.
- Ollama, if used, runs locally.

## Known limitations / residual risks

- No user accounts, RBAC or rate limiting on the API.
- The verification subprocess is not a container or VM sandbox. That is acceptable only because it runs trusted fixture code. Running arbitrary uploaded code would require a real sandbox (Docker with `--network none`, gVisor, etc.), which is intentionally out of scope.
- Static analysis covers two vulnerability classes in specific Python/Flask patterns. False negatives outside those patterns are expected.
- Exploit tests are specific payloads. "Blocked" means those attacks are blocked, not that every variant is impossible.
- Project files on disk are not encrypted at rest.
