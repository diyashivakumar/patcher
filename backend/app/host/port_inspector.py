"""Windows Port Inspector -- read-only inspection of local listening ports.

Safety:
  * Windows only; on other OSes returns supported=False with a clear message.
  * Uses fixed PowerShell scripts run via a subprocess ARGUMENT LIST (never shell
    interpolation, never user-supplied PowerShell), with a timeout.
  * Read-only: Get-NetTCPConnection / Get-NetUDPEndpoint / Get-Process. Never
    terminates a process, touches the firewall or changes the host.
  * Reports process name/path and PID only -- no environment variables or secrets.

Risk is a transparent heuristic about EXPOSURE, not a vulnerability claim.
"""
import json
import platform
import subprocess
from datetime import datetime, timezone

TIMEOUT_SECONDS = 15

LOOPBACK = {"127.0.0.1", "::1", "127.0.0.1/8"}
ALL_INTERFACES = {"0.0.0.0", "::", "*"}

# Ports that are sensitive to expose on all interfaces (DBs, remote admin, caches, etc.).
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
    1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}
# Common local developer services -> LOW when only on localhost.
KNOWN_LOCAL = {5173: "Vite dev server", 8000: "Dev HTTP/API", 3000: "Dev server",
               11434: "Ollama", 5432: "PostgreSQL", 8080: "Dev HTTP"}

# Fixed scripts -- no interpolation of any external input.
_TCP_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$p=@{};Get-Process|ForEach-Object{$p[$_.Id]=@{name=$_.ProcessName;path=$_.Path}};"
    "Get-NetTCPConnection -State Listen|ForEach-Object{$i=$p[[int]$_.OwningProcess];"
    "[pscustomobject]@{proto='TCP';local=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;"
    "name=$i.name;path=$i.path}}|ConvertTo-Json -Depth 3 -Compress"
)
_UDP_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$p=@{};Get-Process|ForEach-Object{$p[$_.Id]=@{name=$_.ProcessName;path=$_.Path}};"
    "Get-NetUDPEndpoint|ForEach-Object{$i=$p[[int]$_.OwningProcess];"
    "[pscustomobject]@{proto='UDP';local=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;"
    "name=$i.name;path=$i.path}}|ConvertTo-Json -Depth 3 -Compress"
)


class InspectionError(Exception):
    pass


def is_windows():
    return platform.system() == "Windows"


def _run_powershell(script):
    """Run a FIXED PowerShell script read-only; return stdout. Overridable in tests."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise InspectionError("PowerShell was not found on this system.") from exc
    except subprocess.TimeoutExpired as exc:
        raise InspectionError(f"Port inspection timed out after {TIMEOUT_SECONDS}s.") from exc
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip()[-300:]
        raise InspectionError(f"PowerShell exited with code {proc.returncode}: {tail}")
    return proc.stdout


def _parse(raw):
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InspectionError("Could not parse PowerShell output.") from exc
    return data if isinstance(data, list) else [data]


def _binding_scope(local):
    addr = str(local or "").strip().strip("[]")
    if addr in LOOPBACK or addr.startswith("127."):
        return "localhost"
    if addr in ALL_INTERFACES:
        return "all_interfaces"
    return "specific_interface"


def classify(proto, port, scope):
    """Transparent exposure heuristic -> (risk, explanation). Never a vulnerability claim."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = -1
    if scope == "localhost":
        svc = KNOWN_LOCAL.get(port)
        if svc:
            return "LOW", f"Expected local service ({svc}) bound to localhost; not reachable from other machines."
        return "INFO", "Listener bound to localhost only; not reachable from other machines."
    if scope == "specific_interface":
        return "MEDIUM", "Bound to a specific non-loopback interface, so it is reachable from that network."
    # all_interfaces
    if port in SENSITIVE_PORTS:
        return "HIGH", (f"{SENSITIVE_PORTS[port]} is exposed on all interfaces (0.0.0.0/::). "
                        "Sensitive services should usually be bound to localhost or firewalled.")
    return "MEDIUM", "Listening on all interfaces (0.0.0.0/::), so it is reachable from other machines on the network."


def _entries(rows):
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        scope = _binding_scope(r.get("local"))
        risk, why = classify(r.get("proto"), r.get("port"), scope)
        out.append({
            "protocol": r.get("proto", "TCP"),
            "local_address": str(r.get("local") or ""),
            "port": int(r.get("port")) if str(r.get("port") or "").isdigit() else None,
            "pid": int(r.get("pid")) if str(r.get("pid") or "").isdigit() else None,
            "process_name": r.get("name") or "(unknown)",
            "process_path": r.get("path") or None,
            "binding_scope": scope,
            "risk": risk,
            "risk_reason": why,
        })
    out.sort(key=lambda e: (["HIGH", "MEDIUM", "LOW", "INFO"].index(e["risk"]), e["port"] or 0))
    return out


def inspect_ports():
    """Collect listening TCP/UDP ports with risk classification. Always returns a result dict."""
    result = {
        "supported": is_windows(),
        "os": platform.system(),
        "inspected_at": datetime.now(timezone.utc).isoformat(),
        "scope_note": "Inspection is local to this machine only; no external hosts are contacted.",
        "warning": None,
        "entries": [],
        "summary": {},
    }
    if not is_windows():
        result["warning"] = f"Port Inspector supports Windows only; this host reports '{platform.system()}'."
        return result

    rows, warnings = [], []
    for script in (_TCP_SCRIPT, _UDP_SCRIPT):
        try:
            rows.extend(_parse(_run_powershell(script)))
        except InspectionError as exc:
            warnings.append(str(exc))
    if warnings:
        result["warning"] = "; ".join(warnings) + (
            " (listing may be incomplete; run as Administrator for full process details)"
            if any("code" in w or "Access" in w for w in warnings) else "")
    result["entries"] = _entries(rows)
    result["summary"] = summarize(result["entries"])
    return result


def summarize(entries):
    by_risk = {k: 0 for k in ("HIGH", "MEDIUM", "LOW", "INFO")}
    for e in entries:
        by_risk[e["risk"]] += 1
    return {
        "total": len(entries),
        "tcp": sum(1 for e in entries if e["protocol"] == "TCP"),
        "udp": sum(1 for e in entries if e["protocol"] == "UDP"),
        "localhost": sum(1 for e in entries if e["binding_scope"] == "localhost"),
        "external": sum(1 for e in entries if e["binding_scope"] != "localhost"),
        "by_risk": by_risk,
    }
