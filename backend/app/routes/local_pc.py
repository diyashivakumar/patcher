"""Local Windows PC port investigation, firewall vulnerability remediation, and live target testing."""
import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse, urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import get_settings

router = APIRouter(tags=["local Windows PC"])

# Well-known sensitive ports and their vulnerability risks when exposed to network interfaces
SENSITIVE_PORTS = {
    445: {
        "service": "SMB / Direct-Hosted",
        "severity": "CRITICAL",
        "risk": "Remote File Sharing / SMB vulnerability (EternalBlue, WannaCry attack vector)",
        "recommendation": "Block inbound port 445 on external network adapters unless required for domain file shares.",
    },
    135: {
        "service": "RPC Endpoint Mapper",
        "severity": "HIGH",
        "risk": "Remote Procedure Call discovery and potential relay/privilege escalation attacks",
        "recommendation": "Restrict inbound RPC to loopback or trusted domain controllers.",
    },
    139: {
        "service": "NetBIOS Session Service",
        "severity": "HIGH",
        "risk": "NetBIOS name resolution and session hijacking",
        "recommendation": "Disable NetBIOS over TCP/IP and block inbound port 139.",
    },
    3389: {
        "service": "RDP (Remote Desktop)",
        "severity": "CRITICAL",
        "risk": "Remote Desktop protocol exposed without perimeter VPN (Brute force & BlueKeep risk)",
        "recommendation": "Close public RDP access; restrict to VPN or specific management jump-boxes.",
    },
    21: {
        "service": "FTP",
        "severity": "HIGH",
        "risk": "Cleartext credentials and data transmission",
        "recommendation": "Replace with SFTP (SSH) or FTPS; close cleartext port 21.",
    },
    23: {
        "service": "Telnet",
        "severity": "CRITICAL",
        "risk": "Cleartext unencrypted remote terminal protocol",
        "recommendation": "Disable Telnet service immediately; use SSH instead.",
    },
    5985: {
        "service": "WinRM HTTP",
        "severity": "HIGH",
        "risk": "Unencrypted Windows Remote Management listener exposed on network",
        "recommendation": "Switch to WinRM HTTPS (port 5986) and block unencrypted port 5985.",
    },
    5986: {
        "service": "WinRM HTTPS",
        "severity": "MEDIUM",
        "risk": "Remote management interface exposed to untrusted subnets",
        "recommendation": "Restrict inbound firewall access to authorized administrator subnets.",
    },
    1433: {
        "service": "Microsoft SQL Server",
        "severity": "HIGH",
        "risk": "Database listener exposed directly to network without firewall barrier",
        "recommendation": "Bind MS-SQL to loopback (127.0.0.1) or restrict inbound port via firewall.",
    },
    3306: {
        "service": "MySQL Database",
        "severity": "HIGH",
        "risk": "Database listener exposed to external interface",
        "recommendation": "Set bind-address = 127.0.0.1 in my.cnf and block inbound 3306 on external interfaces.",
    },
    5432: {
        "service": "PostgreSQL Database",
        "severity": "HIGH",
        "risk": "Database listener exposed to external interface",
        "recommendation": "Set listen_addresses = 'localhost' in postgresql.conf and block inbound 5432.",
    },
    6379: {
        "service": "Redis In-Memory Store",
        "severity": "CRITICAL",
        "risk": "Redis often lacks authentication by default; external exposure leads to Remote Code Execution",
        "recommendation": "Bind Redis to 127.0.0.1 and block public inbound access to port 6379.",
    },
    27017: {
        "service": "MongoDB Database",
        "severity": "HIGH",
        "risk": "NoSQL database exposed without strict firewall whitelist",
        "recommendation": "Bind MongoDB to 127.0.0.1 and enable auth.",
    },
    8080: {
        "service": "Alternative HTTP / Proxy",
        "severity": "MEDIUM",
        "risk": "Development web service or proxy listener bound to all network interfaces",
        "recommendation": "Review listening application; block inbound traffic if intended for local development only.",
    },
    8000: {
        "service": "Dev Server / API",
        "severity": "MEDIUM",
        "risk": "Development web service bound to all interfaces",
        "recommendation": "Ensure development servers are bound to 127.0.0.1 instead of 0.0.0.0.",
    },
}


def _verify_local_origin(request: Request):
    local = {"localhost", "127.0.0.1", "::1"}
    if not request.client or request.client.host not in local or request.url.hostname not in local:
        raise HTTPException(403, "Port and host inspection is available only on the local machine.")
    origin = request.headers.get("origin")
    allowed = {s.strip() for s in get_settings().FRONTEND_ORIGIN.split(",")}
    if origin and (origin not in allowed or urlsplit(origin).hostname not in local):
        raise HTTPException(403, "Use the configured local frontend to inspect this PC.")


def _get_process_map():
    """Retrieve PID -> Process Name mapping on Windows."""
    proc_map = {}
    try:
        cmd = ["tasklist", "/FO", "CSV", "/NH"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        for line in res.stdout.splitlines():
            parts = line.strip().split('","')
            if len(parts) >= 2:
                name = parts[0].strip('"')
                try:
                    pid = int(parts[1].strip('"'))
                    proc_map[pid] = name
                except ValueError:
                    pass
    except Exception:
        pass
    return proc_map


def _parse_netstat_listeners():
    """Fast netstat parser for TCP listening ports on Windows."""
    listeners = []
    proc_map = _get_process_map()
    try:
        res = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("TCP"):
                continue
            parts = re.split(r"\s+", line)
            # TCP local_addr foreign_addr state PID
            if len(parts) >= 5 and parts[3].upper() == "LISTENING":
                local_addr = parts[1]
                pid_str = parts[4]
                try:
                    pid = int(pid_str)
                except ValueError:
                    pid = 0

                # Split host and port (supports IPv4 and [IPv6]:port)
                if ":" in local_addr:
                    host, port_str = local_addr.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue
                else:
                    continue

                proc_name = proc_map.get(pid, "Unknown")
                listeners.append({
                    "address": host,
                    "port": port,
                    "pid": pid,
                    "process": proc_name,
                })
    except Exception:
        pass
    return listeners


@router.get("/local-pc/ports")
def local_ports(request: Request):
    """Return all active TCP listeners on the local Windows machine with vulnerability analysis."""
    _verify_local_origin(request)
    if os.name != "nt":
        raise HTTPException(409, "This feature requires a backend running on Windows.")

    listeners = _parse_netstat_listeners()
    
    # If netstat returned empty, try PowerShell Get-NetTCPConnection
    if not listeners:
        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$rows = @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
    $entry = $_
    $owner = Get-Process -Id $entry.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{address=$entry.LocalAddress;port=[int]$entry.LocalPort;pid=[int]$entry.OwningProcess;process=if($owner){$owner.ProcessName}else{'Unknown'}}
})
ConvertTo-Json -InputObject $rows -Compress
"""
        try:
            ps_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
            result = subprocess.run(
                [ps_path, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            raw = result.stdout.strip()
            if raw:
                data = json.loads(raw)
                listeners = [data] if isinstance(data, dict) else data
        except Exception:
            pass

    # Enrich each port with security evaluation
    enriched = []
    vulnerable_count = 0
    exposed_count = 0

    for item in listeners:
        addr = item.get("address", "")
        port = item.get("port", 0)
        is_loopback = addr in ("::1", "127.0.0.1") or addr.startswith("127.")
        
        vuln_info = SENSITIVE_PORTS.get(port)
        has_vulnerability = bool(vuln_info and not is_loopback)
        if not is_loopback:
            exposed_count += 1
        if has_vulnerability:
            vulnerable_count += 1

        rule_name = f"PatchProof-Block-TCP-{port}"
        enriched.append({
            "address": addr,
            "port": port,
            "pid": item.get("pid", 0),
            "process": item.get("process", "Unknown"),
            "binding_type": "Loopback only" if is_loopback else "Exposed (Network / 0.0.0.0)",
            "is_loopback": is_loopback,
            "has_vulnerability": has_vulnerability,
            "severity": vuln_info["severity"] if has_vulnerability else ("LOW" if not is_loopback else "SAFE"),
            "service_name": vuln_info["service"] if vuln_info else ("Web Service" if port in (80, 443) else "TCP Service"),
            "risk_description": vuln_info["risk"] if vuln_info else ("Exposed network listener with no access restriction" if not is_loopback else "Local loopback listener (safe from network)"),
            "recommendation": vuln_info["recommendation"] if vuln_info else f"Block inbound TCP port {port} if external network access is not required.",
            "rule_name": rule_name,
        })

    # Sort so vulnerable and exposed ports appear at the top
    enriched.sort(key=lambda x: (not x["has_vulnerability"], x["is_loopback"], x["port"]))

    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "total_listeners": len(enriched),
        "exposed_listeners": exposed_count,
        "vulnerable_listeners": vulnerable_count,
        "ports": enriched,
        "scope": "TCP listeners on local Windows PC with active vulnerability scanning",
    }


class PortRemediationRequest(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    action: str = Field(default="block", pattern="^(block|allow|stop_process)$")
    protocol: str = Field(default="TCP")
    rule_name: str | None = None


@router.post("/local-pc/ports/remediate")
def remediate_port(req: PortRemediationRequest, request: Request):
    """Generate the exact reviewed Windows Firewall PowerShell script and rollback for a port vulnerability."""
    _verify_local_origin(request)
    rule_name = req.rule_name or f"PatchProof-Block-{req.protocol}-{req.port}"

    if req.action == "block":
        ps_script = f"""# PatchProof: Inbound Firewall Block Rule
# Requires Administrator privileges in Windows PowerShell
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$ruleName = '{rule_name}'
Write-Host "Applying PatchProof firewall block on {req.protocol} port {req.port}..."
if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {{
    Write-Host "Updating existing rule: $ruleName"
    Set-NetFirewallRule -Name $ruleName -Enabled True -Action Block -Direction Inbound
}} else {{
    New-NetFirewallRule -Name $ruleName -DisplayName "$ruleName" -Group "PatchProof Security Remediation" -Direction Inbound -Action Block -Protocol {req.protocol} -LocalPort {req.port} -Profile Any -Enabled True
}}
Write-Host "Verification:"
Get-NetFirewallRule -Name $ruleName | Select-Object Name,Enabled,Direction,Action | Format-Table -AutoSize
"""
        rollback_script = f"""# Rollback: Remove the inbound block rule for port {req.port}
#Requires -RunAsAdministrator
$ruleName = '{rule_name}'
Write-Host "Rolling back rule: $ruleName..."
Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
Write-Host "Rule removed successfully. Port {req.port} is no longer blocked by PatchProof."
"""
    elif req.action == "allow":
        ps_script = f"""# PatchProof: Inbound Firewall Allow Rule
# Requires Administrator privileges
#Requires -RunAsAdministrator
$ruleName = 'PatchProof-Allow-{req.protocol}-{req.port}'
New-NetFirewallRule -Name $ruleName -DisplayName "$ruleName" -Group "PatchProof Security Remediation" -Direction Inbound -Action Allow -Protocol {req.protocol} -LocalPort {req.port} -Profile Any -Enabled True
"""
        rollback_script = f"Remove-NetFirewallRule -Name 'PatchProof-Allow-{req.protocol}-{req.port}' -ErrorAction SilentlyContinue\n"
    else:  # stop_process
        ps_script = f"""# PatchProof: Terminate rogue listener process on port {req.port}
$entry = Get-NetTCPConnection -LocalPort {req.port} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($entry) {{
    $proc = Get-Process -Id $entry.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "Stopping process $($proc.ProcessName) (PID $($entry.OwningProcess))..."
    Stop-Process -Id $entry.OwningProcess -Force
}} else {{
    Write-Host "No active listener found on port {req.port}."
}}
"""
        rollback_script = "# Process termination cannot be automatically rolled back; restart the service manually if needed.\n"

    return {
        "port": req.port,
        "action": req.action,
        "rule_name": rule_name,
        "powershell_script": ps_script,
        "rollback_script": rollback_script,
        "filename": f"patchproof-{req.action}-port-{req.port}.ps1",
    }


class LiveScanRequest(BaseModel):
    target_url: str = Field(..., description="Target website or server endpoint (e.g., http://localhost:8000 or https://example.com)")
    probe_endpoints: bool = True


@router.post("/local-pc/live-scan")
def live_website_scan(req: LiveScanRequest, request: Request):
    """Audit a real live website or server endpoint for security headers, sensitive leaks, and endpoint exposures."""
    _verify_local_origin(request)

    url = req.target_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or "localhost"

    # Test basic reachability
    start_time = datetime.now(timezone.utc)
    findings = []
    headers_audit = {}

    try:
        with httpx.Client(timeout=6.0, follow_redirects=True, verify=False) as client:
            resp = client.get(url)
            latency_ms = int(resp.elapsed.total_seconds() * 1000)
            status_code = resp.status_code
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            server_header = resp_headers.get("server", "Hidden / Not Disclosed")
            powered_by = resp_headers.get("x-powered-by")
    except Exception as exc:
        raise HTTPException(400, f"Cannot reach target '{url}': {type(exc).__name__} - {exc}")

    # 1. Security Headers Audit
    # A. Content-Security-Policy
    csp = resp_headers.get("content-security-policy")
    if not csp:
        findings.append({
            "id": "live.missing_csp",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "impact": "Leaves application vulnerable to Cross-Site Scripting (XSS) and unauthorized resource injection.",
            "evidence": "No Content-Security-Policy header returned.",
            "remediation": "Add Content-Security-Policy header with restrictive default-src 'self' directive.",
            "code_fix": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';",
        })
        headers_audit["Content-Security-Policy"] = {"status": "FAIL", "value": None}
    else:
        headers_audit["Content-Security-Policy"] = {"status": "PASS", "value": csp[:60] + "..." if len(csp) > 60 else csp}

    # B. X-Frame-Options (Clickjacking)
    xfo = resp_headers.get("x-frame-options")
    if not xfo:
        findings.append({
            "id": "live.clickjacking",
            "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
            "severity": "MEDIUM",
            "cwe": "CWE-1021",
            "impact": "Attacker can embed the target site in an invisible iframe and trick authenticated users into clicking unauthorized actions.",
            "evidence": "No X-Frame-Options header present in HTTP response.",
            "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN on all HTML responses.",
            "code_fix": "X-Frame-Options: DENY",
        })
        headers_audit["X-Frame-Options"] = {"status": "FAIL", "value": None}
    else:
        headers_audit["X-Frame-Options"] = {"status": "PASS", "value": xfo}

    # C. X-Content-Type-Options
    xcto = resp_headers.get("x-content-type-options")
    if xcto != "nosniff":
        findings.append({
            "id": "live.mime_sniffing",
            "title": "Missing X-Content-Type-Options: nosniff",
            "severity": "LOW",
            "cwe": "CWE-79",
            "impact": "Browser may MIME-sniff response content away from declared Content-Type, enabling XSS via uploaded files.",
            "evidence": f"Header value is '{xcto}' (expected 'nosniff').",
            "remediation": "Configure web server to return X-Content-Type-Options: nosniff.",
            "code_fix": "X-Content-Type-Options: nosniff",
        })
        headers_audit["X-Content-Type-Options"] = {"status": "FAIL", "value": xcto}
    else:
        headers_audit["X-Content-Type-Options"] = {"status": "PASS", "value": "nosniff"}

    # D. Strict-Transport-Security (HSTS)
    if url.startswith("https://"):
        hsts = resp_headers.get("strict-transport-security")
        if not hsts:
            findings.append({
                "id": "live.missing_hsts",
                "title": "Missing Strict-Transport-Security (HSTS)",
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "impact": "Users can be downgraded to cleartext HTTP via SSL-stripping man-in-the-middle attacks.",
                "evidence": "HTTPS response does not include Strict-Transport-Security header.",
                "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                "code_fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
            headers_audit["Strict-Transport-Security"] = {"status": "FAIL", "value": None}
        else:
            headers_audit["Strict-Transport-Security"] = {"status": "PASS", "value": hsts}
    else:
        headers_audit["Strict-Transport-Security"] = {"status": "INFO", "value": "Target is HTTP; HSTS applies to HTTPS"}

    # E. Server Token Leak / Fingerprinting
    if server_header != "Hidden / Not Disclosed" and any(token in server_header.lower() for token in ["werkzeug", "python", "apache", "nginx", "iis", "express", "uvicorn", "kestrel"]):
        findings.append({
            "id": "live.server_fingerprint",
            "title": "Server Software Fingerprint Leaked",
            "severity": "LOW",
            "cwe": "CWE-200",
            "impact": "Exposing server version strings helps attackers identify known CVE vulnerabilities for the specific technology stack.",
            "evidence": f"Server header reveals: '{server_header}'" + (f", X-Powered-By reveals: '{powered_by}'" if powered_by else ""),
            "remediation": "Suppress Server and X-Powered-By headers in web server configuration.",
            "code_fix": "# Nginx: server_tokens off;\n# Express: app.disable('x-powered-by');\n# FastAPI: remove_header(response, 'server')",
        })

    # F. CORS wildcard with credentials
    cors = resp_headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append({
            "id": "live.cors_wildcard",
            "title": "Permissive Wildcard CORS Configuration (*)",
            "severity": "MEDIUM",
            "cwe": "CWE-942",
            "impact": "Any malicious third-party site can make cross-origin requests and read sensitive API data.",
            "evidence": "Access-Control-Allow-Origin: *",
            "remediation": "Specify explicit trusted domains in CORS allowlist rather than wildcard '*'.",
            "code_fix": "Access-Control-Allow-Origin: https://app.yourdomain.com",
        })

    # 2. Endpoint Exposure Probing
    exposed_endpoints = []
    if req.probe_endpoints:
        probe_paths = [
            ("/.env", "Environment Variables File", "CRITICAL"),
            ("/.git/HEAD", "Git Repository Metadata", "CRITICAL"),
            ("/swagger", "Interactive Swagger Docs", "LOW"),
            ("/docs", "FastAPI / OpenAPI Swagger Docs", "LOW"),
            ("/api/health", "Health Status API", "INFO"),
            ("/admin", "Administrative Portal", "MEDIUM"),
            ("/actuator/health", "Spring Boot Actuator", "MEDIUM"),
        ]
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        with httpx.Client(timeout=2.0, verify=False, follow_redirects=False) as probe_client:
            for path, desc, sev in probe_paths:
                try:
                    probe_url = base_origin + path
                    p_resp = probe_client.get(probe_url)
                    if p_resp.status_code in (200, 301, 302):
                        exposed_endpoints.append({
                            "path": path,
                            "url": probe_url,
                            "status": p_resp.status_code,
                            "description": desc,
                            "severity": sev,
                        })
                        if sev in ("CRITICAL", "HIGH"):
                            findings.append({
                                "id": f"live.exposed_{path.replace('/', '_').replace('.', '')}",
                                "title": f"Sensitive Resource Exposed: {path}",
                                "severity": sev,
                                "cwe": "CWE-538",
                                "impact": f"Direct public access to {desc} exposes secrets or infrastructure details.",
                                "evidence": f"HTTP {p_resp.status_code} at {probe_url}",
                                "remediation": f"Block public access to {path} in web server configuration.",
                                "code_fix": f"# Nginx:\nlocation {path} {{ deny all; return 404; }}",
                            })
                except Exception:
                    pass

    # Security Score Calculation (A+ to F)
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    if critical_count > 0:
        grade = "F"
    elif high_count > 0:
        grade = "D"
    elif medium_count >= 2:
        grade = "C"
    elif medium_count == 1:
        grade = "B"
    elif low_count > 0:
        grade = "A-"
    else:
        grade = "A+"

    return {
        "target_url": url,
        "scanned_at": start_time.isoformat(),
        "status_code": status_code,
        "latency_ms": latency_ms,
        "server_banner": server_header,
        "grade": grade,
        "headers_audit": headers_audit,
        "exposed_endpoints": exposed_endpoints,
        "findings_count": len(findings),
        "severity_counts": {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
        },
        "findings": findings,
    }
