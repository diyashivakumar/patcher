"""Non-invasive website security checks: HTTPS/TLS, security headers, cookies, response config, DNS.

Only normal GET/HEAD requests are made, to a validated + pinned destination. No payloads, no
crawling, no brute forcing. Response bodies are never stored; only header/cookie metadata is kept.
"""
import re
import socket
import ssl
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import certifi
import httpx

from app.sitecheck import ssrf

USER_AGENT = "PatchProof-SiteCheck/0.1 (non-invasive config check)"
TIMEOUT = httpx.Timeout(6.0, connect=5.0)
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 262_144
DISCLAIMER = ("PatchProof performs basic non-invasive configuration checks. "
              "This is not a full penetration test or guarantee that a website is secure.")

SECURITY_HEADERS = {
    "strict-transport-security": "Enforces HTTPS for future visits (HSTS), preventing protocol-downgrade attacks.",
    "content-security-policy": "Restricts where scripts/styles load from, mitigating cross-site scripting (XSS).",
    "x-content-type-options": "`nosniff` stops browsers MIME-sniffing responses into executable types.",
    "x-frame-options": "Prevents the page being framed (clickjacking); CSP `frame-ancestors` is the modern equivalent.",
    "referrer-policy": "Controls how much referrer information is shared with other sites.",
    "permissions-policy": "Restricts powerful browser features (camera, geolocation, etc.).",
}
SENSITIVE_COOKIE = re.compile(r"(token|secret|key|password|auth)", re.I)


def _check(name, status, explanation, evidence=None, remediation=None):
    return {"name": name, "status": status, "evidence": evidence, "explanation": explanation,
            "remediation": remediation, "checked_at": datetime.now(timezone.utc).isoformat()}


def _tls_certificate(host):
    """Direct read-only TLS handshake to the validated IP; returns cert facts or an error."""
    try:
        ips = ssrf.resolve_public_ips(host)
    except ssrf.SSRFError as exc:
        return {"ok": False, "error": str(exc)}
    ctx = ssl.create_default_context(cafile=certifi.where())  # match httpx's trust store (certifi)
    with ssrf.pinned(host, ips):
        try:
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            return {"ok": False, "error": f"certificate verification failed: {exc.verify_message or exc}"}
        except (ssl.SSLError, socket.timeout, OSError) as exc:
            return {"ok": False, "error": f"TLS connection failed: {type(exc).__name__}"}
    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass
    subject = dict(x[0] for x in cert.get("subject", []))
    return {"ok": True, "subject_cn": subject.get("commonName"), "not_after": not_after, "days_left": days_left}


def _fetch(url, method="GET"):
    """Validate, pin and fetch one URL (no auto-redirect). Returns (response, ips) or raises SSRFError."""
    _, host, _ = ssrf.validate_url(url)
    ips = ssrf.resolve_public_ips(host)
    with ssrf.pinned(host, ips):
        client = httpx.Client(timeout=TIMEOUT, verify=True, follow_redirects=False,
                              headers={"User-Agent": USER_AGENT}, max_redirects=0)
        try:
            with client.stream(method, url) as r:
                read = 0
                for chunk in r.iter_raw():
                    read += len(chunk)
                    if read >= MAX_BODY_BYTES:
                        break
                return r, ips
        finally:
            client.close()


def _follow(url):
    """Follow redirects manually, re-validating each hop. Returns (chain, final_response)."""
    chain = []
    seen = set()
    for _ in range(MAX_REDIRECTS + 1):
        if url in seen:
            raise ssrf.SSRFError("Redirect loop detected.")
        seen.add(url)
        resp, _ = _fetch(url)
        chain.append({"url": str(resp.url), "status": resp.status_code})
        if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
            nxt = str(httpx.URL(url).join(resp.headers["location"]))
            ssrf.validate_url(nxt)          # re-validate before following (SSRF on redirects)
            ssrf.resolve_public_ips(urlparse(ssrf.normalize(nxt)).hostname)
            url = nxt
            continue
        return chain, resp
    raise ssrf.SSRFError(f"Too many redirects (> {MAX_REDIRECTS}).")


def run_site_check(url):
    target = ssrf.normalize(url)
    scheme, host, _ = ssrf.validate_url(target)
    result = {"url": target, "host": host, "created_at": datetime.now(timezone.utc).isoformat(),
              "disclaimer": DISCLAIMER, "resolved_ips": [], "final_url": None, "redirect_chain": [],
              "checks": [], "status": "ERROR", "posture": {}}
    checks = result["checks"]

    # E. DNS / reachability
    try:
        ips = ssrf.resolve_public_ips(host)
        result["resolved_ips"] = ips
        checks.append(_check("DNS resolution", "INFO", f"{host} resolves to {len(ips)} public address(es).", evidence=", ".join(ips)))
    except ssrf.SSRFError as exc:
        checks.append(_check("DNS resolution", "ERROR", str(exc), remediation="Only publicly reachable sites can be assessed."))
        result["posture"] = _posture(checks)
        return result

    # A. HTTPS + TLS certificate
    cert = _tls_certificate(host)
    if cert["ok"]:
        checks.append(_check("HTTPS supported", "PASS", "The site completed a valid TLS handshake.",
                             evidence=f"certificate CN={cert.get('subject_cn')}"))
        if cert.get("days_left") is not None:
            if cert["days_left"] < 0:
                checks.append(_check("Certificate validity", "ERROR", "The TLS certificate has expired.",
                                     evidence=f"expired {cert['not_after']}", remediation="Renew the certificate."))
            elif cert["days_left"] < 15:
                checks.append(_check("Certificate validity", "WARNING", "The certificate expires soon.",
                                     evidence=f"{cert['days_left']} days left ({cert['not_after']})", remediation="Renew before expiry."))
            else:
                checks.append(_check("Certificate validity", "PASS", "The certificate is valid and not near expiry.",
                                     evidence=f"{cert['days_left']} days left"))
    else:
        checks.append(_check("HTTPS supported", "WARNING", "HTTPS could not be verified.",
                             evidence=cert.get("error"), remediation="Serve the site over HTTPS with a valid certificate."))

    # A2. HTTP -> HTTPS redirect
    try:
        http_chain, _ = _follow(f"http://{host}/")
        ends_https = http_chain[-1]["url"].startswith("https://")
        checks.append(_check("HTTP to HTTPS redirect", "PASS" if ends_https else "WARNING",
                             "Plain HTTP redirects to HTTPS." if ends_https else "Plain HTTP does not redirect to HTTPS.",
                             evidence=" → ".join(h["url"] for h in http_chain),
                             remediation=None if ends_https else "Redirect all HTTP traffic to HTTPS."))
    except ssrf.SSRFError as exc:
        checks.append(_check("HTTP to HTTPS redirect", "INFO", "Could not evaluate the HTTP redirect.", evidence=str(exc)))

    # Main fetch over the normalized target (for headers / cookies / config)
    try:
        chain, resp = _follow(target if scheme == "https" else f"https://{host}/")
        result["final_url"] = chain[-1]["url"]
        result["redirect_chain"] = chain
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks.append(_check("HTTP status", "INFO" if resp.status_code < 400 else "WARNING",
                             f"Final response HTTP {resp.status_code}.",
                             evidence=" → ".join(f"{h['status']} {h['url']}" for h in chain)))

        # B. Security headers
        for h, why in SECURITY_HEADERS.items():
            if h == "x-frame-options":
                present = h in headers or "frame-ancestors" in headers.get("content-security-policy", "").lower()
                ev = headers.get(h) or ("CSP frame-ancestors present" if present else None)
            else:
                present = h in headers
                ev = headers.get(h)
            checks.append(_check(f"Header: {h}", "PASS" if present else "WARNING",
                                 why, evidence=(ev[:200] if ev else "not set"),
                                 remediation=None if present else f"Add the {h} response header."))

        # C. Cookies
        cookie_findings = _cookies(resp)
        if cookie_findings:
            weak = [c for c in cookie_findings if not (c["secure"] and c["http_only"] and c["same_site"])]
            checks.append(_check("Cookie security", "WARNING" if weak else "PASS",
                                 "Cookies are missing Secure/HttpOnly/SameSite attributes." if weak else "Cookies set Secure, HttpOnly and SameSite.",
                                 evidence="; ".join(f"{c['name']}[{'S' if c['secure'] else '-'}{'H' if c['http_only'] else '-'}{'A' if c['same_site'] else '-'}]" for c in cookie_findings),
                                 remediation=None if not weak else "Set Secure, HttpOnly and SameSite on session cookies."))
        else:
            checks.append(_check("Cookie security", "INFO", "No cookies were set on this response."))

        # D. Technology disclosure + cache
        disclosed = {k: headers[k] for k in ("server", "x-powered-by", "x-aspnet-version") if k in headers}
        checks.append(_check("Technology disclosure", "WARNING" if disclosed else "PASS",
                             "Server/technology version headers are exposed." if disclosed else "No obvious server/technology version headers.",
                             evidence="; ".join(f"{k}: {v}" for k, v in disclosed.items()) or None,
                             remediation=None if not disclosed else "Suppress or genericise Server / X-Powered-By headers."))
        checks.append(_check("Cache-Control", "INFO",
                             "Cache-Control header present." if "cache-control" in headers else "No Cache-Control header on this response.",
                             evidence=headers.get("cache-control")))
    except ssrf.SSRFError as exc:
        checks.append(_check("HTTPS request", "ERROR", str(exc)))

    result["posture"] = _posture(checks)
    result["status"] = "COMPLETED"
    return result


def _cookies(resp):
    findings = []
    for raw in resp.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # noqa: BLE001
            continue
        for name, morsel in jar.items():
            safe = "<redacted-sensitive-name>" if SENSITIVE_COOKIE.search(name) else name
            findings.append({
                "name": safe,
                "secure": bool(morsel["secure"]),
                "http_only": bool(morsel["httponly"]),
                "same_site": (morsel["samesite"] or "").strip() or None,
            })
    return findings


def _posture(checks):
    counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("PASS", "WARNING", "INFO", "ERROR")}
    if counts["ERROR"]:
        level = "needs attention"
    elif counts["WARNING"] >= 3:
        level = "several improvements recommended"
    elif counts["WARNING"]:
        level = "minor improvements recommended"
    else:
        level = "good configuration"
    return {"counts": counts, "summary": level}
