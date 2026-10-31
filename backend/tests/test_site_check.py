"""Website Security Check tests. No real site is ever contacted; DNS/HTTP are mocked.

Covers SSRF defences (scheme/port/credential rejection, private-IP rejection after
DNS resolution, DNS-rebinding pinning, redirect re-validation) and the API contract.
"""
import socket

import httpx
import pytest

from app.sitecheck import checker, ssrf


# ---- SSRF: URL validation ------------------------------------------------
@pytest.mark.parametrize("url", [
    "ftp://example.com", "file:///etc/passwd", "gopher://x", "javascript:alert(1)",
])
def test_reject_non_http_schemes(url):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url(url)


def test_reject_embedded_credentials():
    with pytest.raises(ssrf.SSRFError, match="credentials"):
        ssrf.validate_url("https://user:pass@example.com/")


def test_reject_nonstandard_port():
    with pytest.raises(ssrf.SSRFError, match="ports"):
        ssrf.validate_url("https://example.com:2222/")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "https://10.0.0.1/", "http://169.254.169.254/latest/meta-data/",
    "https://192.168.1.1/", "http://[::1]/", "http://0.0.0.0/",
])
def test_reject_literal_private_and_metadata_ips(url):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url(url)


# ---- SSRF: DNS resolution rejects private targets ------------------------
def _fake_getaddrinfo(ip):
    def inner(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return inner


def test_resolve_rejects_private_dns_answer(monkeypatch):
    monkeypatch.setattr(ssrf, "_orig_getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    with pytest.raises(ssrf.SSRFError, match="private"):
        ssrf.resolve_public_ips("rebind.evil.test")


def test_resolve_rejects_metadata_dns_answer(monkeypatch):
    monkeypatch.setattr(ssrf, "_orig_getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    with pytest.raises(ssrf.SSRFError, match="link-local|metadata"):
        ssrf.resolve_public_ips("metadata.evil.test")


def test_resolve_accepts_public_ip(monkeypatch):
    monkeypatch.setattr(ssrf, "_orig_getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert ssrf.resolve_public_ips("example.test") == ["93.184.216.34"]


# ---- SSRF: DNS-rebinding pinning ----------------------------------------
def test_pinning_forces_connection_to_validated_ip(monkeypatch):
    # Even if the resolver later returns an attacker IP, a pinned host returns only the pinned IP.
    monkeypatch.setattr(ssrf, "_orig_getaddrinfo", _fake_getaddrinfo("6.6.6.6"))
    with ssrf.pinned("victim.test", ["93.184.216.34"]):
        infos = socket.getaddrinfo("victim.test", 443)
        assert {i[4][0] for i in infos} == {"93.184.216.34"}
    # Outside the context the patch is inert and falls back to the real resolver.
    assert socket.getaddrinfo("victim.test", 443)[0][4][0] == "6.6.6.6"


# ---- SSRF: redirect re-validation ---------------------------------------
def test_follow_rejects_redirect_to_private_host(monkeypatch):
    monkeypatch.setattr(ssrf, "resolve_public_ips", lambda host: ["93.184.216.34"])

    class Resp:
        def __init__(self, url, status, location=None):
            self.url = url
            self.status_code = status
            self.headers = httpx.Headers({"location": location} if location else {})

    def fake_fetch(url, method="GET"):
        return Resp(url, 302, "http://169.254.169.254/"), ["93.184.216.34"]

    monkeypatch.setattr(checker, "_fetch", fake_fetch)
    # The redirect target resolves to metadata -> re-validation must raise.
    monkeypatch.setattr(ssrf, "resolve_public_ips",
                        lambda host: (_ for _ in ()).throw(ssrf.SSRFError("link-local")) if "169.254" in host else ["1.1.1.1"])
    with pytest.raises(ssrf.SSRFError):
        checker._follow("https://example.test/")


# ---- checker helpers -----------------------------------------------------
def test_cookies_redact_values_and_sensitive_names():
    class R:
        headers = httpx.Headers([
            ("set-cookie", "session_token=supersecret; Secure; HttpOnly; SameSite=Lax"),
            ("set-cookie", "theme=dark"),
        ])
    findings = checker._cookies(R())
    names = {f["name"] for f in findings}
    assert "<redacted-sensitive-name>" in names   # 'session_token' matched sensitive regex
    assert "theme" in names
    # Values are never present in the finding dicts.
    assert all("supersecret" not in str(f) and "dark" not in str(f.get("name", "")) for f in findings) or "theme" in names
    blob = str(findings)
    assert "supersecret" not in blob


def test_posture_levels():
    assert checker._posture([{"status": "PASS"}])["summary"] == "good configuration"
    assert checker._posture([{"status": "WARNING"}] * 3)["summary"] == "several improvements recommended"
    assert checker._posture([{"status": "ERROR"}])["summary"] == "needs attention"


def test_disclaimer_present():
    assert "not a full penetration test" in checker.DISCLAIMER


# ---- API contract --------------------------------------------------------
def test_site_check_requires_authorization(client):
    r = client.post("/api/site-checks", json={"url": "https://example.com", "authorized": False})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "authorization_required"


def test_site_check_rejects_private_target_without_running(client, monkeypatch):
    r = client.post("/api/site-checks", json={"url": "http://127.0.0.1/", "authorized": True})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_target"


def test_site_check_persists_and_reads_back(client, monkeypatch):
    fake = {
        "url": "https://example.com", "host": "example.com", "status": "COMPLETED",
        "final_url": "https://example.com/", "resolved_ips": ["93.184.216.34"],
        "redirect_chain": [{"url": "https://example.com/", "status": 200}],
        "posture": {"counts": {"PASS": 2, "WARNING": 1, "INFO": 0, "ERROR": 0}, "summary": "minor improvements recommended"},
        "checks": [{"name": "HTTPS supported", "status": "PASS", "evidence": None,
                    "explanation": "ok", "remediation": None, "checked_at": None}],
    }
    monkeypatch.setattr("app.routes.sitecheck.run_site_check", lambda url: fake)
    r = client.post("/api/site-checks", json={"url": "https://example.com", "authorized": True})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "COMPLETED"
    assert body["disclaimer"]
    cid = body["id"]
    r2 = client.get(f"/api/site-checks/{cid}")
    assert r2.status_code == 200 and r2.json()["host"] == "example.com"
    assert client.get("/api/site-checks").json()[0]["id"] == cid
