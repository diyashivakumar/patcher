"""Port Inspector tests. PowerShell is mocked; nothing on the host is touched."""
import json

import pytest

from app.host import port_inspector as pi

SAMPLE = [
    {"proto": "TCP", "local": "127.0.0.1", "port": 11434, "pid": 10, "name": "ollama", "path": "C:/ollama.exe"},
    {"proto": "TCP", "local": "0.0.0.0", "port": 445, "pid": 4, "name": "System", "path": None},
    {"proto": "TCP", "local": "192.168.1.5", "port": 8081, "pid": 20, "name": "svc", "path": None},
    {"proto": "UDP", "local": "::1", "port": 53, "pid": 30, "name": "dns", "path": None},
]


def test_classify_sensitive_on_all_interfaces_is_high():
    risk, why = pi.classify("TCP", 445, "all_interfaces")
    assert risk == "HIGH" and "SMB" in why


def test_classify_known_local_is_low():
    risk, _ = pi.classify("TCP", 11434, "localhost")
    assert risk == "LOW"


def test_classify_specific_interface_is_medium():
    assert pi.classify("TCP", 8081, "specific_interface")[0] == "MEDIUM"


def test_binding_scope_detection():
    assert pi._binding_scope("127.0.0.1") == "localhost"
    assert pi._binding_scope("0.0.0.0") == "all_interfaces"
    assert pi._binding_scope("::") == "all_interfaces"
    assert pi._binding_scope("[::1]") == "localhost"
    assert pi._binding_scope("10.0.0.2") == "specific_interface"


def test_inspect_ports_mocked(monkeypatch):
    monkeypatch.setattr(pi, "is_windows", lambda: True)
    monkeypatch.setattr(pi, "_run_powershell", lambda script: json.dumps(SAMPLE))
    result = pi.inspect_ports()
    assert result["supported"] is True
    # TCP + UDP scripts both return the sample, so counts double; just assert classification worked.
    risks = {(e["port"], e["risk"]) for e in result["entries"]}
    assert (445, "HIGH") in risks
    assert (11434, "LOW") in risks
    assert result["summary"]["by_risk"]["HIGH"] >= 1


def test_inspect_ports_non_windows(monkeypatch):
    monkeypatch.setattr(pi, "is_windows", lambda: False)
    monkeypatch.setattr("platform.system", lambda: "Linux")
    result = pi.inspect_ports()
    assert result["supported"] is False
    assert "Windows only" in result["warning"]
    assert result["entries"] == []


def test_powershell_failure_becomes_warning(monkeypatch):
    monkeypatch.setattr(pi, "is_windows", lambda: True)

    def boom(script):
        raise pi.InspectionError("PowerShell exited with code 1: Access denied")

    monkeypatch.setattr(pi, "_run_powershell", boom)
    result = pi.inspect_ports()
    assert result["entries"] == []
    assert "Access denied" in result["warning"]


def test_run_powershell_uses_argument_list(monkeypatch):
    """Guard: the command is an argument list (no shell), carries no user input, and has a timeout."""
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(pi.subprocess, "run", fake_run)
    pi._run_powershell(pi._TCP_SCRIPT)
    assert isinstance(captured["args"], list)
    assert captured["args"][0] == "powershell"
    assert "-NoProfile" in captured["args"] and "-NonInteractive" in captured["args"]
    assert captured["kwargs"]["timeout"] == pi.TIMEOUT_SECONDS
    assert captured["kwargs"].get("shell") in (None, False)


def test_ports_endpoint(client):
    r = client.get("/api/host/ports")
    assert r.status_code == 200
    body = r.json()
    assert "supported" in body and "entries" in body and "summary" in body
