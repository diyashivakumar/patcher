"""Optional local AI assistance through Ollama.

AI output is ADVISORY ONLY. It is used to write friendlier explanations and
remediation notes. It is never used to detect vulnerabilities, assign severity,
generate or apply patches, or decide verification verdicts. Every function here
returns a structured result instead of raising, so the app works without Ollama.
"""
import httpx

from app.config import get_settings

ADVISORY = ("AI-generated, advisory only. Not used for detection, severity, patching or verification. "
            "Check it against the evidence.")
MAX_CHARS = 4000


def _model_matches(configured, installed):
    if not configured:
        return False
    names = {m for m in installed} | {m.split(":")[0] for m in installed if m.endswith(":latest")}
    return configured in names


def status():
    s = get_settings()
    result = {"available": False, "base_url": s.OLLAMA_BASE_URL, "model": s.OLLAMA_MODEL or None,
              "model_installed": False, "installed_models": [], "message": ""}
    try:
        resp = httpx.get(f"{s.OLLAMA_BASE_URL.rstrip('/')}/api/tags", timeout=3.0)
        resp.raise_for_status()
        models = [m.get("name", "") for m in resp.json().get("models", [])]
    except (httpx.HTTPError, ValueError) as exc:
        result["message"] = f"Ollama is not reachable at {s.OLLAMA_BASE_URL} ({type(exc).__name__}). " \
                            "PatchProof works fully without it."
        return result
    result["available"] = True
    result["installed_models"] = models
    result["model_installed"] = _model_matches(s.OLLAMA_MODEL, models)
    if not s.OLLAMA_MODEL:
        result["message"] = "Ollama is running but OLLAMA_MODEL is not set."
    elif not result["model_installed"]:
        result["message"] = f"Model '{s.OLLAMA_MODEL}' is not installed. Run: ollama pull {s.OLLAMA_MODEL}"
    else:
        result["message"] = "Ollama is ready."
    return result


def _prompt(finding):
    return (
        "You are a secure-code reviewer helping a student developer. Explain the following finding in "
        "plain English in under 250 words, using these headings: What is wrong, Why it matters, How to fix. "
        "Only discuss the code shown. Do not claim the issue is confirmed, fixed or verified, and do not "
        "invent line numbers.\n\n"
        f"Vulnerability: {finding.title} ({finding.cwe})\n"
        f"File: {finding.file_path}, lines {finding.line_start}-{finding.line_end}\n"
        f"Scanner explanation: {finding.explanation}\n"
        f"Code:\n```python\n{finding.code_snippet}\n```\n"
    )


def explain_finding(finding):
    st = status()
    base = {"available": False, "model": st["model"], "text": None, "advisory": ADVISORY}
    if not st["available"] or not st["model_installed"]:
        return {**base, "message": st["message"]}
    s = get_settings()
    try:
        resp = httpx.post(
            f"{s.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
            json={"model": s.OLLAMA_MODEL, "prompt": _prompt(finding), "stream": False,
                  "options": {"temperature": 0.2}},
            timeout=s.OLLAMA_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        text = resp.json().get("response")
    except httpx.TimeoutException:
        return {**base, "message": f"Ollama did not answer within {s.OLLAMA_TIMEOUT_SECONDS}s."}
    except (httpx.HTTPError, ValueError) as exc:
        return {**base, "message": f"Ollama request failed ({type(exc).__name__})."}
    if not isinstance(text, str) or not text.strip():
        return {**base, "message": "Ollama returned an empty or malformed response."}
    return {**base, "available": True, "text": text.strip()[:MAX_CHARS], "message": "OK"}
