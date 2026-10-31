"""Candidate generation via local Ollama with cached fallback."""
import re
import httpx
from app.challenge.fixtures import get_cached_candidates
from app.config import get_settings


def _clean_markdown_code(text: str) -> str:
    """Extract code from markdown code fences or return raw text."""
    match = re.search(r"```(?:python)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return text.strip()


def generate_candidates(
    vuln_type: str,
    target_func_name: str,
    original_func_code: str,
    count: int = 8,
    use_cache: bool = True,
    temperature: float = 0.4,
) -> tuple[list[dict], str]:
    """Generate candidate replacement functions.
    
    Returns (candidates_list, source_label).
    If use_cache is True or Ollama fails, returns the cached batch.
    """
    settings = get_settings()
    if use_cache or not settings.OLLAMA_MODEL:
        return get_cached_candidates(vuln_type)[:count], "cached"

    prompt = f"""You are a code security assistant.
A security flaw was detected in this Flask Python function:

```python
{original_func_code}
```

Vulnerability Type: {vuln_type.upper()}
Task: Write a defensive patch for the function `{target_func_name}` that eliminates the security flaw.
IMPORTANT RULES:
- Output ONLY the replacement Python function definition starting with `def {target_func_name}(...):`.
- Do NOT output any explanation, markdown commentary, or extra code.
- Do NOT import any modules. Use existing flask helpers: get_db(), query_one(), request, jsonify, abort.
"""
    generated: list[dict] = []
    temps = [0.2, 0.4, 0.6, 0.7, 0.8, 0.9, 0.3, 0.5]

    try:
        url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate"
        for i in range(min(count, 4)):  # Generate up to 4 live candidates to avoid long timeouts
            t = temps[i % len(temps)]
            payload = {
                "model": settings.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": t},
            }
            resp = httpx.post(url, json={**payload, "think": False}, timeout=10.0)
            if resp.status_code == 400:
                resp = httpx.post(url, json=payload, timeout=10.0)
            if resp.status_code == 200:
                raw_text = resp.json().get("response", "")
                code = _clean_markdown_code(raw_text)
                if code.startswith(f"def {target_func_name}"):
                    generated.append({
                        "name": f"Ollama Candidate #{i + 1} (temp={t})",
                        "source_type": "ollama",
                        "model_name": settings.OLLAMA_MODEL,
                        "source_code": code,
                    })
    except Exception:
        pass

    # If live generation produced candidates, supplement with cached to reach requested count
    if generated:
        needed = count - len(generated)
        if needed > 0:
            cached = get_cached_candidates(vuln_type)[:needed]
            generated.extend(cached)
        return generated, "ollama_hybrid"

    # Fallback to cached batch
    return get_cached_candidates(vuln_type)[:count], "cached_fallback"
