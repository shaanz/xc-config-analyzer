import json
import re
import time

import requests

SYSTEM_PROMPT = (
    "You are a security architect reviewing the security configuration of an F5 Distributed Cloud "
    "(XC) HTTP Load Balancer. You will be given a JSON object describing, for each security feature, "
    "whether it is 'configured', explicitly 'disabled', or 'absent' (never set) on this load balancer, "
    "along with the raw configuration values where present and, where available, the resolved detail "
    "of referenced objects (the App Firewall's AI-enhancement setting, the User Identification rules).\n\n"
    "For each category, decide a verdict:\n"
    "- 'good': configured, and nothing about the value looks risky.\n"
    "- 'missing': absent or explicitly disabled, and this is a real gap worth flagging for an "
    "internet-facing load balancer.\n"
    "- 'review': configured, but the value itself looks weak or risky (e.g. a WAF exclusion rule that "
    "excludes an entire domain/path/signature set rather than a narrow, justified case; a rate limit "
    "with a very high threshold; HSTS disabled on an HTTPS listener).\n"
    "- 'not_applicable': the feature genuinely doesn't apply here (e.g. HSTS on a plain-HTTP listener).\n\n"
    "Pay particular attention to: WAF / AI WAF enhancements, whether any WAF exclusion rule is overly "
    "broad, rate limiting, what the user identification policy actually resolves requests to (name the "
    "actual mechanism — e.g. a specific cookie or header — when the resolved rule data gives you one), "
    "malicious user mitigation, malware protection, sensitive data discovery (and whether it's a custom "
    "policy or just the platform default), L7 DDoS protection, and HSTS.\n\n"
    "Respond with ONLY a JSON object, no prose, no markdown fences, in this exact shape:\n"
    '{"overall_risk": "critical"|"high"|"medium"|"low"|"good", "summary": "<2-3 sentence summary>", '
    '"categories": [{"key": "<category key>", "verdict": "good"|"missing"|"review"|"not_applicable", '
    '"note": "<one short sentence>"}]}'
)


class LLMAnalyzerError(Exception):
    pass


def _extract_json_object(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"```$", "", text).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise LLMAnalyzerError("AI response did not contain a JSON object")
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise LLMAnalyzerError(f"Could not parse AI response as JSON: {exc}") from exc


def _require(base_url: str, model: str, api_key: str) -> None:
    if not base_url:
        raise LLMAnalyzerError("No LLM endpoint configured. Add one on the Settings page.")
    if not model:
        raise LLMAnalyzerError("No LLM model configured. Add one on the Settings page.")
    if not api_key:
        raise LLMAnalyzerError("No LLM API key configured. Add a placeholder value on the Settings page.")


def _chat_completion(base_url: str, api_key: str, model: str, messages: list, timeout: float = 90) -> str:
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
    payload = {"model": model, "messages": messages, "temperature": 0}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        raise LLMAnalyzerError(f"Request to LLM endpoint failed: {exc}") from exc
    if resp.status_code >= 400:
        raise LLMAnalyzerError(f"LLM endpoint returned {resp.status_code}: {resp.text[:300]}")
    try:
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError) as exc:
        raise LLMAnalyzerError(f"Unexpected LLM response shape: {exc}") from exc


def analyze_load_balancer(cfg: dict, namespace: str, lb_name: str, profile: dict, resolved_refs: dict) -> dict:
    base_url = (cfg.get("llm_base_url") or "").rstrip("/")
    api_key = cfg.get("llm_api_key") or ""
    model = cfg.get("llm_model") or ""
    _require(base_url, model, api_key)

    user_payload = {
        "namespace": namespace,
        "load_balancer": lb_name,
        "security_profile": profile,
        "resolved_references": resolved_refs,
    }
    user_prompt = "Analyze this load balancer's security configuration:\n" + json.dumps(user_payload, indent=2)
    text = _chat_completion(
        base_url,
        api_key,
        model,
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    return _extract_json_object(text)


def test_connection(base_url: str, api_key: str, model: str) -> tuple[float, str]:
    """Minimal real completion to verify endpoint/model/key actually work.
    Returns (latency_seconds, reply_text); raises LLMAnalyzerError otherwise."""
    _require(base_url, model, api_key)
    started = time.monotonic()
    text = _chat_completion(
        base_url,
        api_key,
        model,
        [{"role": "user", "content": "Reply with exactly: OK"}],
        timeout=30,
    )
    latency = time.monotonic() - started
    text = text.strip()
    if not text:
        raise LLMAnalyzerError("Connected, but the model returned no content.")
    return latency, text


def list_models(base_url: str, api_key: str) -> list[str]:
    """GET {base_url}/models — the OpenAI-compatible model-listing endpoint."""
    if not base_url:
        raise LLMAnalyzerError("No LLM endpoint configured. Add one on the Settings page.")
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as exc:
        raise LLMAnalyzerError(f"Request to {url} failed: {exc}") from exc
    if resp.status_code >= 400:
        raise LLMAnalyzerError(f"Endpoint returned {resp.status_code} listing models: {resp.text[:300]}")
    try:
        data = resp.json()
        ids = sorted({m["id"] for m in data.get("data", []) if m.get("id")})
    except (ValueError, KeyError, TypeError) as exc:
        raise LLMAnalyzerError(f"Unexpected response shape listing models: {exc}") from exc
    if not ids:
        raise LLMAnalyzerError("Endpoint returned no models.")
    return ids
