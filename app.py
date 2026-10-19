import os
import secrets
import threading
import time

from flask import Flask, Response, redirect, render_template, request, url_for

import config_store
import exporters
import security_fields
from llm_analyzer import LLMAnalyzerError, analyze_load_balancer, list_models, test_connection
from xc_client import XCClient, XCError

app = Flask(__name__)

MAX_LOAD_BALANCERS = 200  # safety cap when "ALL namespaces" pulls a lot of LBs
AI_RETRY_ATTEMPTS = 3
AI_RETRY_BACKOFF_SECONDS = 2.0  # multiplied by attempt number

# No default credentials in source — this repo is public. Both must be set via
# environment (docker run -e / a k8s Secret) or every request is rejected.
BASIC_AUTH_USERNAME = os.environ.get("BASIC_AUTH_USERNAME", "")
BASIC_AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")


@app.before_request
def require_basic_auth():
    """Gates every route except /health. That one's exempt because a k8s
    liveness/readiness probe's httpHeaders only accept literal strings, not a
    Secret reference — authenticating it would mean the real credential has
    to sit in the (public) deployment manifest. /health reveals only process
    liveness, not app data, so this is a reasonable boundary.

    Fails closed otherwise: if the env vars aren't set, every non-health
    request is rejected rather than auth silently becoming a no-op."""
    if request.path == "/health":
        return None
    if not BASIC_AUTH_USERNAME or not BASIC_AUTH_PASSWORD:
        return Response("Basic auth is not configured (BASIC_AUTH_USERNAME/BASIC_AUTH_PASSWORD unset).", 503)
    auth = request.authorization
    valid = (
        auth is not None
        and secrets.compare_digest(auth.username or "", BASIC_AUTH_USERNAME)
        and secrets.compare_digest(auth.password or "", BASIC_AUTH_PASSWORD)
    )
    if not valid:
        return Response(
            "Authentication required.",
            401,
            {"WWW-Authenticate": 'Basic realm="XC Config Analyzer"'},
        )

# Single-process local tool: current inventory + AI results live in memory,
# same pattern as the other local analyzers in this workspace.
STATE = {
    "namespace": None,
    "load_balancers": [],
    "load_error": None,
    "truncated": False,
    "notice": None,
    # "Analyse all with AI" runs in a background thread so a large inventory
    # can't tie up the request long enough to hit a browser/proxy timeout,
    # and the page stays usable while it works through the list.
    "ai_job": {"running": False, "total": 0, "done": 0, "current": None, "cancel": False},
}


def render_index(error=None, notice=None):
    cfg = config_store.load_config()
    namespaces = []
    namespaces_error = None
    if cfg.get("f5_tenant_url") and cfg.get("f5_api_token"):
        try:
            client = XCClient(cfg["f5_tenant_url"], cfg["f5_api_token"])
            namespaces = client.list_namespaces()
        except XCError as exc:
            namespaces_error = str(exc)

    return render_template(
        "index.html",
        namespaces=namespaces,
        namespaces_error=namespaces_error,
        selected_namespace=STATE["namespace"],
        load_balancers=STATE["load_balancers"],
        feature_coverage=security_fields.compute_feature_coverage(STATE["load_balancers"]),
        health_scores=security_fields.compute_health_scores(STATE["load_balancers"]),
        ai_job=STATE["ai_job"],
        error=error or STATE["load_error"],
        truncated=STATE["truncated"],
        notice=notice,
        has_f5_config=bool(cfg.get("f5_tenant_url") and cfg.get("f5_api_token")),
        has_llm_config=bool(cfg.get("llm_base_url") and cfg.get("llm_model") and cfg.get("llm_api_key")),
    )


@app.route("/", methods=["GET"])
def index():
    return render_index()


def _resolve_refs(client: XCClient, profile: dict, spec: dict) -> dict:
    """Follows the app_firewall / user_identification object references so the
    AI pass can reason about their actual content, not just that they exist."""
    resolved = {}

    waf_ref = security_fields.extract_ref(spec, "app_firewall")
    if waf_ref:
        try:
            waf_spec = client.get_app_firewall(waf_ref["namespace"], waf_ref["name"])
            resolved["app_firewall"] = waf_spec
            ai_enabled = "enable_ai_enhancements" in waf_spec
            ai_disabled = "disable_ai_enhancements" in waf_spec
            profile["ai_waf"] = {
                "label": "AI WAF Enhancements",
                "status": security_fields.STATUS_CONFIGURED
                if ai_enabled
                else (security_fields.STATUS_DISABLED if ai_disabled else security_fields.STATUS_ABSENT),
                "field": "enable_ai_enhancements" if ai_enabled else ("disable_ai_enhancements" if ai_disabled else None),
                "value": waf_spec.get("enable_ai_enhancements") or waf_spec.get("disable_ai_enhancements"),
            }
        except XCError as exc:
            resolved["app_firewall_error"] = str(exc)
            profile["ai_waf"] = {"label": "AI WAF Enhancements", "status": "unknown", "field": None, "value": str(exc)}
    else:
        profile["ai_waf"] = {"label": "AI WAF Enhancements", "status": security_fields.STATUS_ABSENT, "field": None, "value": None}

    uid_ref = security_fields.extract_ref(spec, "user_identification")
    if uid_ref:
        try:
            uid_spec = client.get_user_identification(uid_ref["namespace"], uid_ref["name"])
            resolved["user_identification"] = uid_spec
            # Show the resolved rule content, not just the {namespace, name} pointer —
            # that's what "what does this policy actually identify users by" needs.
            if "user_identification" in profile:
                profile["user_identification"]["value"] = {"name": uid_ref["name"], **uid_spec}
        except XCError as exc:
            resolved["user_identification_error"] = str(exc)
            if "user_identification" in profile:
                profile["user_identification"]["status"] = "unknown"
                profile["user_identification"]["value"] = str(exc)

    return resolved


@app.route("/load", methods=["POST"])
def load():
    cfg = config_store.load_config()
    if not (cfg.get("f5_tenant_url") and cfg.get("f5_api_token")):
        return render_index(error="Configure the F5 XC tenant URL and API token in Settings first.")

    selection = request.form.get("namespace", "")
    if not selection:
        return render_index(error="Choose a namespace or 'All namespaces'.")

    try:
        client = XCClient(cfg["f5_tenant_url"], cfg["f5_api_token"])
        if selection == "__ALL__":
            target_namespaces = client.list_namespaces()
        else:
            target_namespaces = [selection]
    except XCError as exc:
        return render_index(error=str(exc))

    load_balancers = []
    truncated = False
    load_error = None
    try:
        for ns in target_namespaces:
            for lb_ref in client.list_load_balancers(ns):
                if len(load_balancers) >= MAX_LOAD_BALANCERS:
                    truncated = True
                    break
                spec, identity = client.get_load_balancer(ns, lb_ref["name"])
                profile = security_fields.build_security_profile(spec)
                resolved_refs = _resolve_refs(client, profile, spec)
                load_balancers.append(
                    {
                        "namespace": identity["namespace"],
                        "name": identity["name"],
                        "domains": spec.get("domains") or [],
                        "spec": spec,
                        "profile": profile,
                        "resolved_refs": resolved_refs,
                        "ai": None,
                    }
                )
            if truncated:
                break
    except XCError as exc:
        load_error = str(exc)

    STATE["namespace"] = selection
    STATE["load_balancers"] = load_balancers
    STATE["load_error"] = load_error
    STATE["truncated"] = truncated

    notice = None
    if not load_error:
        notice = f"Loaded {len(load_balancers)} load balancer(s) across {len(target_namespaces)} namespace(s)."
        if truncated:
            notice += f" Stopped at the {MAX_LOAD_BALANCERS}-LB safety cap — narrow the namespace selection to see the rest."
    return render_index(notice=notice)


def _apply_ai_result(lb: dict, ai_result: dict) -> None:
    lb["ai"] = ai_result
    for cat in ai_result.get("categories", []):
        key = cat.get("key")
        if key in lb["profile"]:
            lb["profile"][key]["ai_verdict"] = cat.get("verdict")
            lb["profile"][key]["ai_note"] = cat.get("note")


def _analyze_one(cfg: dict, lb: dict) -> str | None:
    """Runs the AI pass for one LB, merges it in, and returns an error string (or None)."""
    try:
        result = analyze_load_balancer(cfg, lb["namespace"], lb["name"], lb["profile"], lb["resolved_refs"])
        _apply_ai_result(lb, result)
        return None
    except LLMAnalyzerError as exc:
        lb["ai"] = {"error": str(exc)}
        return str(exc)


def _analyze_one_with_retry(cfg: dict, lb: dict) -> str | None:
    """Retries a transient failure (timeout, connection error, rate limit,
    bad JSON from the model) up to AI_RETRY_ATTEMPTS times with backoff before
    giving up on this one load balancer. By the time this runs, the upfront
    "is AI configured at all" check has already passed, so a failure here is
    presumed transient rather than a permanent misconfiguration."""
    error = None
    for attempt in range(1, AI_RETRY_ATTEMPTS + 1):
        error = _analyze_one(cfg, lb)
        if not error:
            return None
        if attempt < AI_RETRY_ATTEMPTS:
            time.sleep(AI_RETRY_BACKOFF_SECONDS * attempt)
    return error


def _llm_not_configured_message(cfg: dict) -> str | None:
    """Single upfront check shared by both AI routes, so a misconfigured LLM
    fails once with one clear message instead of every load balancer in the
    loaded set independently hitting (and rendering) the same error."""
    if not (cfg.get("llm_base_url") and cfg.get("llm_model") and cfg.get("llm_api_key")):
        return "No AI provider configured yet. Add an endpoint, model, and API key on the Settings page."
    return None


@app.route("/analyze-ai/<namespace>/<name>", methods=["POST"])
def analyze_ai_one(namespace, name):
    cfg = config_store.load_config()
    not_configured = _llm_not_configured_message(cfg)
    if not_configured:
        return render_index(error=not_configured)

    lb = next((x for x in STATE["load_balancers"] if x["namespace"] == namespace and x["name"] == name), None)
    if not lb:
        return render_index(error=f"{namespace}/{name} is not in the current inventory — reload first.")
    error = _analyze_one_with_retry(cfg, lb)
    notice = None if error else f"AI analysis complete for {namespace}/{name}."
    return render_index(notice=notice, error=error)


def _run_ai_batch(cfg: dict, load_balancers: list) -> None:
    """Background-thread worker: walks the loaded inventory one load balancer
    at a time (never in parallel — a shared rate limit or a slow/small local
    model handles one request at a time far more reliably than a burst), with
    retry-with-backoff per LB. Runs outside the request/response cycle so a
    big inventory can't tie up the page long enough to hit a browser or proxy
    timeout, and the app stays usable for everything else while it works."""
    job = STATE["ai_job"]
    consecutive_same_error = 0
    last_error = None
    try:
        for lb in load_balancers:
            if job["cancel"]:
                break
            job["current"] = f"{lb['namespace']}/{lb['name']}"
            err = _analyze_one_with_retry(cfg, lb)
            job["done"] += 1
            if err:
                if err == last_error:
                    consecutive_same_error += 1
                else:
                    consecutive_same_error = 1
                    last_error = err
                # Three in a row with the identical message (even after each one's
                # own retries) means the endpoint itself is down/misconfigured, not
                # a per-LB issue — stop hammering it across the rest of the inventory.
                if consecutive_same_error >= 3:
                    job["current"] = f"Stopped after {consecutive_same_error} identical failures: {last_error}"
                    return
            else:
                consecutive_same_error = 0
                last_error = None
    finally:
        job["running"] = False
        if not job["cancel"] and consecutive_same_error < 3:
            job["current"] = None


@app.route("/analyze-ai-all", methods=["POST"])
def analyze_ai_all():
    cfg = config_store.load_config()
    if not STATE["load_balancers"]:
        return render_index(error="Load an inventory first.")

    not_configured = _llm_not_configured_message(cfg)
    if not_configured:
        return render_index(error=not_configured)

    job = STATE["ai_job"]
    if job["running"]:
        return render_index(notice="AI analysis is already running in the background.")

    job["running"] = True
    job["total"] = len(STATE["load_balancers"])
    job["done"] = 0
    job["current"] = None
    job["cancel"] = False
    threading.Thread(target=_run_ai_batch, args=(cfg, STATE["load_balancers"]), daemon=True).start()

    notice = (
        f"AI analysis started in the background for {job['total']} load balancer(s), one at a time. "
        "Reload this page anytime to see progress — the rest of the app stays usable meanwhile."
    )
    return render_index(notice=notice)


@app.route("/analyze-ai-cancel", methods=["POST"])
def analyze_ai_cancel():
    STATE["ai_job"]["cancel"] = True
    return render_index(notice="Cancelling after the load balancer currently in progress finishes.")


@app.route("/export/csv", methods=["GET"])
def export_csv():
    if not STATE["load_balancers"]:
        return redirect(url_for("index"))
    csv_bytes = exporters.build_csv(STATE["load_balancers"])
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=xc-security-config-analysis.csv"},
    )


@app.route("/export/json", methods=["GET"])
def export_json():
    if not STATE["load_balancers"]:
        return redirect(url_for("index"))
    json_bytes = exporters.build_json(STATE["load_balancers"])
    return Response(
        json_bytes,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=xc-raw-api-data.json"},
    )


def _cfg_from_form(form) -> dict:
    """Builds a working config from submitted form fields, falling back to the
    saved secret when a password field was left blank (same convention as
    save_config) — so Test/Fetch-models can use the real key without forcing
    the user to retype it, and without persisting anything."""
    saved = config_store.load_config()
    cfg = dict(saved)
    cfg["f5_tenant_url"] = form.get("f5_tenant_url", saved.get("f5_tenant_url", "")).strip().rstrip("/")
    cfg["llm_base_url"] = form.get("llm_base_url", saved.get("llm_base_url", "")).strip().rstrip("/")
    cfg["llm_model"] = form.get("llm_model", saved.get("llm_model", "")).strip()
    cfg["f5_api_token"] = form.get("f5_api_token", "").strip() or saved.get("f5_api_token", "")
    cfg["llm_api_key"] = form.get("llm_api_key", "").strip() or saved.get("llm_api_key", "")
    return cfg


def _render_config(cfg: dict, notice=None, f5_test_result=None, llm_test_result=None, available_models=None):
    return render_template(
        "config.html",
        cfg=cfg,
        masked_f5_token=config_store.mask(cfg.get("f5_api_token", "")),
        masked_llm_key=config_store.mask(cfg.get("llm_api_key", "")),
        notice=notice,
        f5_test_result=f5_test_result,
        llm_test_result=llm_test_result,
        available_models=available_models,
        has_f5_config=bool(cfg.get("f5_tenant_url") and cfg.get("f5_api_token")),
        has_llm_config=bool(cfg.get("llm_base_url") and cfg.get("llm_model") and cfg.get("llm_api_key")),
    )


@app.route("/config", methods=["GET"])
def config_screen():
    cfg = config_store.load_config()
    notice = STATE.pop("notice", None)
    return _render_config(cfg, notice=notice)


@app.route("/config/reset", methods=["POST"])
def reset_all():
    """Moving to a different tenant: wipe saved Settings and drop the loaded
    inventory (and every AI result derived from it) so nothing from the
    previous tenant lingers in memory or on disk."""
    config_store.reset_config()
    STATE["namespace"] = None
    STATE["load_balancers"] = []
    STATE["load_error"] = None
    STATE["truncated"] = False
    STATE["notice"] = "Settings and loaded inventory cleared. Ready for a new tenant."
    return redirect(url_for("config_screen"))


@app.route("/config", methods=["POST"])
def save_config():
    cfg = _cfg_from_form(request.form)
    config_store.save_config(cfg)
    STATE["notice"] = "Settings saved."
    return redirect(url_for("config_screen"))


@app.route("/config/test-f5", methods=["POST"])
def test_f5():
    cfg = _cfg_from_form(request.form)
    try:
        client = XCClient(cfg["f5_tenant_url"], cfg["f5_api_token"])
        namespaces = client.list_namespaces()
        result = {"ok": True, "message": f"Connected — found {len(namespaces)} namespace(s): {', '.join(namespaces[:8])}" + (", ..." if len(namespaces) > 8 else "")}
    except XCError as exc:
        result = {"ok": False, "message": str(exc)}
    return _render_config(cfg, f5_test_result=result)


@app.route("/config/test-llm", methods=["POST"])
def test_llm():
    cfg = _cfg_from_form(request.form)
    try:
        latency, reply = test_connection(cfg["llm_base_url"], cfg["llm_api_key"], cfg["llm_model"])
        result = {"ok": True, "message": f"Connected · {latency * 1000:.0f}ms · model replied: {reply[:80]!r}"}
    except LLMAnalyzerError as exc:
        result = {"ok": False, "message": str(exc)}
    return _render_config(cfg, llm_test_result=result)


@app.route("/config/fetch-models", methods=["POST"])
def fetch_models():
    cfg = _cfg_from_form(request.form)
    try:
        models = list_models(cfg["llm_base_url"], cfg["llm_api_key"])
        result = {"ok": True, "message": f"Found {len(models)} model(s)."}
    except LLMAnalyzerError as exc:
        models = None
        result = {"ok": False, "message": str(exc)}
    return _render_config(cfg, llm_test_result=result, available_models=models)


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
