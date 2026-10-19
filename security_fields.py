"""Maps a raw F5 XC http_loadbalancer spec onto the security-feature checklist.

Field names are taken directly from the published
ves.io.schema.views.http_loadbalancer.GetSpecType schema
(https://docs.cloud.f5.com/docs-v2/api/views-http-loadbalancer). Each checker
below reports whether a feature is configured, explicitly disabled, or simply
absent from the spec, plus whatever raw sub-object is present so the LLM pass
can reason about the actual values rather than just presence/absence.
"""

STATUS_CONFIGURED = "configured"
STATUS_DISABLED = "disabled"
STATUS_ABSENT = "absent"


def _present(spec: dict, *keys: str):
    for key in keys:
        if key in spec:
            return key, spec[key]
    return None, None


def _oneof(spec: dict, enabled_keys, disabled_keys) -> dict:
    key, value = _present(spec, *enabled_keys)
    if key is not None:
        return {"status": STATUS_CONFIGURED, "field": key, "value": value}
    key, value = _present(spec, *disabled_keys)
    if key is not None:
        return {"status": STATUS_DISABLED, "field": key, "value": value}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def _flag(spec: dict, key: str) -> dict:
    """For fields that carry real list/object content (as opposed to Empty-type
    boolean markers like disable_waf, where `{}` IS the meaningful value —
    those go through `_oneof`, never this). F5 XC appears to always emit several
    of these keys with an empty placeholder ([] or {}) even when the user never
    touched the feature, so presence alone isn't "configured" — the content has
    to be non-empty too."""
    value = spec.get(key)
    if value:
        return {"status": STATUS_CONFIGURED, "field": key, "value": value}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_waf(spec: dict) -> dict:
    return _oneof(spec, ["app_firewall"], ["disable_waf"])


def check_waf_exclusion(spec: dict) -> dict:
    # waf_exclusion is a wrapper object; its own content is a oneof of
    # waf_exclusion_inline_rules / waf_exclusion_policy (ref). Confirmed
    # against real tenant data: waf_exclusion_inline_rules is ITSELF a
    # wrapper ({"rules": [...]})  , not the array directly — F5 emits
    # {"waf_exclusion_inline_rules": {"rules": []}} on effectively every load
    # balancer, so the array one level down has to be non-empty, not just the
    # two wrapper dicts around it.
    value = spec.get("waf_exclusion")
    if not isinstance(value, dict) or not value:
        return {"status": STATUS_ABSENT, "field": None, "value": None}
    inline_rules = value.get("waf_exclusion_inline_rules")
    rules = inline_rules.get("rules") if isinstance(inline_rules, dict) else None
    if rules or value.get("waf_exclusion_policy"):
        return {"status": STATUS_CONFIGURED, "field": "waf_exclusion", "value": value}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_rate_limit(spec: dict) -> dict:
    return _oneof(spec, ["rate_limit", "api_rate_limit"], ["disable_rate_limit"])


def check_user_identification(spec: dict) -> dict:
    result = _oneof(spec, ["user_identification", "user_id_client_ip"], [])
    # user_id_client_ip's value is always the Empty marker ({}), which reads
    # as "no details" in the UI even though the policy itself is simple and
    # fully described by its name — give it a human-readable value instead.
    # The user_identification ref branch gets its real detail filled in later
    # by _resolve_refs, once the referenced object has been fetched.
    if result["field"] == "user_id_client_ip":
        result["value"] = "Uses the client IP address as the user identifier"
    return result


def check_malicious_user_detection(spec: dict) -> dict:
    return _oneof(spec, ["enable_malicious_user_detection"], ["disable_malicious_user_detection"])


def check_l7_ddos(spec: dict) -> dict:
    related = {
        k: spec[k]
        for k in (
            "l7_ddos_protection",
            "ddos_mitigation_rules",
            "slow_ddos_mitigation",
            "l7_ddos_action_block",
            "l7_ddos_action_default",
            "l7_ddos_action_js_challenge",
        )
        if k in spec
    }
    if related:
        return {"status": STATUS_CONFIGURED, "field": ",".join(related.keys()), "value": related}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_bot_defense(spec: dict) -> dict:
    result = _oneof(spec, ["bot_defense", "bot_defense_advanced_protection"], ["disable_bot_defense"])
    return result


def check_client_side_defense(spec: dict) -> dict:
    return _oneof(spec, ["client_side_defense"], ["disable_client_side_defense"])


def check_hsts(spec: dict) -> dict:
    for tls_key in ("https", "https_auto_cert"):
        if tls_key in spec and isinstance(spec[tls_key], dict):
            add_hsts = spec[tls_key].get("add_hsts")
            if add_hsts:
                return {"status": STATUS_CONFIGURED, "field": f"{tls_key}.add_hsts", "value": True}
            return {"status": STATUS_DISABLED, "field": f"{tls_key}.add_hsts", "value": add_hsts}
    if "http" in spec:
        return {"status": STATUS_ABSENT, "field": "http", "value": "plain HTTP listener, HSTS not applicable"}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def _wrapped_policy(spec: dict, field: str, disabled_key: str = "disabled") -> dict:
    """For policy objects that are ALWAYS present on the spec (not a top-level
    oneof like WAF/rate_limit) but wrap their own enabled/disabled state one
    level down — e.g. csrf_policy is always set, but its *contents* are one of
    {all_load_balancer_domains, custom_domain_list, disabled}. Checking only
    "is the key present" (as a plain _flag) is wrong here: it reports
    'configured' even when the policy's own content says disabled."""
    policy = spec.get(field)
    if not isinstance(policy, dict):
        return {"status": STATUS_ABSENT, "field": None, "value": None}
    if disabled_key in policy:
        return {"status": STATUS_DISABLED, "field": f"{field}.{disabled_key}", "value": policy[disabled_key]}
    if not policy:
        return {"status": STATUS_ABSENT, "field": None, "value": None}
    return {"status": STATUS_CONFIGURED, "field": field, "value": policy}


def check_csrf_policy(spec: dict) -> dict:
    return _wrapped_policy(spec, "csrf_policy")


def check_cors_policy(spec: dict) -> dict:
    return _wrapped_policy(spec, "cors_policy")


def check_cookie_protection(spec: dict) -> dict:
    return _flag(spec, "protected_cookies")


def check_api_discovery(spec: dict) -> dict:
    return _oneof(spec, ["enable_api_discovery"], ["disable_api_discovery"])


def check_api_protection_rules(spec: dict) -> dict:
    related = {k: spec[k] for k in ("api_protection_rules", "api_specification", "api_testing") if spec.get(k)}
    if related:
        return {"status": STATUS_CONFIGURED, "field": ",".join(related.keys()), "value": related}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_malware_protection(spec: dict) -> dict:
    return _oneof(spec, ["malware_protection_settings"], ["disable_malware_protection"])


def check_data_guard(spec: dict) -> dict:
    return _flag(spec, "data_guard_rules")


def check_sensitive_data_discovery(spec: dict) -> dict:
    # default_sensitive_data_policy turns out to be present on effectively
    # every load balancer regardless of whether the user ever touched this
    # feature, so — unlike real Empty-marker booleans such as disable_waf —
    # its presence isn't a meaningful signal. Only a genuinely custom policy,
    # or an explicit disclosure-rules list, counts as "configured" here.
    if spec.get("sensitive_data_policy"):
        return {"status": STATUS_CONFIGURED, "field": "sensitive_data_policy", "value": spec["sensitive_data_policy"]}
    if spec.get("sensitive_data_disclosure_rules"):
        return {
            "status": STATUS_CONFIGURED,
            "field": "sensitive_data_disclosure_rules",
            "value": spec["sensitive_data_disclosure_rules"],
        }
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_jwt_validation(spec: dict) -> dict:
    return _flag(spec, "jwt_validation")


def check_ip_reputation_threat_mesh(spec: dict) -> dict:
    related = {}
    for enabled, disabled in (
        ("enable_ip_reputation", "disable_ip_reputation"),
        ("enable_threat_mesh", "disable_threat_mesh"),
        ("enable_trust_client_ip_headers", "disable_trust_client_ip_headers"),
    ):
        if enabled in spec:
            related[enabled] = spec[enabled]
        elif disabled in spec:
            related[disabled] = spec[disabled]
    if not related:
        return {"status": STATUS_ABSENT, "field": None, "value": None}
    configured = any(k.startswith("enable_") for k in related)
    return {
        "status": STATUS_CONFIGURED if configured else STATUS_DISABLED,
        "field": ",".join(related.keys()),
        "value": related,
    }


def check_challenge_mechanism(spec: dict) -> dict:
    related = {
        k: spec[k]
        for k in ("js_challenge", "captcha_challenge", "policy_based_challenge", "enable_challenge")
        if k in spec
    }
    if related:
        return {"status": STATUS_CONFIGURED, "field": ",".join(related.keys()), "value": related}
    if "no_challenge" in spec:
        return {"status": STATUS_DISABLED, "field": "no_challenge", "value": True}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


def check_trusted_blocked_clients(spec: dict) -> dict:
    related = {k: spec[k] for k in ("trusted_clients", "blocked_clients") if spec.get(k)}
    if related:
        return {"status": STATUS_CONFIGURED, "field": ",".join(related.keys()), "value": related}
    return {"status": STATUS_ABSENT, "field": None, "value": None}


# (slug, label, checker) — order drives display order.
SECURITY_CHECKS = [
    ("waf", "WAF / App Firewall", check_waf),
    ("ai_waf", "AI WAF Enhancements", None),  # resolved separately via the app_firewall object
    ("waf_exclusion", "WAF Exclusion Rules", check_waf_exclusion),
    ("rate_limit", "Rate Limiting", check_rate_limit),
    ("user_identification", "User Identification Policy", check_user_identification),
    ("malicious_user_detection", "Malicious User Mitigation", check_malicious_user_detection),
    ("l7_ddos", "L7 DDoS Protection", check_l7_ddos),
    ("bot_defense", "Bot Defense", check_bot_defense),
    ("client_side_defense", "Client-Side Defense", check_client_side_defense),
    ("hsts", "HSTS", check_hsts),
    ("csrf_policy", "CSRF Policy", check_csrf_policy),
    ("cors_policy", "CORS Policy", check_cors_policy),
    ("cookie_protection", "Cookie Protection", check_cookie_protection),
    ("api_discovery", "API Discovery", check_api_discovery),
    ("api_protection_rules", "API Protection Rules", check_api_protection_rules),
    ("malware_protection", "Malware Protection", check_malware_protection),
    ("data_guard", "Data Guard", check_data_guard),
    ("sensitive_data_discovery", "Sensitive Data Discovery", check_sensitive_data_discovery),
    ("jwt_validation", "JWT Validation", check_jwt_validation),
    ("ip_rep_threat_mesh", "IP Reputation / Threat Mesh", check_ip_reputation_threat_mesh),
    ("challenge", "Challenge Mechanisms (JS/Captcha/Policy)", check_challenge_mechanism),
    ("trusted_blocked_clients", "Trusted / Blocked Clients", check_trusted_blocked_clients),
]


def build_security_profile(spec: dict) -> dict:
    """Runs every static (non-ref-resolving) checker against one LB spec."""
    profile = {}
    for slug, label, checker in SECURITY_CHECKS:
        if checker is None:
            continue
        result = checker(spec)
        profile[slug] = {"label": label, **result}
    return profile


def compute_feature_coverage(load_balancers: list) -> list:
    """For each security feature seen across the loaded inventory, how many
    load balancers have it 'configured' — sorted worst-covered first so the
    biggest gaps are the most visible."""
    total = len(load_balancers)
    if total == 0:
        return []

    labels = {}
    counts = {}
    for lb in load_balancers:
        for key, item in lb.get("profile", {}).items():
            labels[key] = item.get("label", key)
            if item.get("status") == STATUS_CONFIGURED:
                counts[key] = counts.get(key, 0) + 1

    coverage = []
    for key, label in labels.items():
        count = counts.get(key, 0)
        pct = round(count / total * 100, 1)
        status = "good" if pct >= 80 else ("warning" if pct >= 40 else "critical")
        coverage.append({"key": key, "label": label, "count": count, "total": total, "pct": pct, "status": status})

    coverage.sort(key=lambda i: i["pct"])
    return coverage


# AI overall_risk -> a 0-100 health score, for charting. Ordinal, not a
# precise measurement — just gives the categorical verdict a position on a bar.
RISK_SCORES = {"critical": 10, "high": 30, "medium": 55, "low": 75, "good": 100}


def _score_status(score: float) -> str:
    return "good" if score >= 80 else ("warning" if score >= 40 else "critical")


def _risk_phrase(risk: str) -> str:
    return {
        "critical": "critical risk",
        "high": "high risk",
        "medium": "medium risk",
        "low": "low risk",
        "good": "good — no material risk",
    }.get(risk, risk)


def compute_health_scores(load_balancers: list) -> dict | None:
    """AI-computed health score (from each load balancer's overall_risk),
    rolled up per app, per namespace, and for the whole tenant. Only load
    balancers that have actually been through 'Analyse with AI' (and didn't
    error) contribute — this reflects AI judgement, not the static checklist,
    so it's only as complete as what's been analyzed so far. Each level also
    carries a `reasoning` string for the info-icon tooltip: the AI's own
    summary for an app, or how an aggregate was derived for namespace/tenant."""
    apps = []
    for lb in load_balancers:
        ai = lb.get("ai")
        if not ai or ai.get("error") or ai.get("overall_risk") not in RISK_SCORES:
            continue
        score = RISK_SCORES[ai["overall_risk"]]
        reasoning = ai.get("summary") or f"AI verdict: {_risk_phrase(ai['overall_risk'])}. No summary text was returned."
        apps.append(
            {
                "namespace": lb["namespace"],
                "name": lb["name"],
                "label": f"{lb['namespace']}/{lb['name']}",
                "risk": ai["overall_risk"],
                "score": score,
                "status": _score_status(score),
                "reasoning": reasoning,
            }
        )

    if not apps:
        return None

    apps.sort(key=lambda a: a["score"])

    by_namespace = {}
    for app in apps:
        by_namespace.setdefault(app["namespace"], []).append(app)

    namespaces = []
    for ns, ns_apps in by_namespace.items():
        score = round(sum(a["score"] for a in ns_apps) / len(ns_apps), 1)
        breakdown = "; ".join(f"{a['name']}: {a['score']} ({_risk_phrase(a['risk'])})" for a in ns_apps)
        namespaces.append(
            {
                "namespace": ns,
                "label": ns,
                "score": score,
                "count": len(ns_apps),
                "status": _score_status(score),
                "reasoning": f"Average of {len(ns_apps)} analysed app(s) in {ns} — {breakdown}.",
            }
        )
    namespaces.sort(key=lambda n: n["score"])

    tenant_score = round(sum(a["score"] for a in apps) / len(apps), 1)
    ns_breakdown = "; ".join(f"{n['namespace']}: {n['score']}" for n in namespaces)
    return {
        "tenant": {
            "score": tenant_score,
            "status": _score_status(tenant_score),
            "count": len(apps),
            "reasoning": f"Average of {len(apps)} analysed app(s) across {len(namespaces)} namespace(s) — {ns_breakdown}.",
        },
        "namespaces": namespaces,
        "apps": apps,
    }


def extract_ref(spec: dict, field: str) -> dict | None:
    """Returns {"namespace":..,"name":..} for a oneof ref field, or None."""
    value = spec.get(field)
    if isinstance(value, dict) and value.get("name"):
        return {"namespace": value.get("namespace", ""), "name": value["name"]}
    return None
