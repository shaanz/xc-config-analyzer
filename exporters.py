import csv
import io
import json
from datetime import datetime, timezone

CSV_FIELDS = [
    "namespace",
    "load_balancer",
    "domains",
    "overall_risk",
    "ai_summary",
    "security_feature",
    "status",
    "configured_value",
    "ai_verdict",
    "ai_note",
]


def _value_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def build_csv(load_balancers: list) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    writer.writeheader()

    for lb in load_balancers:
        ai = lb.get("ai") or {}
        overall_risk = ai.get("overall_risk", "")
        ai_summary = ai.get("error") or ai.get("summary", "")
        profile = lb.get("profile", {})
        domains = ", ".join(lb.get("domains") or [])

        if not profile:
            writer.writerow(
                {
                    "namespace": lb["namespace"],
                    "load_balancer": lb["name"],
                    "domains": domains,
                    "overall_risk": overall_risk,
                    "ai_summary": ai_summary,
                    "security_feature": "",
                    "status": "",
                    "configured_value": "",
                    "ai_verdict": "",
                    "ai_note": "",
                }
            )
            continue

        for item in profile.values():
            writer.writerow(
                {
                    "namespace": lb["namespace"],
                    "load_balancer": lb["name"],
                    "domains": domains,
                    "overall_risk": overall_risk,
                    "ai_summary": ai_summary,
                    "security_feature": item.get("label", ""),
                    "status": item.get("status", ""),
                    "configured_value": _value_str(item.get("value")),
                    "ai_verdict": item.get("ai_verdict", ""),
                    "ai_note": item.get("ai_note", ""),
                }
            )

    return buf.getvalue().encode("utf-8")


def build_json(load_balancers: list) -> bytes:
    """The raw F5 XC API data behind the current inventory, one entry per
    load balancer: its spec exactly as returned by GetLoadBalancer, the
    resolved app_firewall/user_identification objects exactly as returned by
    their own Get calls, plus our derived checklist and AI verdict for
    context. Unlike the CSV export this keeps full nested structure."""
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "load_balancer_count": len(load_balancers),
        "load_balancers": [
            {
                "namespace": lb["namespace"],
                "name": lb["name"],
                "domains": lb.get("domains") or [],
                "raw_spec": lb.get("spec", {}),
                "resolved_references": lb.get("resolved_refs", {}),
                "security_profile": lb.get("profile", {}),
                "ai_analysis": lb.get("ai"),
            }
            for lb in load_balancers
        ],
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")
