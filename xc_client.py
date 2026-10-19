"""Minimal client for the F5 Distributed Cloud (XC) config API.

Endpoint paths and field names below come from the published OpenAPI specs at
https://docs.cloud.f5.com/docs-v2/api (views-http-loadbalancer, namespace,
app-firewall), not guesswork. Two assumptions are noted inline where the
public spec didn't confirm the exact path (object reference REST prefixes
follow F5's consistent <schema_name>s pluralization convention elsewhere).
"""

import requests


class XCError(Exception):
    pass


class XCClient:
    def __init__(self, tenant_url: str, api_token: str, timeout: float = 30.0):
        if not tenant_url:
            raise XCError("No tenant URL configured.")
        if not api_token:
            raise XCError("No API token configured.")
        self.base_url = tenant_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"APIToken {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            raise XCError(f"Request to {path} failed: {exc}") from exc
        if resp.status_code == 401:
            raise XCError("F5 XC rejected the API token (401 Unauthorized).")
        if resp.status_code == 403:
            raise XCError(f"No permission to access {path} (403 Forbidden).")
        if resp.status_code == 404:
            raise XCError(f"Not found: {path} (404).")
        if resp.status_code >= 400:
            raise XCError(f"F5 XC API error {resp.status_code} on {path}: {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise XCError(f"Non-JSON response from {path}: {exc}") from exc

    # GET /api/web/namespaces
    def list_namespaces(self) -> list[str]:
        data = self._get("/api/web/namespaces")
        return sorted(item["name"] for item in data.get("items", []) if item.get("name"))

    # GET /api/config/namespaces/{namespace}/http_loadbalancers
    def list_load_balancers(self, namespace: str) -> list[dict]:
        data = self._get(f"/api/config/namespaces/{namespace}/http_loadbalancers")
        return [
            {"name": item["name"], "namespace": item.get("namespace", namespace)}
            for item in data.get("items", [])
            if item.get("name")
        ]

    # GET /api/config/namespaces/{namespace}/http_loadbalancers/{name}
    # Returns (spec, identity): identity is read from this response's own
    # metadata rather than trusted from the earlier list call, since metadata
    # on a Get is always authoritative for the object actually fetched.
    def get_load_balancer(self, namespace: str, name: str) -> tuple[dict, dict]:
        data = self._get(f"/api/config/namespaces/{namespace}/http_loadbalancers/{name}")
        metadata = data.get("metadata") or {}
        identity = {
            "name": metadata.get("name") or name,
            "namespace": metadata.get("namespace") or namespace,
        }
        return data.get("spec", {}), identity

    # GET /api/config/namespaces/{namespace}/app_firewalls/{name}
    def get_app_firewall(self, namespace: str, name: str) -> dict:
        data = self._get(f"/api/config/namespaces/{namespace}/app_firewalls/{name}")
        return data.get("spec", {})

    # GET /api/config/namespaces/{namespace}/user_identifications/{name}
    # Assumption: REST path follows F5's standard <object>s pluralization
    # (confirmed for http_loadbalancer -> http_loadbalancers and
    # app_firewall -> app_firewalls); not separately confirmed for this type.
    def get_user_identification(self, namespace: str, name: str) -> dict:
        data = self._get(f"/api/config/namespaces/{namespace}/user_identifications/{name}")
        return data.get("spec", {})
