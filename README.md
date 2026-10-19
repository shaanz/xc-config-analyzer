# F5 XC Security Config Analyzer

A local web tool that pulls HTTP Load Balancer security configuration out of
an F5 Distributed Cloud (XC) tenant, checks it against a fixed checklist of
security features, and uses an LLM to judge what's missing, disabled, or
configured in a risky way.

## Project layout

| File | Responsibility |
|---|---|
| `app.py` | Flask routes; in-memory inventory/AI-result state |
| `xc_client.py` | F5 XC REST API client |
| `security_fields.py` | Maps a raw load balancer spec onto the security checklist; computes fleet-wide feature coverage |
| `llm_analyzer.py` | OpenAI-compatible chat-completion client used for the AI pass, connection test, and model listing |
| `exporters.py` | CSV export |
| `config_store.py` | Persists Settings (tenant URL/token, LLM endpoint/model/key) to `data/config.json` |
| `templates/`, `static/` | Server-rendered UI (Flask/Jinja), no JS framework |

## API flow design

### 1. Namespace discovery

```
Browser                    app.py                      F5 XC tenant
   |  GET /                  |                               |
   |------------------------>|  GET /api/web/namespaces      |
   |                         |------------------------------>|
   |                         |<------------------------------|
   |  <namespace dropdown>   |  {"items": [{"name": ...}]}   |
   |<------------------------|                               |
```

Every load of the home page calls `XCClient.list_namespaces()` live (no
caching) so the dropdown always reflects the tenant's current namespaces. An
`"All namespaces"` pseudo-option is injected client-side in the template; it
isn't an F5 API concept — selecting it just makes `/load` iterate every
namespace instead of one.

### 2. Loading an inventory

Triggered by `POST /load` with `namespace` = a specific namespace name or the
sentinel `__ALL__`.

```
for each target namespace:
    GET /api/config/namespaces/{ns}/http_loadbalancers        -> list of {name, namespace}
    for each load balancer in that list:
        GET /api/config/namespaces/{ns}/http_loadbalancers/{name}
            -> {spec, metadata}
        security_fields.build_security_profile(spec)           -> 19 static checks
        resolve app_firewall ref  -> GET .../app_firewalls/{name}      -> AI WAF enhancements
        resolve user_identification ref -> GET .../user_identifications/{name}
        append {namespace, name, domains, spec, profile, resolved_refs, ai: None}
            to in-memory STATE["load_balancers"]
```

Key design choice: **the load balancer's identity (`name`/`namespace`) for
every downstream use (display, AI prompt, CSV, the per-LB analyze-with-AI
URL) is read back from that object's own `GetResponse.metadata`**, not
trusted from the earlier list call. The list endpoint is only used to
enumerate *which* objects exist; the authoritative identity always comes from
the `Get` response for that specific object.

A safety cap (`MAX_LOAD_BALANCERS = 200`) stops the `__ALL__` walk from
pulling an unbounded number of objects from a very large tenant; hitting it
surfaces a truncation notice rather than failing silently.

Two referenced objects are followed per load balancer, because the load
balancer spec only carries a `{namespace, name}` pointer, not their content:

- `app_firewall` → the **App Firewall** object, read for
  `enable_ai_enhancements` / `disable_ai_enhancements` (displayed as the "AI
  WAF Enhancements" row, since it isn't a field on the load balancer itself).
- `user_identification` → the **User Identification** object, read so the AI
  pass can describe what the policy actually resolves requests to, not just
  that one is attached.

### 3. The security checklist

`security_fields.SECURITY_CHECKS` is a fixed, ordered list of
`(key, label, checker_fn)` tuples — 19 static checkers plus `ai_waf`, which is
populated separately once the App Firewall ref is resolved (see above). Each
checker inspects the raw spec dict for the relevant field(s) and returns one
of three statuses:

- `configured` — the feature is set.
- `disabled` — an explicit `disable_*` field is present.
- `absent` — neither is present (F5 XC spec fields are frequently exclusive
  "oneof" pairs, e.g. `app_firewall` vs `disable_waf`).

`build_security_profile(spec)` runs every checker once per load balancer and
returns `{key: {label, status, field, value}}`. Nothing here calls the AI —
this is pure, cheap, local parsing against the already-fetched spec.

### 4. Feature coverage

`compute_feature_coverage(load_balancers)` aggregates the already-built
profiles: for each checklist key, what fraction of the *currently loaded* load
balancers have it `configured`. Rendered as a bar per feature, sorted
worst-covered first, colored by a fixed threshold (<40% critical, 40–79%
warning, ≥80% good). This is a fleet-wide view computed from data already in
memory — it never makes an extra API call.

### 5. AI analysis

Triggered per load balancer (`POST /analyze-ai/<namespace>/<name>`) or for
the whole loaded set (`POST /analyze-ai-all`, which just calls the per-LB path
in a loop, collecting errors rather than aborting on the first failure).

```
app.py                                   LLM endpoint (OpenAI-compatible)
  |  build_ai_items / payload:               |
  |   {namespace, load_balancer,              |
  |    security_profile, resolved_references} |
  |------------------------------------------>|  POST {base_url}/chat/completions
  |                                           |   system: analysis instructions + verdict rubric
  |                                           |   user:   the JSON payload above
  |<------------------------------------------|
  |  {overall_risk, summary,                  |
  |   categories: [{key, verdict, note}]}     |
  |                                           |
  |  merge verdict/note back into             |
  |  profile[key] for display + CSV           |
```

The system prompt fixes the verdict vocabulary (`good` / `missing` / `review`
/ `not_applicable`) and explicitly calls out the checks the tool cares most
about: AI WAF, WAF exclusion breadth, rate limiting, what the user
identification policy resolves to, malicious user detection, L7 DDoS, HSTS.
The model is asked to return one JSON object, parsed defensively (strips
markdown fences, regexes out the `{...}` block) since it's going over an
arbitrary OpenAI-compatible endpoint, not a tool-calling API with a
guaranteed schema.

A single provider abstraction (`llm_analyzer._chat_completion`) backs three
entry points:
- `analyze_load_balancer()` — the real analysis call described above.
- `test_connection()` — a minimal `"Reply with exactly: OK"` round trip, used
  by the Settings page's **Test connection** button.
- `list_models()` — `GET {base_url}/models`, used by **Fetch available
  models** to turn the model field into a dropdown.

### 6. Settings / connection testing

`config_store.py` persists one JSON blob (`data/config.json`): tenant URL +
API token, LLM base URL + model + API key. The Settings page never trusts
only the saved file — `app._cfg_from_form()` merges whatever's currently
typed in the form over the saved config (falling back to the saved secret
when a password field is left blank), so **Test connection** and **Fetch
available models** always act on what's on screen, not stale saved values,
without forcing a Save first and without ever echoing a real secret back into
the page (password fields show a masked hint, never the value).

### 7. Export

`GET /export/csv` flattens the in-memory `STATE["load_balancers"]` — one row
per `(load balancer, security feature)` pair, with `overall_risk`/`ai_summary`
repeated per row so the file stays a flat, spreadsheet-usable table rather
than needing a second sheet. Nested config values are JSON-encoded inline
rather than dropped.

### Route summary

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Render current inventory + feature coverage |
| `/load` | POST | Pull a fresh inventory for one namespace or all of them |
| `/analyze-ai/<namespace>/<name>` | POST | AI pass for one load balancer |
| `/analyze-ai-all` | POST | AI pass for every loaded load balancer |
| `/export/csv` | GET | Download the current inventory + AI results as CSV |
| `/config` | GET/POST | View / save Settings |
| `/config/test-f5` | POST | Test the F5 XC tenant URL/token |
| `/config/test-llm` | POST | Test the LLM endpoint/model/key |
| `/config/fetch-models` | POST | List models from the LLM endpoint |
| `/config/reset` | POST | Wipe saved Settings and the loaded inventory — see below |
| `/health` | GET | Liveness/readiness probe target |

## Switching to a different tenant

Settings → **"Clean config & wipe all data"**. This clears the saved
`data/config.json` back to empty and drops the in-memory inventory
(`STATE["load_balancers"]` and everything derived from it — AI results,
feature coverage), so nothing from the previous tenant leaks into the next
one. It's a destructive, confirmation-gated action — there's no undo.

## Running it

```bash
python3 app.py                 # dev server on :5000
# or
docker build -t xc-config-analyzer .
docker run -p 5093:5000 -v "$PWD/data:/app/data" xc-config-analyzer
```

Settings (tenant URL/token, LLM endpoint/model/key) are entered through the
web UI at `/config` — there's no environment-variable path for them.
