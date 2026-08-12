# pki-mcp Coverage Map

Full mapping of PKI Squire CA capabilities across three surfaces:
**MCP tools** (AI agent), **REST API** (`/api/v1/`), and **Web UI**.

---

## Summary

| Surface | Capabilities |
|---|---|
| MCP tools | 63 tools — covers 100% of the REST API + enterprise routes + meta/versioning |
| REST API (`/api/v1/`) | 45 endpoints — primary machine interface |
| Enterprise API (app routes) | ~15 additional endpoints for PSKs, challenge passwords, EST, OCSP |
| Web UI | Full coverage of all API operations + exclusive UI-only features (see below) |

---

## Resource coverage

### Certificates — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `certificate_list` | GET | `/api/v1/certificates` |
| `certificate_get` | GET | `/api/v1/certificates/<id>` |
| `certificate_download` | GET | `/api/v1/certificates/<id>/download` |
| `certificate_sign` | POST | `/api/v1/certificates/sign` |
| `certificate_revoke` | POST | `/api/v1/certificates/<id>/revoke` |
| `certificate_delete` | DELETE | `/api/v1/certificates/<id>` |

Filters: `search`, `status` (valid/revoked/expired), `date_from`, `date_to`, `issued_via`, `username`, `sort_by`, `sort_order`.

---

### Keys — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `key_list` | GET | `/api/v1/keys` |
| `key_generate` | POST | `/api/v1/keys` |
| `key_get` | GET | `/api/v1/keys/<id>` |
| `key_delete` | DELETE | `/api/v1/keys/<id>` |

Filters: `search`, `key_type` (RSA/EC/PQC), `curve_name`, `pqc_alg`, `date_from`, `date_to`.

---

### CSRs — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `csr_list` | GET | `/api/v1/csrs` |
| `csr_generate` | POST | `/api/v1/csrs/generate` |
| `csr_import` | POST | `/api/v1/csrs/import` |
| `csr_get` | GET | `/api/v1/csrs/<id>` |
| `csr_delete` | DELETE | `/api/v1/csrs/<id>` |

Filters: `search`, `source` (generated/imported/scep/est), `date_from`, `date_to`.

---

### Certificate Profiles — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `profile_list` | GET | `/api/v1/profiles` |
| `profile_get` | GET | `/api/v1/profiles/<id>` |
| `profile_create` | POST | `/api/v1/profiles` |
| `profile_update` | PUT | `/api/v1/profiles/<id>` |
| `profile_delete` | DELETE | `/api/v1/profiles/<id>` |

---

### RA Policies — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `ra_policy_list` | GET | `/api/v1/ra_policies` |
| `ra_policy_get` | GET | `/api/v1/ra_policies/<id>` |
| `ra_policy_create` | POST | `/api/v1/ra_policies` |
| `ra_policy_update` | PUT | `/api/v1/ra_policies/<id>` |
| `ra_policy_delete` | DELETE | `/api/v1/ra_policies/<id>` |

---

### Users — ✅ Full coverage `[ADMIN]`

| MCP Tool | HTTP | Route |
|---|---|---|
| `user_list` | GET | `/api/v1/users` |
| `user_get` | GET | `/api/v1/users/<id>` |
| `user_create` | POST | `/api/v1/users` |
| `user_delete` | DELETE | `/api/v1/users/<id>` |
| `user_approve` | POST | `/api/v1/users/<id>/approve` |
| `user_toggle_active` | POST | `/api/v1/users/<id>/toggle_active` |
| `user_change_role` | POST | `/api/v1/users/<id>/change_role` |
| `user_reset_password` | POST | `/api/v1/users/<id>/reset_password` |

Filters: `search`, `role`, `status`, `sort_by`.

---

### API Tokens — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `token_list` | GET | `/api/v1/tokens` |
| `token_create` | POST | `/api/v1/tokens` |
| `token_delete` | DELETE | `/api/v1/tokens/<id>` |

---

### Events / Audit Log — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `event_list` | GET | `/api/v1/events` |
| `event_get` | GET | `/api/v1/events/<id>` |

Filters: `search`, `resource_type`, `event_type`, `resource_name`, `date_from`, `date_to`, `sort_by`.

---

### Dashboard — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `dashboard_stats` | GET | `/api/v1/dashboard` |
| `dashboard_activity` | GET | `/api/v1/dashboard/activity` |

---

### Inspection — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `inspect_pem` | POST | `/api/v1/inspect` |

Parses certificates, CSRs, CRLs, keys, OCSP, PKCS#7/12.

---

### CA / VA / Config / Logs — ✅ Full coverage

| MCP Tool | HTTP | Route |
|---|---|---|
| `ca_info` | GET | `/api/v1/ca` |
| `va_info` | GET | `/api/v1/va` |
| `ocsp_check` | GET | `/status/<serial>` |
| `config_get` | GET | `/api/v1/config` |
| `logs_get` | GET | `/api/v1/logs` |

---

### Challenge Passwords — ✅ Full coverage `[Enterprise]`

| MCP Tool | HTTP | Route |
|---|---|---|
| `challenge_password_list` | GET | `/challenge_passwords/data` |
| `challenge_password_create` | POST | `/api/challenge_passwords` |
| `challenge_password_delete` | POST | `/delete_challenge_password` |
| `challenge_password_delete_expired` | POST | `/delete_all_expired_challenge_passwords` |

---

### Pre-Shared Keys (PSKs) — ✅ Full coverage `[Enterprise]`

| MCP Tool | HTTP | Route |
|---|---|---|
| `psk_list` | GET | `/preshared_keys/data` |
| `psk_get` | GET | `/api/preshared_keys/<name>` |
| `psk_history` | GET | `/api/preshared_keys/<name>/history` |
| `psk_get_by_hash` | GET | `/api/preshared_keys/<name>/history/<hash_id>` |
| `psk_create` | POST | `/api/preshared_keys` |
| `psk_delete` | DELETE | `/api/preshared_keys/<name>` |
| `psk_revoke` | POST | `/preshared_keys/<id>/revoke` |
| `psk_regenerate` | POST | `/preshared_keys/<id>/regenerate` |
| `psk_start_rotation` | POST | `/api/preshared_keys/<name>/rotation/start` |
| `psk_stop_rotation` | POST | `/api/preshared_keys/<name>/rotation/stop` |

---

### EST Protocol — ✅ Full coverage `[Enterprise]`

| MCP Tool | HTTP | Route |
|---|---|---|
| `est_cacerts` | GET | `/.well-known/est/cacerts` |
| `est_enroll` | POST | `/.well-known/est/simpleenroll` |

---

### Meta / Versioning — MCP-only

| MCP Tool | Description |
|---|---|
| `pki_list_versions` | Server version + baked-in skill version |
| `pki_check_skill_version` | Detect drift between loaded skill and server copy |
| `list_filter_capabilities` | Full filter/sort/pagination reference for all resource types |

---

## UI-only features (no API equivalent)

These are available in the web UI but have no REST API endpoint and therefore no MCP tool:

| Feature | UI path | Notes |
|---|---|---|
| Certificate template wizard (legacy) | `/x509_templates` | Old template system, not in api_v1 |
| Rendered template preview | `/list_rendered` | View/download rendered templates |
| Account profile (own user) | `/account` | Name, email, password for current user |
| Theme / color preferences | `/account` | UI display settings only |
| Real-time log streaming | `/logs` | Polls `/logs/last` — not in api_v1; `logs_get` uses `/api/v1/logs` (snapshot) |
| DER/binary file upload in Inspect | `/inspect` | The UI accepts file upload + binary DER input |
| "Check" tab in Inspect | `/inspect` | Multi-PEM chain/key comparison report |
| Dashboard timeline chart | `/` | Visual chart rendering in browser |
| CRL viewer (formatted VA page) | `/va` | Human-readable CRL display |
| Server extension config viewer | `/get_server_ext_content` | RA policy extension viewer widget |
| Sign wizard with CSR preview | `/sign` | Interactive UI form |
| Config page (secret-gated) | `/config` | The RAW config.ini viewer |

---

## What the API has that the UI doesn't highlight

These endpoints exist in `api_v1.py` but have no dedicated UI page — the MCP is often the primary interface:

- `POST /api/v1/inspect` — PEM inspection (the UI has it, but the API is used programmatically)
- `GET /api/v1/config` — full config read (API only, UI requires secret)
- `GET /api/v1/dashboard/activity` — raw event stream for charting
- All filtering/sorting parameters (`date_from`, `date_to`, `issued_via`, etc.) — the MCP exposes these directly; the UI uses them internally

---

## Tool count

| Category | Tools |
|---|---|
| Certificates | 6 |
| Keys | 4 |
| CSRs | 5 |
| Profiles | 5 |
| RA Policies | 5 |
| Users | 8 |
| API Tokens | 3 |
| Events | 2 |
| Dashboard | 2 |
| Inspection | 1 |
| CA / VA / Config / Logs / OCSP | 5 |
| Challenge Passwords | 4 |
| PSKs | 8 |
| EST | 2 |
| Meta / Versioning | 3 |
| **Total** | **63** |
