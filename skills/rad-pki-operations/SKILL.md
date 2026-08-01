---
name: rad-pki-operations
description: PKI Squire CA operations — issue, revoke, inspect, and manage certificates, keys, CSRs, RA policies, profiles, users, tokens, challenge passwords, pre-shared keys, and EST/SCEP/OCSP protocols through the pki-mcp MCP server. Load whenever the user asks about the PKI server, Pikachu CA, certificate lifecycle, SCEP enrollment, EST enrollment, OCSP status, key generation, RA policies, or any pki-mcp tool. ALWAYS load when the user addresses "pikachu", "pika", "pkisquire", "the CA", or "the PKI" (the PKI CA personas and common shorthand).
version: 1.3.0
---

> **Skill version:** 1.3.0 · updated 2026-08-01 (v1.3.0 — expanded trigger words: pikachu, pika, pkisquire, the CA, the PKI) (bump this line and the `version:` field on every change; it is how we tell which copy is loaded)

## Session self-check (once, at session start)

Call `pki_check_skill_version(skill="rad-pki-operations", version="1.3.0")` once and surface any returned `alerts` to the user. A mismatch means the loaded skill and the connected server have drifted — warn the user but continue. If the tool is unavailable, skip silently.

## Trigger words

Load and apply this skill whenever the user says any of the following — they all refer to the PKI Squire CA server:

| Trigger | Notes |
|---|---|
| **pikachu** | Full nickname for the CA |
| **pika** | Short nickname |
| **pkisquire** | Product name shorthand |
| **the CA** | Generic CA reference |
| **the PKI** | Generic PKI reference |

Treat all of these exactly like "PKI server" or "CA".

## What this skill covers

The **pki-mcp** server wraps the PKI Squire CA HTTP API and exposes it as 59 MCP tools. The PKI Squire CA issues X.509 certificates via the web UI, REST API, EST, and SCEP. This skill teaches correct tool selection, sequencing, and safety rules for PKI operations.

---

## Golden rules

1. **Never delete or revoke a certificate without explicit user confirmation** — ask: *"Revoke/delete certificate ID \<N\> (serial \<hex\>)? This cannot be undone."* Wait for a clear yes.
2. **Admin-only tools** are marked `[ADMIN]` below and in the tool descriptions. They fail with a clear `403` if called with a non-admin token. Tell the user to create their API token while logged in as an admin-role account.
3. **Token is the auth boundary** — never log or echo the raw `PKI_TOKEN` value. If a token operation fails with 401, tell the user to re-generate the token in the UI (Account → API Tokens).
4. **Signing before confirmation** — for `certificate_sign`, always show the CSR subject and policy before signing, and ask once: *"Sign this CSR and issue the certificate?"*
5. **No retries on 4xx** — HTTP 400/401/403/404 are definitive. Report the error from the tool output verbatim; do not silently retry with different parameters.
6. **Validity of PEM strings** — the server validates all PEM inputs. If `certificate_sign` or `csr_import` returns a 400 with a PEM error, ask the user to verify the PEM block, not to guess a fix.
7. **Never substitute a different resource type** — always use the correct tool for the resource the user asked for. If the tool call fails, report the error and ask the user to check/restart the server. Do not invent cross-resource workarounds.

   | User asks for | Correct tool(s) | NEVER use instead |
   |---|---|---|
   | Certificates | `certificate_list`, `certificate_get` | `csr_list`, `key_list` |
   | Keys | `key_list`, `key_get` | `certificate_list`, `csr_list` |
   | CSRs | `csr_list`, `csr_get` | `certificate_list`, `key_list` |
   | Profiles / templates | `profile_list`, `profile_get` | any other list tool |
   | RA policies | `ra_policy_list`, `ra_policy_get` | any other list tool |
   | Users | `user_list`, `user_get` | any other list tool |
   | Challenge passwords | `challenge_password_list` | any other list tool |
   | Pre-shared keys (PSKs) | `psk_list`, `psk_get` | `key_list` or `certificate_list` |
   | API tokens | `token_list` | any other list tool |
   | Audit events | `event_list`, `event_get` | any other list tool |

8. **Resource isolation** — all resource types are independent entities. A certificate *references* a key but is not the key. A CSR *uses* a profile but is not a profile. Filtering one resource type to infer data about another is always wrong.
9. **Always render lists as markdown tables** — whenever returning a list of resources (certificates, keys, CSRs, profiles, RA policies, users, tokens, challenge passwords, PSKs, events), present the results as a **markdown table**, never as a numbered or bulleted list. Include a row count summary after the table (e.g. *"5 EC keys found"*). Use the most relevant columns for the resource type — examples below:

   | Resource | Key columns to show |
   |---|---|
   | Certificates | ID, Common Name, Serial, Issued, Expires, Via, User, Status |
   | Keys | ID, Name, Type, Size/Curve, Algorithm, Created |
   | CSRs | ID, Name, Source, Key ID, Profile ID, Created |
   | Profiles | ID, Name, Type |
   | RA Policies | ID, Name, Validity, EST default, SCEP default |
   | Users | ID, Username, Role, Status, Auth Source |
   | Challenge Passwords | Value (masked), Usage Mode, Expires, Used |
   | PSKs | Name, Profile, Rotation, Expires, Status |
   | API Tokens | ID, Name, Expires |
   | Events | Event ID, Type, Resource Type, Resource Name, User, Timestamp |

---

## Tool reference

### Certificates (6 tools)

| Tool | What it does |
|---|---|
| `certificate_list` | List/filter certs. Filters: `search` (subject/serial/CN), `status` (valid/revoked/expired), `date_from`, `date_to` (on issuance date), `issued_via` (ui/scep/est/api), `username`. Sort: `sort_by`, `sort_order`. Paginated. |
| `certificate_get` | Full detail for one cert by ID — subject, issuer, extensions, PEM |
| `certificate_sign` | **Sign a CSR and issue a cert.** Accepts `csr_pem` (raw string) **or** `csr_id` (stored DB record); `policy_id` (0 = server default); `validity_days` (0 = policy default); `no_extensions`; `use_csr_extensions` |
| `certificate_revoke` | Revoke by DB ID — updates CRL automatically |
| `certificate_delete` | Permanently remove from DB by ID |
| `certificate_download` | Return PEM text for a cert by ID |

**Typical sign flow:**
```
1. key_generate(name, key_type="EC") → key_id
2. profile_list() → pick profile_id
3. csr_generate(name, key_id, profile_id) → csr_id
4. certificate_sign(csr_id=csr_id) → cert_id
```
Or sign directly from an external CSR PEM:
```
certificate_sign(csr_pem="-----BEGIN CERTIFICATE REQUEST-----\n...")
```

### Keys (4 tools)

| Tool | What it does |
|---|---|
| `key_list` | List/filter keys. Filters: `search` (name/curve/pqc_alg), `key_type` (RSA/EC/PQC), `curve_name` (EC curve), `pqc_alg` (PQC algorithm), `date_from`, `date_to`. Sort: `sort_by`, `sort_order`. Paginated. |
| `key_generate` | Generate RSA/EC/PQC key. `key_type` = RSA\|EC\|PQC; `key_size` (RSA bits); `curve_name` (EC); `pqc_alg` (mldsa44/65/87 — Enterprise + oqsprovider required) |
| `key_get` | Get key detail; `include_private=true` returns private key PEM (use with care) |
| `key_delete` | Delete a key by ID (irreversible) |

### CSRs (5 tools)

| Tool | What it does |
|---|---|
| `csr_list` | List/filter CSRs. Filters: `search` (name), `source` (generated/imported/scep/est), `date_from`, `date_to`. Sort: `sort_by`, `sort_order`. Paginated. |
| `csr_generate` | Generate a CSR using a stored key + profile (`key_id`, `profile_id`) |
| `csr_import` | Import an external PEM CSR into the server |
| `csr_get` | Retrieve a stored CSR by ID including PEM |
| `csr_delete` | Delete a stored CSR by ID |

### Profiles / Templates (5 tools)

Certificate profiles are OpenSSL `.cnf` config blocks (extensions + subject DN) stored on the server.

| Tool | What it does |
|---|---|
| `profile_list` | List profiles |
| `profile_get` | Get profile content by ID |
| `profile_create` | Create a new profile (`name`, `content` = OpenSSL INI config, `profile_type`) |
| `profile_update` | Update `content` or `profile_type` |
| `profile_delete` | Delete a profile by ID |

### RA Policies (5 tools) — create/update/delete require `[ADMIN]`

RA policies control signing extensions and validity. `certificate_sign` uses the server's default policy when `policy_id` is omitted.

| Tool | What it does |
|---|---|
| `ra_policy_list` | List policies (admin sees all; users see own) |
| `ra_policy_get` | Get policy detail by ID |
| `ra_policy_create` | **[ADMIN]** Create policy (`name`, `ext_config`, `validity_period`, `is_system`, `is_est_default`, `is_scep_default`) |
| `ra_policy_update` | **[ADMIN]** Update `ext_config` or `validity_period` |
| `ra_policy_delete` | **[ADMIN]** Delete policy by ID |

### Users (8 tools) — all `[ADMIN]`

| Tool | What it does |
|---|---|
| `user_list` | List/filter users. Filters: `search` (username/email), `role` (user/admin), `status` (active/disabled/pending). Sort: `sort_by`, `sort_order`. Paginated. |
| `user_get` | Get user detail by ID |
| `user_create` | Create user (`username`, `password` ≥ 8 chars, `role` = user\|admin, `email`) |
| `user_delete` | Delete user by ID (cannot delete own account) |
| `user_approve` | Approve a pending self-registration |
| `user_toggle_active` | Enable/disable a user |
| `user_change_role` | Change role to user or admin |
| `user_reset_password` | Reset password (min 8 chars) |

### API Tokens (3 tools)

| Tool | What it does |
|---|---|
| `token_list` | List tokens (admin = all; user = own) |
| `token_create` | Create token (`name`, `validity` e.g. `"30d"`, `length` 24–256). Raw token shown **once only** — copy immediately. |
| `token_delete` | Delete token by ID |

### Challenge Passwords — SCEP (4 tools)

Enterprise/SCEP feature. Challenge passwords are one-time or reusable passwords for SCEP enrollment.

| Tool | What it does |
|---|---|
| `challenge_password_list` | List challenge passwords with status |
| `challenge_password_create` | Create (`validity` e.g. `"60m"`, `usage_mode` = single_use\|reusable\|unlimited, `length`) |
| `challenge_password_delete` | Delete one by value |
| `challenge_password_delete_expired` | Bulk-delete expired (`scope` = own\|all) |

### Pre-Shared Keys — PSK (7 tools)

Enterprise feature. PSKs support optional auto-rotation.

| Tool | What it does |
|---|---|
| `psk_list` | List all PSKs |
| `psk_get` | Get current PSK value by name |
| `psk_create` | Create (`name`, `length`, `validity`, `rotation_interval`, `profile`) |
| `psk_delete` | Delete by name |
| `psk_revoke` | Revoke by DB ID |
| `psk_start_rotation` | Enable auto-rotation |
| `psk_stop_rotation` | Disable auto-rotation |

### Events / Audit (2 tools)

| Tool | What it does |
|---|---|
| `event_list` | List/filter audit events. Filters: `search` (resource name), `resource_type`, `event_type`, `resource_name`, `date_from`, `date_to`. Sort: `sort_by`, `sort_order`. Paginated. |
| `event_get` | Get one event by ID |

### Dashboard (2 tools)

| Tool | What it does |
|---|---|
| `dashboard_stats` | Counts: total/valid/expired/revoked; enrollment breakdown (UI/EST/SCEP/API) |
| `dashboard_activity` | Recent N activity events for charting |

### Inspection (1 tool)

| Tool | What it does |
|---|---|
| `inspect_pem` | Parse a PEM object (certificate, CSR, key) — returns subject, issuer, serial, validity, key algorithm, extensions, detected type |

### CA / VA / Config / Logs (5 tools)

| Tool | What it does |
|---|---|
| `ca_info` | Sub-CA subject, issuer, serial, validity, CA mode (RSA/EC), cert PEM |
| `va_info` | CRL status: exists, size, last-modified, revoked count |
| `ocsp_check` | OCSP/DB status check for a certificate serial (hex) → good/revoked/unknown |
| `config_get` | **[ADMIN]** Non-sensitive server config (CA_MODE, SCEP_ENABLED, edition, etc.) |
| `logs_get` | **[ADMIN]** Last N lines from the server log |

### EST Protocol (2 tools)

| Tool | What it does |
|---|---|
| `est_cacerts` | Fetch CA chain via EST `/.well-known/est/cacerts` |
| `est_enroll` | Submit a CSR via EST `simpleenroll` |

### Meta / Versioning (2 tools)

| Tool | What it does |
|---|---|
| `pki_list_versions` | Server version + loaded skill version |
| `pki_check_skill_version` | Compare loaded skill version with server copy; returns drift alerts |
| `list_filter_capabilities` | Return full filter/sort/pagination reference for any resource (certificates/keys/csrs/users/events). Call this when user asks *"how can I filter ..."* or *"what can I search by"*. |

---

## Common workflows

### Check server health
```
dashboard_stats()          → summary counts
ca_info()                  → verify CA is loaded and not expired
va_info()                  → confirm CRL exists
```

### Issue a new certificate (full flow)
```
1. key_generate(name="device-001", key_type="EC", curve_name="prime256v1")
2. profile_list()                            → pick a profile
3. csr_generate(name="device-001", key_id=<id>, profile_id=<id>)
4. ra_policy_list()                          → pick or use default (policy_id=0)
5. certificate_sign(csr_id=<id>)             → confirm before calling
6. certificate_get(<cert_id>)                → verify
```

### Issue a certificate from an external CSR
```
certificate_sign(csr_pem="-----BEGIN CERTIFICATE REQUEST-----\n...")
```

### Bulk certificate audit
```
certificate_list(status="expired", per_page=100)   → list expired
certificate_list(status="revoked", per_page=100)   → list revoked
event_list(event_type="revoke", resource_type="certificate")  → audit trail
```

### Create a SCEP challenge password and use it
```
challenge_password_create(validity="60m", usage_mode="single_use")
   → note the returned value for the SCEP client
```

---

## Error handling

| HTTP status | Meaning | Action |
|---|---|---|
| `401` | Token missing or expired | Ask user to create a new token in the UI |
| `403 [ADMIN]` | Admin token required | Ask user to use a token from an admin-role account |
| `400` | Bad input | Show the error verbatim; ask user to correct input |
| `404` | Resource not found or access denied | Check the ID and token ownership |
| `500` | Server error (signing failed, etc.) | Show `error` field verbatim; check server logs via `logs_get` |

---

## Versions

The server version and skill version are tracked separately so you can detect drift between the installed skill file and the running server.

When the user asks about versions (*"what version is the PKI MCP?"*, *"are the skills up to date?"*):

1. Call `pki_list_versions()` — returns server + skill versions from the running server.
2. Compare against this skill's version line above (`1.0.0`).
3. If they differ, warn the user: *"Loaded skill is X.Y.Z but server reports A.B.C — re-run the installer to sync."*

Render a table:

| Component | Version |
|---|---|
| pki-mcp server | \<from pki_list_versions\> |
| rad-pki-operations skill (server copy) | \<from pki_list_versions\> |
| rad-pki-operations skill (loaded here) | 1.0.0 |
