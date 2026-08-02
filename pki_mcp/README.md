# pki-mcp

MCP server + skill for operating the **PKI Squire CA** in natural language —
issue, revoke, inspect, and manage X.509 certificates, keys, CSRs, RA
policies, profiles, users, tokens, challenge passwords, and pre-shared keys
through 61 MCP tools.

> The skill layer is the center of gravity — `rad-pki-operations` carries
> the PKI operational expertise, golden rules, and full tool reference.
> The MCP server is the execution arm that puts that knowledge to work.

---

## What the agent can do

Ask in plain language — no API knowledge needed:

- *"Issue a new certificate for device-001 using the server profile"*
- *"Show me the dashboard — how many certs are valid vs expired?"*
- *"Revoke certificate 42 and confirm the CRL updated"*
- *"Create a SCEP challenge password valid for 30 minutes"*
- *"List all users and disable the suspended ones"*
- *"Inspect this PEM — what extensions does it carry?"*

---

## Repository layout

```
PKI/                                 ← project root (equivalent to rad-mcp-server/)
  pki_mcp/                           ← this directory: the MCP server Python package
    server.py                        ← entry point (--transport stdio|HTTP)
    client.py                        ← PKIClient — async HTTP wrapper
    config.py                        ← pydantic-settings: PKI_BASE_URL, PKI_TOKEN, …
    version.py                       ← SERVER_VERSION, SKILL_VERSION constants
    tools/                           ← 61 MCP tool functions, grouped by domain
    requirements.txt                 ← mcp[cli], httpx, pydantic-settings
  skills/                            ← agent skill SKILL.md files
    rad-pki-operations/
      SKILL.md                       ← the skill: knowledge, rules, tool reference
  scripts/install/                   ← installer scripts (mirrors rad-mcp-server/scripts/install/)
    _common.ps1
    skills_and_mcp/
      install-copilot-vscode.ps1
      install-claude-desktop.ps1
    mcp_server/
      install-stdio-mcp-server.ps1
      install-HTTP-mcp-server.ps1
  api_v1.py                          ← Flask blueprint: /api/v1/ JSON endpoints (server-side)
  app.py                             ← PKI Squire CA Flask application
```

---

## Setup

See **[INSTALL.md](INSTALL.md)** for the full installation guide — prerequisites, per-target scripts (VS Code Copilot, JetBrains, Claude Desktop, generic), and HTTP server setup.


The installer prompts for the PKI server URL and API token, writes the MCP
config entry, and copies the skill. Full details → [INSTALL.md](INSTALL.md).

---

## Deployment modes

| Mode | What runs where | Best for |
|---|---|---|
| **stdio (default)** | IDE spawns the server process locally | Single-user, local PKI server |
| **HTTP / HTTP** | You run one server; clients connect by URL | Shared team access to a remote PKI server |

### stdio — IDE spawns the server

Nothing listens on the network. Full tool access. The IDE config entry
carries `command`/`args`/`cwd`/`env`:

```json
{
  "type": "stdio",
  "command": ".venv\\Scripts\\python.exe",
  "args": ["-m", "pki_mcp.server", "--transport", "stdio"],
  "cwd": "<PKI project root>",
  "env": {
    "PKI_BASE_URL": "https://localhost:443",
    "PKI_TOKEN":    "<your-api-token>",
    "PKI_VERIFY_SSL": "false"
  }
}
```

### HTTP (HTTP) — shared server

Start once on a server; multiple clients connect to `https://<host>:<port>/mcp`.

**Authentication uses two headers:**

| Header | Purpose | Set by |
|---|---|---|
| `Authorization: Bearer <mcp-token>` | Gates access to the MCP server | Admin (from install output) |
| `X-PKI-Token: <personal-pki-token>` | Forwarded to the PKI CA backend | Each individual client |

The PKI token is **not** stored on the MCP server — every request must carry the client's own token so the PKI server audit log shows real user attribution.

**Start the server (Windows — interactive):**
```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1
```

**Start the server (Linux — systemd service):**
```bash
sudo bash scripts/install/mcp_server/install-mcp-service.sh
```

Client config (each user sets their own `X-PKI-Token`):

```json
{
  "type": "http",
  "url": "https://pki-server:444/mcp",
  "headers": {
    "Authorization": "Bearer <shared-mcp-token>",
    "X-PKI-Token":   "<your-personal-pki-api-token>"
  }
}
```

---

## Environment variables

### MCP server

| Variable | Required | Default | Description |
|---|---|---|---|
| `PKI_BASE_URL` | ✅ | `https://localhost:443` | PKI Squire CA base URL |
| `PKI_VERIFY_SSL` | — | `true` | `false` to skip SSL verification (self-signed certs) |
| `MCP_TRANSPORT` | — | `stdio` | `stdio` or `http` |
| `MCP_HOST` | — | `0.0.0.0` | HTTP bind host |
| `MCP_PORT` | — | `8080` | HTTP port |
| `MCP_NAME` | — | `PKI Squire MCP` | Display name shown in the IDE |
| `MCP_AUTH_TOKEN` | — | — | Shared Bearer token clients must send (empty = open) |
| `MCP_READONLY_TOKEN` | — | — | Second accepted Bearer token (read-only use) |
| `MCP_SSL_CERTFILE` | — | — | Path to TLS certificate PEM (enables HTTPS) |
| `MCP_SSL_KEYFILE` | — | — | Path to TLS private key PEM |

> `PKI_TOKEN` is **not** a server setting. In HTTP mode each client supplies its own
> PKI API token via the `X-PKI-Token` request header. In stdio mode, the token lives
> in the IDE config `env` block.

### Client (per-user, stored in the IDE config)

| Header | Description |
|---|---|
| `Authorization: Bearer <mcp-token>` | Shared MCP server access token (from install output) |
| `X-PKI-Token: <personal-token>` | Your personal PKI API token — identifies you in the audit log |

---

## Tools — 61 total

| Group | Tools | Notes |
|---|---|---|
| Certificates | list, get, sign, revoke, delete, download | `sign` accepts `csr_pem` or `csr_id` |
| Keys | list, generate, get, delete | RSA / EC / PQC |
| CSRs | list, generate, import, get, delete | |
| Profiles | list, get, create, update, delete | OpenSSL `.cnf` templates |
| RA Policies | list, get, create, update, delete | `[ADMIN]` for mutations |
| Users | list, get, create, delete, approve, toggle, change_role, reset_password | `[ADMIN]` all |
| Tokens | list, create, delete | |
| Challenge Passwords | list, create, delete, delete_expired | Enterprise/SCEP |
| Pre-Shared Keys | list, get, create, delete, revoke, start_rotation, stop_rotation | Enterprise |
| Events | list, get | Audit trail |
| Dashboard | stats, activity | |
| Inspection | inspect_pem | Auto-detects cert / CSR / key |
| CA / VA | ca_info, va_info, ocsp_check | |
| Config / Logs | config_get, logs_get | `[ADMIN]` |
| EST Protocol | est_cacerts, est_enroll | Enterprise |
| Meta | pki_list_versions, pki_check_skill_version | Version drift detection |

`[ADMIN]` tools require a token created by an admin-role user; they return
`403` with a clear message for regular tokens.

---

## The skill

The `rad-pki-operations` skill carries all PKI operational knowledge —
golden rules, full tool reference, workflow examples, error handling guide,
and version tracking. It is installed alongside the MCP server entry by the
skill+MCP installers.

**Location:** [`skills/rad-pki-operations/SKILL.md`](../skills/rad-pki-operations/SKILL.md)

**Current version:** 1.0.0 (tracked in [`version.py`](version.py) and the skill's
frontmatter; call `pki_list_versions` in agent mode to compare loaded vs server copy)

---

## Versioning

| File | What version it holds |
|---|---|
| `pki_mcp/version.py` | `SERVER_VERSION`, `SKILL_VERSION` constants |
| `skills/rad-pki-operations/SKILL.md` | `version:` frontmatter + changelog line |

Bump both on every change. The `pki_list_versions` tool returns live values
from the running server; `pki_check_skill_version` detects drift between the
loaded skill (in the IDE) and the server's copy.

---

## Running directly (without an IDE)

```powershell
# stdio
$env:PKI_BASE_URL    = "https://localhost:443"
$env:PKI_VERIFY_SSL  = "false"
.venv\Scripts\python.exe -m pki_mcp.server --transport stdio
# Note: set PKI_TOKEN in the IDE env block, not on the server

# HTTP (Windows)
.venv\Scripts\python.exe -m pki_mcp.server --transport http --port 8080

# HTTP with TLS
.venv\Scripts\python.exe -m pki_mcp.server --transport http --port 444 \
    --ssl-certfile pki-https/server.crt --ssl-keyfile pki-https/server.key
```
"
```


