# Installing pki-mcp

Two modes: **stdio** (IDE launches the server) · **HTTP** (you run a shared server, clients connect by URL).

Each target script does **two things in one run**:
1. Writes the MCP server config entry into your IDE (so the agent can call the PKI tools)
2. Copies the `rad-pki-operations` skill to your IDE's skill folder (so the agent knows how to use them)

All commands run from the **repo root**. No `cd` required.

> **"running scripts is disabled"** → use `PowerShell -ExecutionPolicy Bypass -File <script>`

---

## Prerequisites

- Python 3.10+ (the script bootstraps the venv automatically)
- A PKI API token — **Account → API Tokens** in the web UI (use an admin-role account for full access)

> In HTTP mode, the MCP server does **not** hold any PKI token.
> Each client passes their own token per request via `X-PKI-Token`.

---

## Step 1 — Bootstrap the server (stdio mode, once per machine)

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-stdio-mcp-server.ps1
```

> Skip this step if you are connecting to an existing HTTP server hosted elsewhere.

---

## GitHub Copilot — VS Code

**Installs:** MCP server entry (`%APPDATA%\Code\User\mcp.json`) + skill (`~\.copilot\skills\rad-pki-operations\`)

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1
```

HTTP server (non-interactive, prompts for `X-PKI-Token` interactively):
```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1 -Http -Url https://pki-server:444/mcp -Token <mcp-bearer-token>
```

The script will prompt for **your personal PKI API token** (`X-PKI-Token`) which is stored only in your local `mcp.json` headers.

After install: reload VS Code window → accept MCP trust dialog → switch Copilot Chat to **Agent** mode.

---

## GitHub Copilot — JetBrains (IntelliJ, PyCharm, …)

**Installs:** MCP server entry (two config files for both JetBrains agent paths) + skill (`~\.copilot\skills\rad-pki-operations\`)

Requires the official **GitHub Copilot** plugin (by GitHub).

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-intellij.ps1
```

HTTP server (non-interactive):
```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-intellij.ps1 -Http -Url https://pki-server:444/mcp -Token <mcp-bearer-token>
```

After install: restart IDE → **Settings → GitHub Copilot → Chat** → enable Agent Skills → accept MCP trust → start a **new chat**.

Verify: `/mcp list` → `pki-mcp` · `/skills list` → `rad-pki-operations`

---

## Claude Desktop

**Installs:** MCP server entry (`claude_desktop_config.json`) + builds skill zip for manual upload

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-claude-desktop.ps1
```

After install: restart Claude Desktop → **Customize → Skills** → upload `build\claude-skills\rad-pki-operations.zip`.

---

## Generic / other client (prints snippets, writes nothing)

**Prints:** MCP config snippets for any client format + the exact skill copy command. Does not modify any files.

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-generic.ps1
```

---

## HTTP server — start a shared server for multiple clients

### Authentication model

HTTP mode uses **two separate tokens** per request:

| Header | What it does |
|---|---|
| `Authorization: Bearer <mcp-token>` | Gates access to the MCP server (shared, set at server install time) |
| `X-PKI-Token: <personal-pki-token>` | Forwarded to the PKI CA backend — required, per-client, identifies you in the audit log |

The MCP server holds **no PKI token**. Every client must supply their own.

### Windows (interactive foreground)

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1
# Custom port:
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1 -Port 9090
# Force reconfigure:
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1 -Reconfigure
```

Prompts for: PKI CA URL • bind host/port • TLS mode • RW + RO Bearer tokens (auto-generated if blank).
Config saved to `.mcp-http.env` in the repo root for reuse.

### Linux (systemd service — auto-start on boot)

```bash
sudo bash scripts/install/mcp_server/install-mcp-service.sh
# Force reconfigure:
sudo bash scripts/install/mcp_server/install-mcp-service.sh --reconfigure
```

Prompts for the same values across 3 sections (PKI CA server / MCP HTTP server / service install).
Installs to `/etc/systemd/system/pki-mcp.service`, reads env from `/etc/sysconfig/pki-mcp`.

Manage the service:
```bash
sudo systemctl status  pki-mcp
sudo systemctl restart pki-mcp
sudo journalctl -u pki-mcp -f
```

### Wire a client to the running server

```powershell
# Each user runs this with their own PKI API token
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1   -Http -Url https://pki-server:444/mcp -Token <mcp-bearer-token>
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-intellij.ps1 -Http -Url https://pki-server:444/mcp -Token <mcp-bearer-token>
```

Resulting `mcp.json` entry:
```json
{
  "pki-mcp": {
    "type": "http",
    "url": "https://pki-server:444/mcp",
    "headers": {
      "Authorization": "Bearer <shared-mcp-token>",
      "X-PKI-Token":   "<your-personal-pki-api-token>"
    }
  }
}```

---

## Verify

In agent mode: *"call pki_list_versions"* → returns server and skill versions.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: pki_mcp` | Run `scripts\install\mcp_server\install-stdio-mcp-server.ps1` |
| `401 X-PKI-Token header is required` | Add `X-PKI-Token: <your-pki-token>` to your client's `mcp.json` headers |
| `401 Unauthorized` (no token) | Check `Authorization: Bearer <mcp-token>` is set in your client headers |
| `403 [ADMIN]` | Your PKI token belongs to a non-admin user; create one with an admin account |
| Connection errors on tool calls | Check PKI server is running at `PKI_BASE_URL`; check firewall on MCP port |
| TLS errors | Set `PKI_VERIFY_SSL=false` or provide a CA bundle path |
| Skill not loading | Reload VS Code window; check `~\.copilot\skills\rad-pki-operations\SKILL.md` exists |
| `pki-mcp` missing from `/mcp list` (JetBrains) | Re-run `scripts\install\skills_and_mcp\install-copilot-intellij.ps1` |
| Service fails on Rocky/RHEL (SELinux exec denied) | `sudo chcon -R -t bin_t <repo>/pki_mcp/.venv/bin` then restart |
| Service fails (port < 1024 permission denied) | Unit already has `AmbientCapabilities=CAP_NET_BIND_SERVICE`; re-run installer to regenerate unit file |

---

## Environment variables

### MCP server (`.mcp-http.env` / `/etc/sysconfig/pki-mcp`)

| Variable | Default | Description |
|---|---|---|
| `PKI_BASE_URL` | `https://localhost:443` | PKI Squire CA base URL |
| `PKI_VERIFY_SSL` | `true` | `false` for self-signed CA certs |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST` | `0.0.0.0` | HTTP bind host |
| `MCP_PORT` | `8080` | HTTP port |
| `MCP_NAME` | `PKI Squire MCP` | Server display name shown in the IDE |
| `MCP_AUTH_TOKEN` | — | Shared Bearer token (RW); empty = open |
| `MCP_READONLY_TOKEN` | — | Second accepted Bearer token (RO) |
| `MCP_SSL_CERTFILE` | — | TLS certificate PEM path (enables HTTPS) |
| `MCP_SSL_KEYFILE` | — | TLS private key PEM path |

> `PKI_TOKEN` is **not** a server variable in HTTP mode. Each client passes
> their own PKI API token per-request via the `X-PKI-Token` header.

### Client (per-user, in `mcp.json`)

| Header | Description |
|---|---|
| `Authorization: Bearer <token>` | Shared MCP server access token |
| `X-PKI-Token: <token>` | Your personal PKI API token (required in HTTP mode) |
