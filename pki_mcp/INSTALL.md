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

HTTP server (non-interactive):
```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1 -Http -Url http://pki-server:8080/mcp -Token <token>
```

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
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-intellij.ps1 -Http -Url http://pki-server:8080/mcp -Token <token>
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

```powershell
$env:PKI_BASE_URL   = "https://localhost:443"
$env:PKI_TOKEN      = "<token>"
$env:PKI_VERIFY_SSL = "false"

PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1
# custom port:
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-http-mcp-server.ps1 -Port 9090
```

Clients connect to `http://<host>:8080/mcp`. Wire a client to the running server:

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1   -Http -Url http://localhost:8080/mcp -Token <token>
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-intellij.ps1 -Http -Url http://localhost:8080/mcp -Token <token>
```

---

## Verify

In agent mode: *"call pki_list_versions"* → returns server and skill versions.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: pki_mcp` | Run `scripts\install\mcp_server\install-stdio-mcp-server.ps1` |
| `401 Invalid or expired token` | Create a new token in PKI UI, update MCP config `env` block |
| `403 [ADMIN]` | Re-create the token while logged in as an admin-role user |
| Connection errors on tool calls | Check PKI server is running at `PKI_BASE_URL` |
| TLS errors | Set `PKI_VERIFY_SSL=false` |
| Skill not loading | Reload VS Code window; check `~\.copilot\skills\rad-pki-operations\SKILL.md` exists |
| `pki-mcp` missing from `/mcp list` (JetBrains) | Re-run `scripts\install\skills_and_mcp\install-copilot-intellij.ps1` |

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PKI_BASE_URL` | `https://localhost:443` | PKI Squire CA base URL |
| `PKI_TOKEN` | *(required)* | API token — Bearer auth |
| `PKI_VERIFY_SSL` | `true` | `false` for self-signed CA certs |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST` | `0.0.0.0` | HTTP bind host |
| `MCP_PORT` | `8080` | HTTP port |
| `MCP_NAME` | `PKI Squire MCP` | Server display name shown in the IDE |
