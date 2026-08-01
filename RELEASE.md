# Release Notes

## 2.20 — 2026-08-01

### Highlights
Full **AI Agent / MCP integration** for PKI Squire CA — issue, revoke, inspect, and manage the CA in natural language via GitHub Copilot, Claude, or any MCP-compatible AI assistant.

---

### New: pki-mcp MCP Server (`pki_mcp/`)

- **63 MCP tools** covering 100% of the REST API + enterprise routes (challenge passwords, PSKs, EST, OCSP).
- Dedicated isolated venv at `pki_mcp/.venv` — completely separate from the CA server venv, matching the rad-agent-toolkit `server/.venv` pattern.
- Portable Python fallback: if no Python ≥ 3.10 is found on PATH the installer downloads a repo-local CPython 3.12 (no system install, no admin required).
- `pki_mcp/COVERAGE.md` — full API ↔ MCP tool mapping including UI-only features.

### New: `rad-pki-operations` Skill (`skills/rad-pki-operations/`)

- Skill v1.3.0 with 9 golden rules including:
  - Rule 7: never substitute a different resource type (keys ≠ certificates ≠ CSRs)
  - Rule 8: resource isolation
  - Rule 9: always render list results as markdown tables
- Trigger words: `pikachu`, `pika`, `pkisquire`, `the CA`, `the PKI`
- `list_filter_capabilities` tool — AI calls this when user asks "how can I filter?"
- Versioning check: `pki_check_skill_version` alerts on skill/server drift

### New: Install Scripts (`scripts/install/`)

- `install-copilot-vscode.ps1` — MCP + skill installer for VS Code
- `install-copilot-intellij.ps1` — MCP + skill installer for JetBrains IDEs
- `install-claude-desktop.ps1` — MCP + skill installer for Claude Desktop
- `install-generic.ps1` — prints MCP config snippets for any client
- `install-stdio-mcp-server.ps1` — bootstraps the dedicated MCP venv
- `install-http-mcp-server.ps1` — starts the shared HTTP MCP server

### New: MCP Install Page (`/mcp-install`)

- Tabbed install guide for VS Code, JetBrains, Claude Desktop, HTTP server, Generic
- "What can I ask?" section with 10 example prompts
- Copy-to-clipboard buttons for all commands
- Dynamic server URL/port injection
- Accessible from the navbar: **MCP** link

### Enhanced: REST API (`api_v1.py`)

All list endpoints now support **filtering, sorting, and pagination**:

| Resource | New filters |
|---|---|
| Certificates | `date_from`, `date_to`, `issued_via`, `username`, `sort_by`, `sort_order`; `status=expired` |
| Keys | `search` (name/curve/pqc_alg), `key_type`, `curve_name`, `pqc_alg`, `date_from`, `date_to` |
| CSRs | `search`, `source`, `date_from`, `date_to` |
| Users | `search`, `role`, `status`, `sort_by` |
| Events | `search`, `date_from`, `date_to`, `sort_by`, `sort_order` |

Keys and CSRs gain **pagination** (previously returned all records).

### Enhanced: Web UI

- **MCP nav link** — opens `/mcp-install`
- **Navbar reorder** — `MCP · Logs · AI · Help · About`
- **About page** — MCP Test Report link (greyed out until a report exists)
- `/reports/mcp/latest` — serves latest MCP test report; friendly "not yet generated" page if none exists

### New: MCP Test Suite (`tests_repo/test_mcp.py`)

- 56 tests covering all API endpoint groups + live MCP tool calls
- Runs via `scripts/run_tests_mcp.ps1` (auto-sets enterprise edition, keeps latest 2 reports)
- Report served at `/reports/mcp/latest`

### Maintenance

- `.gitignore` — comprehensive update: `.venv/`, `pki_mcp/.venv/`, `pki_mcp/.python/`, `.vscode/`, `.env*`, `.mcp-*.env`, timestamped test reports, build artifacts
- `version.txt` updated to `2.20`

---

## 2.10 — 2026-07-16

Previous release. See git history for details.
