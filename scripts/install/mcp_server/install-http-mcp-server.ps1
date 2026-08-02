<#
Start the pki-mcp server in HTTP mode for shared/remote access.

  .\install-http-mcp-server.ps1                    # interactive (prompts for everything)
  .\install-http-mcp-server.ps1 -Reconfigure       # force re-prompt even if config exists
  .\install-http-mcp-server.ps1 -Port 9090         # override port (keep rest from saved config)

Prompts for:
  - PKI server URL and API token
  - TLS mode (no TLS / self-signed / import cert+key)
  - Read-write and read-only Bearer auth tokens for MCP clients
  - HTTP bind host and port

Config is saved to .mcp-http.env in the project root and reused on subsequent runs.
On each run you are asked whether to keep the existing config or reconfigure.

Client URL after start: http[s]://<host>:<port>/mcp
#>
param(
    [int]$Port = 0,
    [string]$BindHost = '',
    [switch]$Reconfigure
)

. (Join-Path $PSScriptRoot '..\_common.ps1')
Assert-Venv

# ---------------------------------------------------------------------------
# Load or collect configuration
# ---------------------------------------------------------------------------
if (-not $Reconfigure -and (Test-KeepHttpConfig)) {
    $cfg = Read-EnvFile $script:HttpEnvFile
    # Allow port/host override via params
    if ($Port -gt 0)    { $cfg['MCP_PORT'] = "$Port" }
    if ($BindHost)      { $cfg['MCP_HOST'] = $BindHost }
} else {
    Write-Host ""
    Write-Host "=== PKI server connection ==="
    Write-Host "  ┌─────────────────────────────────────────────────────┐"
    Write-Host "  │  Section 1 of 2  --  Pikachu CA server              │"
    Write-Host "  └─────────────────────────────────────────────────────┘"
    Write-Host "  Base URL of the Flask PKI/CA server."
    Write-Host "  (No server-side token needed: each client supplies its own via X-PKI-Token)"
    $pkiUrl = (Read-Host "  Pikachu CA base URL [https://localhost:443]").Trim()
    if (-not $pkiUrl) { $pkiUrl = 'https://localhost:443' }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐"
    Write-Host "  │  Section 2 of 2  --  PKI MCP server                 │"
    Write-Host "  └─────────────────────────────────────────────────────┘"
    Write-Host "  HTTP bind settings, TLS, and client auth tokens."
    $portStr = if ($Port -gt 0) { "$Port" } else {
        $p = (Read-Host "  Bind port [8080]").Trim()
        if (-not $p) { '8080' } else { $p }
    }
    $hostStr = if ($BindHost) { $BindHost } else {
        $h = (Read-Host "  Bind host [0.0.0.0]").Trim()
        if (-not $h) { '0.0.0.0' } else { $h }
    }

    $tls  = Invoke-TlsPrompt
    $toks = Invoke-McpTokensPrompt

    $cfg = [ordered]@{
        PKI_BASE_URL       = $pkiUrl
        PKI_VERIFY_SSL     = 'false'
        MCP_HOST           = $hostStr
        MCP_PORT           = $portStr
        MCP_AUTH_TOKEN     = $toks.RwToken
        MCP_READONLY_TOKEN = $toks.RoToken
    }
    if ($tls.CertFile) {
        $cfg['MCP_SSL_CERTFILE'] = $tls.CertFile
        $cfg['MCP_SSL_KEYFILE']  = $tls.KeyFile
    }
    Write-EnvFile $script:HttpEnvFile $cfg

    # Show client snippets
    $scheme = if ($tls.CertFile) { 'https' } else { 'http' }
    $mcpUrl = "$scheme`://localhost:$portStr/mcp"
    Write-Host ""
    Write-Host "----------------------------------------------------------------"
    Write-Host "  MCP HTTP client configuration:"
    Write-Host "  URL      : $mcpUrl"
    Write-Host "  RW token : $($toks.RwToken)"
    Write-Host "  RO token : $($toks.RoToken)"
    Write-Host ""
    Write-Host "  VS Code mcp.json:"
    Write-Host "    `"pki-mcp`": {"
    Write-Host "      `"type`": `"http`","
    Write-Host "      `"url`": `"$mcpUrl`","
    Write-Host "      `"headers`": {"
    Write-Host "        `"Authorization`": `"Bearer $($toks.RwToken)`","
    Write-Host "        `"X-PKI-Token`":   `"<your-personal-pki-api-token>`"  // REQUIRED"
    Write-Host "      }"
    Write-Host "    }"
    Write-Host "  (each client must set X-PKI-Token to their own PKI API token)"
    Write-Host "----------------------------------------------------------------"
}

# ---------------------------------------------------------------------------
# Apply env vars to current process and start server
# ---------------------------------------------------------------------------
foreach ($kv in $cfg.GetEnumerator()) {
    [System.Environment]::SetEnvironmentVariable($kv.Key, $kv.Value, 'Process')
}

$bindHost  = if ($cfg['MCP_HOST'])         { $cfg['MCP_HOST'] }   else { '0.0.0.0' }
$bindPort  = if ($cfg['MCP_PORT'])         { $cfg['MCP_PORT'] }   else { '8080' }
$scheme    = if ($cfg['MCP_SSL_CERTFILE']) { 'https' }            else { 'http' }
$mcpUrl    = "$scheme`://localhost:$bindPort/mcp"

Show-PkiServerStatus -Mode 'http' -BaseUrl $cfg['PKI_BASE_URL']

Write-Host ""
Write-Host "Starting pki-mcp HTTP server on $bindHost`:$bindPort ..."
Write-Host "PKI server   : $($cfg['PKI_BASE_URL'])"
Write-Host "Client URL   : $mcpUrl"
Write-Host "Auth         : $(if ($cfg['MCP_AUTH_TOKEN']) { 'token required' } else { 'open (no token)' })"
Write-Host "TLS          : $(if ($cfg['MCP_SSL_CERTFILE']) { 'yes (' + $cfg['MCP_SSL_CERTFILE'] + ')' } else { 'no' })"
Write-Host "Press Ctrl+C to stop."
Write-Host ""

$serverArgs = @('-m', $script:McpModule, '--transport', 'http', '--host', $bindHost, '--port', $bindPort)
if ($cfg['MCP_SSL_CERTFILE']) {
    $serverArgs += @('--ssl-certfile', $cfg['MCP_SSL_CERTFILE'], '--ssl-keyfile', $cfg['MCP_SSL_KEYFILE'])
}

& $script:VenvPython @serverArgs

