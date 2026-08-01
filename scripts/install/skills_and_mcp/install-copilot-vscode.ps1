<#
Install pki-mcp (MCP entry + skill) for GitHub Copilot -- VS Code extension.

  .\install-copilot-vscode.ps1                                    # interactive
  .\install-copilot-vscode.ps1 -Http [-Url <url>] [-Token <tok>]  # HTTP client non-interactive
  .\install-copilot-vscode.ps1 -Reconfigure                       # force replace existing entry

Walks you through two sections:
  Section 1 -- Pikachu CA server  (Flask PKI URL + API token)
  Section 2 -- PKI MCP server     (transport: stdio or HTTP, URL, auth token)

Writes/merges VS Code user MCP config (%APPDATA%\Code\User\mcp.json)
and copies the rad-pki-operations skill to ~\.copilot\skills.
#>
param(
    [switch]$Http,
    [string]$Url,
    [string]$Token,
    [string]$Name = 'pki-mcp',
    [switch]$Reconfigure
)
. (Join-Path $PSScriptRoot '..\_common.ps1')

$cfgPath = Join-Path $env:APPDATA 'Code\User\mcp.json'
New-Item -ItemType Directory -Force (Split-Path $cfgPath) | Out-Null
Backup-JsonConfig -Path $cfgPath

# -- keep existing? ----------------------------------------------------------
$explicit = $Http -or $Url -or $Token -or $Reconfigure
if ((-not $explicit) -and (Test-KeepExisting -Path $cfgPath -RootKey 'servers' -Name $Name)) {
    Write-Host "  mcp   -> kept existing $Name entry in $cfgPath"
    Copy-SkillsTo "$env:USERPROFILE\.copilot\skills"
    Write-Host ""
    Write-Host "Done. Existing MCP config kept; skill refreshed. Reload the VS Code window."
    exit 0
}

# -- non-interactive shortcut (flags provided) --------------------------------
if ($explicit -and ($Http -or $Url -or $Token)) {
    $Url, $Token = Resolve-HttpArgs $Url $Token
    $entry = New-HttpEntry -Url $Url -Token $Token
    $mode  = 'http' ; $servedUrl = $Url
} else {
    # ── Transport choice (brief -- determines section 1 content) ────────────
    $mode = Get-TransportChoice

    # ── Section 1 : Pikachu CA server ────────────────────────────────────────
    if ($mode -eq 'stdio') {
        $ca = Invoke-Section1-Stdio     # prompts for / loads PKI URL + token
    } else {
        Invoke-Section1-Http | Out-Null # shows saved server PKI URL (info only)
    }

    # ── Section 2 : PKI MCP server ───────────────────────────────────────────
    if ($mode -eq 'stdio') {
        Show-Section2-Stdio
        Assert-Venv
        $entry     = New-StdioEntry -WithType -BaseUrl $ca.BaseUrl -Token $ca.Token
        $servedUrl = ''
    } else {
        $mcp       = Invoke-Section2-Http   # prompts for MCP URL + token
        $entry     = New-HttpEntry -Url $mcp.Url -Token $mcp.Token
        $servedUrl = $mcp.Url
    }
}

Show-PkiServerStatus -Mode $mode -BaseUrl $servedUrl

# -- write config + skill ----------------------------------------------------
Set-JsonMcpEntry -Path $cfgPath -RootKey 'servers' -Entry $entry -Name $Name
Copy-SkillsTo "$env:USERPROFILE\.copilot\skills"

Write-Host ""
Write-Host "Done. Now:"
Write-Host "  1. Reload the VS Code window (Ctrl+Shift+P -> 'Developer: Reload Window')"
Write-Host "  2. Accept the MCP trust dialog for pki-mcp"
Write-Host "  3. Switch Copilot Chat to AGENT mode"
Write-Host "  4. Try: 'show me the PKI dashboard stats'"
if ($mode -eq 'http') { Write-Host "  NOTE: make sure the pki-mcp HTTP server is running at $servedUrl" }
