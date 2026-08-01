<#
Generic manual helper -- prints MCP config snippets and the skill copy command
for any AI client. Does NOT write any config files or copy any skills.

  .\install-generic.ps1                                  # interactive
  .\install-generic.ps1 -Http [-Url <url>] [-Token <t>]  # HTTP snippets (non-interactive)

Walks you through two sections:
  Section 1 -- Pikachu CA server  (Flask PKI URL + API token)
  Section 2 -- PKI MCP server     (transport: stdio or HTTP, URL, auth token)
#>
param(
    [switch]$Http,
    [string]$Url,
    [string]$Token,
    [string]$Name = 'pki-mcp'
)
. (Join-Path $PSScriptRoot '..\_common.ps1')

# -- non-interactive shortcut ------------------------------------------------
if ($Http -or $Url -or $Token) {
    $Url, $Token = Resolve-HttpArgs $Url $Token
    $mode = 'http'
} else {
    # ── Transport choice ─────────────────────────────────────────────────────
    $mode = Get-TransportChoice

    # ── Section 1 : Pikachu CA server ────────────────────────────────────────
    if ($mode -eq 'stdio') {
        $ca = Invoke-Section1-Stdio
    } else {
        Invoke-Section1-Http | Out-Null
        $mcp = Invoke-Section2-Http
        $Url   = $mcp.Url
        $Token = $mcp.Token
    }

    # ── Section 2 : PKI MCP server (stdio path only -- HTTP handled above) ───
    if ($mode -eq 'stdio') {
        Show-Section2-Stdio
    }
}

# -- print snippets ----------------------------------------------------------
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗"
Write-Host "  ║  pki-mcp config snippets -- paste into client config  ║"
Write-Host "  ╚══════════════════════════════════════════════════════╝"
Write-Host ""

if ($mode -eq 'stdio') {
    $py  = $script:VenvPython
    $cwd = $script:PkiRoot
    $bu  = $ca.BaseUrl
    $tok = $ca.Token

    Write-Host "-- VS Code (mcp.json > servers) ----------------------"
    Write-Host @"
{
  "servers": {
    "$Name": {
      "type":    "stdio",
      "command": "$py",
      "args":    ["-m", "pki_mcp.server", "--transport", "stdio"],
      "cwd":     "$cwd",
      "env": {
        "PKI_BASE_URL":   "$bu",
        "PKI_TOKEN":      "$tok",
        "PKI_VERIFY_SSL": "false"
      }
    }
  }
}
"@
    Write-Host ""
    Write-Host "-- Claude Desktop (claude_desktop_config.json > mcpServers) --"
    Write-Host @"
{
  "mcpServers": {
    "$Name": {
      "command": "$py",
      "args":    ["-m", "pki_mcp.server", "--transport", "stdio"],
      "cwd":     "$cwd",
      "env": {
        "PKI_BASE_URL":   "$bu",
        "PKI_TOKEN":      "$tok",
        "PKI_VERIFY_SSL": "false"
      }
    }
  }
}
"@
} else {
    Write-Host "-- VS Code / generic (mcp.json > servers) ------------"
    Write-Host @"
{
  "servers": {
    "$Name": {
      "type":    "http",
      "url":     "$Url",
      "headers": { "Authorization": "Bearer $Token" }
    }
  }
}
"@
    Write-Host ""
    Write-Host "-- IntelliJ (requestInit style) ----------------------"
    Write-Host @"
{
  "servers": {
    "$Name": {
      "type":        "http",
      "url":         "$Url",
      "requestInit": { "headers": { "Authorization": "Bearer $Token" } }
    }
  }
}
"@
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗"
Write-Host "  ║  Skill -- copy to your client's skill folder          ║"
Write-Host "  ╚══════════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "  Source : $script:SkillsSrc\rad-pki-operations"
Write-Host ""
Write-Host "  VS Code / IntelliJ Copilot:"
Write-Host "    Copy-Item -Recurse '$script:SkillsSrc\rad-pki-operations' '$env:USERPROFILE\.copilot\skills\'"
Write-Host ""
Write-Host "  Claude Desktop (zip upload):"
Write-Host "    Compress-Archive skills\rad-pki-operations\* rad-pki-operations.zip"
