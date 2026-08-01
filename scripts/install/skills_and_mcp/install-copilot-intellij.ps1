<#
Install pki-mcp (MCP entry + skill) for GitHub Copilot in JetBrains IDEs
(IntelliJ IDEA, PyCharm, WebStorm, ...).

  .\install-copilot-intellij.ps1                                    # interactive prompts
  .\install-copilot-intellij.ps1 -Http [-Url <url>] [-Token <tok>]  # HTTP client
  .\install-copilot-intellij.ps1 -Reconfigure                       # force replace

JetBrains Copilot has TWO agent paths -- this script wires BOTH:
  - classic agent mode  -> %LOCALAPPDATA%\github-copilot\intellij\mcp.json
                           (root key "servers"; shared by ALL JetBrains IDEs)
  - embedded Copilot CLI agent (chat: /mcp, /skills)
                        -> ~\.copilot\mcp-config.json  +  ~\.copilot\mcp.json

Also copies the rad-pki-operations skill to ~\.copilot\skills.

Requires the official "GitHub Copilot" plugin (by GitHub), not JetBrains AI Assistant.

Afterwards: restart the IDE, Settings -> GitHub Copilot -> Chat -> enable Agent
Skills, accept MCP trust, start a NEW chat, then verify:
  /mcp list    -> pki-mcp listed
  /skills list -> rad-pki-operations listed
#>
param(
    [switch]$Http,
    [string]$Url,
    [string]$Token,
    [string]$Name = 'pki-mcp',
    [switch]$Reconfigure
)
. (Join-Path $PSScriptRoot '..\_common.ps1')

$cfgPath = Join-Path $env:LOCALAPPDATA 'github-copilot\intellij\mcp.json'
New-Item -ItemType Directory -Force (Split-Path $cfgPath) | Out-Null
Backup-JsonConfig -Path $cfgPath

# -- keep existing? ----------------------------------------------------------
$explicit = $Http -or $Url -or $Token -or $Reconfigure
if ((-not $explicit) -and (Test-KeepExisting -Path $cfgPath -RootKey 'servers' -Name $Name)) {
    Write-Host "  mcp   -> kept existing $Name entry in $cfgPath"
    Copy-SkillsTo "$env:USERPROFILE\.copilot\skills"
    Write-Host ""
    Write-Host "Done. Existing MCP config kept; skill refreshed. Restart the IDE."
    exit 0
}

# -- resolve transport -------------------------------------------------------
$mode = 'stdio' ; $servedUrl = ''
if ($Http -or $Url -or $Token) {
    $Url, $Token = Resolve-HttpArgs $Url $Token
    $mode = 'http' ; $servedUrl = $Url
    # IntelliJ classic agent uses requestInit; Copilot CLI agent uses plain headers
    $entry    = New-HttpEntry -Url $Url -Token $Token -RequestInit
    $cliEntry = New-HttpEntry -Url $Url -Token $Token
} else {
    $transport = Invoke-TransportPrompt
    if ($transport.Mode -eq 'http') {
        $mode = 'http' ; $servedUrl = $transport.Url
        $entry    = New-HttpEntry -Url $transport.Url -Token $transport.Token -RequestInit
        $cliEntry = New-HttpEntry -Url $transport.Url -Token $transport.Token
    } else {
        $creds = Prompt-PkiCredentials
        Assert-Venv
        $entry = New-StdioEntry -WithType -BaseUrl $creds.BaseUrl -Token $creds.Token
        # Copilot CLI embedded agent uses type "local"
        $cliEntry = [ordered]@{
            type    = 'local'
            command = $script:VenvPython
            args    = @('-m', $script:McpModule, '--transport', 'stdio')
            env     = [ordered]@{
                PKI_BASE_URL   = $creds.BaseUrl
                PKI_TOKEN      = $creds.Token
                PKI_VERIFY_SSL = 'false'
            }
        }
    }
}

Show-PkiServerStatus -Mode $mode -BaseUrl $servedUrl

# -- write config (both agent paths) + skill ---------------------------------
Set-JsonMcpEntry -Path $cfgPath -RootKey 'servers' -Entry $entry -Name $Name

foreach ($p in @("$env:USERPROFILE\.copilot\mcp-config.json",
                 "$env:USERPROFILE\.copilot\mcp.json")) {
    Backup-JsonConfig -Path $p
    Set-JsonMcpEntry -Path $p -RootKey 'mcpServers' -Entry $cliEntry -Name $Name
}
Copy-SkillsTo "$env:USERPROFILE\.copilot\skills"

Write-Host ""
Write-Host "Done. Now:"
Write-Host "  1. Restart the JetBrains IDE"
Write-Host "  2. Settings -> GitHub Copilot -> Chat -> enable Agent Skills"
Write-Host "  3. Accept the MCP trust prompt for pki-mcp"
Write-Host "  4. Switch Copilot Chat to AGENT mode and START A NEW CHAT"
Write-Host "  5. Verify:"
Write-Host "       /mcp list    -> pki-mcp listed"
Write-Host "       /skills list -> rad-pki-operations listed"
Write-Host "       'show me the PKI dashboard stats'"
if ($mode -eq 'http') { Write-Host "  NOTE: make sure the pki-mcp HTTP server is running at $servedUrl" }
