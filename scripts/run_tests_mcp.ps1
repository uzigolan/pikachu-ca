# run_tests_mcp.ps1
# Run the MCP endpoint test suite and generate a self-contained HTML report.
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\run_tests_mcp.ps1
#
# For live MCP tool tests (requires a running PKI server + API token):
#   $env:PKI_MCP_LIVE="1"; $env:PKI_MCP_TOKEN="<token>"; $env:PKI_MCP_URL="https://localhost:443"
#   powershell -ExecutionPolicy Bypass -File scripts\run_tests_mcp.ps1

Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH      = (Resolve-Path .).Path
$env:PIKACHU_EDITION = if ($env:PIKACHU_EDITION) { $env:PIKACHU_EDITION } else { "enterprise" }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$report    = "tests_repo\reports\pikachu_test_mcp_$timestamp.html"

$pytest = ".\.venv\Scripts\pytest.exe"
if (-not (Test-Path $pytest)) { $pytest = "pytest" }

# Decide which tests to run: endpoint-only, or endpoint + live tool tests
$live = $env:PKI_MCP_LIVE -and $env:PKI_MCP_TOKEN
$filter = if ($live) { "" } else { "-k not live" }

Write-Host "Starting MCP tests$(if ($live) { ' (including live server tests)' }) → $report" -ForegroundColor Cyan

$args_list = @(
    "tests_repo/test_mcp.py",
    "--capture=tee-sys",
    "--self-contained-html",
    "--html=$report"
)
if (-not $live) { $args_list += "-k"; $args_list += "not live" }

& $pytest @args_list
$exit_code = $LASTEXITCODE

# Keep only the 2 most recent MCP reports (same policy as UI and API reports)
$reports_dir = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests_repo\reports'
$old_reports = Get-ChildItem $reports_dir -Filter 'pikachu_test_mcp_*.html' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 2
foreach ($f in $old_reports) {
    Remove-Item $f.FullName -Force
    Write-Host "  cleaned up old report: $($f.Name)" -ForegroundColor DarkGray
}

Write-Host ""
if ($exit_code -eq 0) {
    Write-Host "MCP tests PASSED. Report: $report" -ForegroundColor Green
} else {
    Write-Host "MCP tests FAILED (exit $exit_code). Report: $report" -ForegroundColor Red
}

exit $exit_code
