# run_tests_api.ps1
# Run the full API / protocol certificate test suite and generate a self-contained HTML report.
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\run_tests_api.ps1
#
# Prerequisites:
#   - estclient installed in WSL  (~/go/bin/estclient)
#   - WSL /etc/hosts maps localhost-wsl-win to the Windows host IP
#   - config.ini has a valid tests_api_token under [DEFAULT]

Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH   = (Resolve-Path .).Path
$env:PIKACHU_EDITION = if ($env:PIKACHU_EDITION) { $env:PIKACHU_EDITION } else { "enterprise" }

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$report    = "tests_repo\reports\pikachu_test_api_full_$timestamp.html"

$pytest = ".\.venv\Scripts\pytest.exe"
if (-not (Test-Path $pytest)) { $pytest = "pytest" }

Write-Host "Starting API tests → $report" -ForegroundColor Cyan
& $pytest `
    "tests_repo/test_certificates_api.py" `
    "--capture=tee-sys" `
    "--self-contained-html" `
    "--html=$report"
$exit_code = $LASTEXITCODE

Write-Host ""
if ($exit_code -eq 0) {
    Write-Host "API tests PASSED. Report: $report" -ForegroundColor Green
} else {
    Write-Host "API tests FAILED (exit $exit_code). Report: $report" -ForegroundColor Red
}

exit $exit_code
