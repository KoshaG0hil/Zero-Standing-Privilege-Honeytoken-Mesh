Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host "  Zero-Standing-Privilege Dynamic Access & Honeytoken Mesh" -ForegroundColor Yellow
Write-Host "  AWS Ephemeral STS Broker · Canary Tripwire Containment" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

$VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    & $VenvPython -m src.cli simulate
} else {
    python -m src.cli simulate
}
