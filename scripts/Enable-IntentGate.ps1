param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

$pythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Virtual environment not found. Run: python -m venv .venv"
}

if (-not $env:UIG_STATE_DIR) {
    $env:UIG_STATE_DIR = Join-Path $ProjectRoot ".intentgate-state"
}

function global:uig {
    & $pythonPath -m intentgate.cli @args
}

Write-Host "Intent Gate enabled for this PowerShell session. State: $env:UIG_STATE_DIR"
