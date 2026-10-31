param([string]$PythonExe = "")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    if ($PythonExe) {
        & $PythonExe -m venv .venv
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.12 -m venv .venv
    } else {
        throw "Install Python 3.12 from python.org, or pass -PythonExe with its full path."
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Python 3.12 environment." }
}

& .\.venv\Scripts\python.exe -m pip install -c requirements-windows.lock.txt -e '.[scanners,ui,service,dev]'
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
& .\.venv\Scripts\python.exe -m iac_guard doctor
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Install Trivy with: winget install --id AquaSecurity.Trivy --exact"
}
