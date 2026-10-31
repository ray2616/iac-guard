$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
docker info --format '{{.ServerVersion}}' 2>$null
if ($LASTEXITCODE -ne 0) { throw "Open Docker Desktop and wait for the Linux engine to say Running, then retry." }
docker compose up --build -d
if ($LASTEXITCODE -ne 0) { throw "Application startup failed. Run: docker compose logs --tail 80 migrate api worker dispatcher" }
Write-Output 'Open http://127.0.0.1:8501 for IaC Guard; API documentation: http://127.0.0.1:8000/docs'
