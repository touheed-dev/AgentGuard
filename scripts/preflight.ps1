# AgentGuard Preflight Verification Script (Fast Infrastructure Check)
# Verifies environment, Docker services, network ports, and live API availability.

$ErrorActionPreference = "Stop"

function Log-Pass($name) {
    Write-Host "[PASS] $name" -ForegroundColor Green
}

function Log-Fail($name, $details) {
    Write-Host "[FAIL] $name - $details" -ForegroundColor Red
}

$Failed = $false

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " AGENTGUARD PREFLIGHT INFRASTRUCTURE CHECK" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# A. Repository Structure Check
try {
    $requiredFiles = @("pyproject.toml", "docker-compose.yml", "alembic.ini", "Dockerfile")
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            throw "Missing required repository file: $file"
        }
    }
    $requiredDirs = @("backend", "frontend-teammate", "backend/tests", "docs")
    foreach ($dir in $requiredDirs) {
        if (-not (Test-Path $dir)) {
            throw "Missing required directory: $dir"
        }
    }
    Log-Pass "Repository structure"
} catch {
    Log-Fail "Repository structure" $_.Exception.Message
    $Failed = $true
}

# B. Docker Daemon Availability
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon unreachable."
    }
    Log-Pass "Docker daemon"
} catch {
    Log-Fail "Docker daemon" $_.Exception.Message
    $Failed = $true
}

# C. Environment Variables Check
try {
    if (-not (Test-Path ".env")) {
        throw ".env file does not exist."
    }
    $envLines = Get-Content ".env" | Where-Object { $_ -match "^[^#].+=" }
    $envMap = @{}
    foreach ($line in $envLines) {
        $parts = $line.Split("=", 2)
        if ($parts.Length -eq 2) {
            $envMap[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    if (-not $envMap.ContainsKey("POSTGRES_PASSWORD") -or [string]::IsNullOrWhiteSpace($envMap["POSTGRES_PASSWORD"])) {
        throw "POSTGRES_PASSWORD is missing or blank in .env"
    }
    if ($envMap["LLM_PROVIDER"] -ne "replay" -and $envMap["AGENTGUARD_ENV"] -ne "replay") {
        Write-Host "[WARN] Non-replay mode detected in .env; replay is expected default." -ForegroundColor Yellow
    }
    Log-Pass "Environment configuration (.env)"
} catch {
    Log-Fail "Environment configuration" $_.Exception.Message
    $Failed = $true
}

# D. Docker Compose Configuration Validation
try {
    $composeConfig = docker compose config --quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose config failed."
    }
    Log-Pass "Compose configuration"
} catch {
    Log-Fail "Compose configuration" $_.Exception.Message
    $Failed = $true
}

# E. Container Service Status
try {
    $psOutput = docker compose ps --format json 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to query container status."
    }
    if ($psOutput -notmatch "postgres") {
        throw "PostgreSQL container is not running."
    }
    if ($psOutput -notmatch "valkey") {
        throw "Valkey container is not running."
    }
    if ($psOutput -notmatch "gateway") {
        throw "Gateway container is not running."
    }
    Log-Pass "Docker Compose services running"
} catch {
    Log-Fail "Docker Compose services running" $_.Exception.Message
    $Failed = $true
}

# F. PostgreSQL Health
try {
    $pgCheck = docker compose exec -T postgres pg_isready -U agentguard -d agentguard 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "PostgreSQL health check failed: $pgCheck"
    }
    Log-Pass "PostgreSQL health & connection"
} catch {
    Log-Fail "PostgreSQL health & connection" $_.Exception.Message
    $Failed = $true
}

# G. Valkey Health
try {
    $valkeyCheck = docker compose exec -T valkey valkey-cli ping 2>&1
    if ($valkeyCheck.Trim() -ne "PONG") {
        throw "Valkey ping check failed: $valkeyCheck"
    }
    Log-Pass "Valkey health (PONG)"
} catch {
    Log-Fail "Valkey health" $_.Exception.Message
    $Failed = $true
}

# H. Gateway Running
try {
    $gwPs = docker compose ps gateway 2>&1 | Out-String
    if ($gwPs -notmatch "Up") {
        throw "Gateway container is not Up."
    }
    Log-Pass "Gateway container state"
} catch {
    Log-Fail "Gateway container state" $_.Exception.Message
    $Failed = $true
}

# I. Host Port 8000 Mapping
try {
    $portOutput = docker port agentguard-gateway-1 8000 2>&1 | Out-String
    if ($portOutput -notmatch "8000") {
        throw "Port 8000 is not published to host: $portOutput"
    }
    Log-Pass "Port 8000 published to host"
} catch {
    Log-Fail "Port 8000 published to host" $_.Exception.Message
    $Failed = $true
}

# J. Live Gateway API & OpenAPI Endpoints
try {
    $healthResp = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -TimeoutSec 5
    if ($healthResp.status -ne "ok") {
        throw "Health status is not 'ok': $($healthResp.status)"
    }
    Log-Pass "Gateway health (http://localhost:8000/health)"
} catch {
    Log-Fail "Gateway health" $_.Exception.Message
    $Failed = $true
}

try {
    $openapiResp = Invoke-RestMethod -Uri "http://localhost:8000/openapi.json" -Method Get -TimeoutSec 5
    if (-not $openapiResp.openapi) {
        throw "Invalid OpenAPI schema response."
    }
    Log-Pass "OpenAPI schema (http://localhost:8000/openapi.json)"
} catch {
    Log-Fail "OpenAPI schema" $_.Exception.Message
    $Failed = $true
}

Write-Host "==================================================" -ForegroundColor Cyan
if ($Failed) {
    Write-Host "PREFLIGHT: FAIL" -ForegroundColor Red
    exit 1
} else {
    Write-Host "PREFLIGHT: PASS" -ForegroundColor Green
    exit 0
}
