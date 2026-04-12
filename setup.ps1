#Requires -Version 5.1
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ___  _     _       _"
Write-Host " / __|| |   (_) _ _ | |_"
Write-Host "| (_ || |__ | || ' \|  _|"
Write-Host " \___||____||_||_||_|\__|"
Write-Host ""
Write-Host "glint -- setup"
Write-Host "--------------"
Write-Host ""

# ── uv ────────────────────────────────────────────────────────────────────────
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "[+] installing uv..."
    powershell -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/install.ps1 | iex"
    $env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"
} else {
    $uvVer = uv --version
    Write-Host "[ok] uv found: $uvVer"
}

# ── dependencies ──────────────────────────────────────────────────────────────
Write-Host "[+] installing dependencies..."
uv sync

# ── .env ──────────────────────────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    $secret = uv run python -c "import secrets; print(secrets.token_hex())"
    (Get-Content ".env") -replace "change-me-generate-a-real-secret", $secret | Set-Content ".env"
    Write-Host "[+] .env created with generated SECRET_KEY"
} else {
    Write-Host "[ok] .env already exists -- skipping"
}

# ── cloudflared (optional) ────────────────────────────────────────────────────
Write-Host ""
$ans = Read-Host "[?] install cloudflared for public URL testing? (y/N)"
if ($ans -match "^[Yy]$") {
    if (Get-Command cloudflared -ErrorAction SilentlyContinue) {
        Write-Host "[ok] cloudflared already installed"
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install Cloudflare.cloudflared
        # refresh PATH so cloudflared is available in this session
        $machinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        $userPath    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $env:PATH    = "$machinePath;$userPath"
        if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
            Write-Host "[!] PATH updated but cloudflared not found yet -- open a new terminal before running the tunnel"
        } else {
            Write-Host "[ok] cloudflared installed and available"
        }
    } else {
        Write-Host "[!] winget not available -- download cloudflared manually:"
        Write-Host "    https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    }
}

# ── done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "done."
Write-Host ""
Write-Host "  run server:       uv run python -m glint"
Write-Host "  public tunnel:    cloudflared tunnel --url http://localhost:5000"
Write-Host ""
