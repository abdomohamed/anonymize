#!/usr/bin/env pwsh

# Setup script for PII Anonymization Tool

$ErrorActionPreference = "Stop"

Write-Host "🚀 Setting up PII Anonymization Tool..." -ForegroundColor Cyan

Write-Host ""

# Check if Python is installed

$pythonCommand = $null

if (Get-Command python -ErrorAction SilentlyContinue) {

    $pythonCommand = "python"

} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {

    $pythonCommand = "python3"

}

if (-not $pythonCommand) {

    Write-Host "❌ Python 3 is not installed." -ForegroundColor Red

    Write-Host "Please install Python 3.9+ from https://www.python.org/downloads/"

    exit 1

}

$pythonVersionOutput = & $pythonCommand --version

$pythonVersion = ($pythonVersionOutput -split ' ')[1]

Write-Host "✓ Python $pythonVersion found" -ForegroundColor Green

# Check if UV is installed, if not install it

$uvCommand = Get-Command uv -ErrorAction SilentlyContinue

if (-not $uvCommand) {

    Write-Host "📦 UV not found. Installing UV..." -ForegroundColor Yellow

    # Check for PowerShell or irm command

    if (Get-Command irm -ErrorAction SilentlyContinue) {

        irm https://astral.sh/uv/install.ps1 | iex

    } else {

        Write-Host "❌ Unable to install UV automatically." -ForegroundColor Red

        Write-Host "   Please install UV manually:"

        Write-Host "   irm https://astral.sh/uv/install.ps1 | iex"

        exit 1

    }

    # Refresh environment variables

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

}

$uvVersionOutput = uv --version

$uvVersion = ($uvVersionOutput -split ' ')[1]

Write-Host "✓ UV $uvVersion found" -ForegroundColor Green

Write-Host ""

# Install dependencies (includes spaCy model)

Write-Host "📦 Installing project dependencies..." -ForegroundColor Yellow

uv sync

Write-Host ""

Write-Host "✅ Setup complete!" -ForegroundColor Green

Write-Host ""

Write-Host "Usage: uv run anonymize input.txt -o output.txt"

Write-Host "   or: .venv\Scripts\Activate.ps1; python -m src.cli input.txt -o output.txt"
