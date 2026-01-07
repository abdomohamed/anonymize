#!/usr/bin/env pwsh
# Build script for creating standalone executable of PII Anonymization Tool

$ErrorActionPreference = "Stop"

Write-Host "🚀 Building PII Anonymization Tool executable..." -ForegroundColor Cyan
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
Write-Host "✓ Python found: $pythonVersionOutput" -ForegroundColor Green

# Check if UV is installed
$uvCommand = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvCommand) {
    Write-Host "❌ UV is not installed." -ForegroundColor Red
    Write-Host "Please install UV first:"
    Write-Host "  irm https://astral.sh/uv/install.ps1 | iex"
    exit 1
}

$uvVersionOutput = uv --version
Write-Host "✓ UV found: $uvVersionOutput" -ForegroundColor Green
Write-Host ""

# Install dependencies including build tools (includes spaCy model)
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
uv sync --extra build

# Clean previous builds
Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -Filter "__pycache__" -Recurse -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Build the executable
Write-Host "🔨 Building executable with PyInstaller..." -ForegroundColor Yellow
uv run pyinstaller anonymize.spec --clean

Write-Host ""
Write-Host "✅ Build complete!" -ForegroundColor Green
Write-Host ""

# Get executable size
$exePath = "dist\anonymize.exe"
if (Test-Path $exePath) {
    $sizeInMB = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
    Write-Host "📦 Executable location: $exePath" -ForegroundColor Cyan
    Write-Host "📏 Size: $sizeInMB MB" -ForegroundColor Cyan
} else {
    Write-Host "📦 Executable location: dist\anonymize" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Test the executable with:" -ForegroundColor Yellow
Write-Host "  .\dist\anonymize.exe examples\sample_input.txt -o test_output.txt"
Write-Host ""
Write-Host "📤 To distribute, simply share the 'dist\anonymize.exe' file." -ForegroundColor Green
Write-Host "   The recipient can run it directly without installing Python or dependencies!" -ForegroundColor Green
