#!/usr/bin/env bash
# Setup script for PII Anonymization Tool

set -e

echo "🚀 Setting up PII Anonymization Tool..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    echo "Please install Python 3.9+ from https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✓ Python $PYTHON_VERSION found"

# Check if UV is installed, if not install it
if ! command -v uv &> /dev/null; then
    echo "📦 UV not found. Installing UV..."
    if command -v curl &> /dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.cargo/bin:$PATH"
    elif command -v wget &> /dev/null; then
        wget -qO- https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "❌ Neither curl nor wget found. Please install UV manually:"
        echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
fi

UV_VERSION=$(uv --version | cut -d' ' -f2)
echo "✓ UV $UV_VERSION found"
echo ""

# Install dependencies (includes spaCy model)
echo "📦 Installing project dependencies..."
uv sync

echo ""
echo "✅ Setup complete!"
echo ""
echo "Usage: uv run anonymize input.txt -o output.txt"
echo "   or: source .venv/bin/activate && python -m src.cli input.txt -o output.txt"
