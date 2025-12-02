#!/bin/bash
# Build script for creating standalone executable of PII Anonymization Tool

set -e

echo "🚀 Building PII Anonymization Tool executable..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Python 3 is not installed."
    echo "Please install Python 3.9+ from https://www.python.org/downloads/"
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

echo "✓ Python found: $($PYTHON_CMD --version)"

# Check if UV is installed
if ! command -v uv &> /dev/null; then
    echo "❌ UV is not installed."
    echo "Please install UV first:"
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo "✓ UV found: $(uv --version)"
echo ""

# Install dependencies including build tools
echo "📦 Installing dependencies..."
uv sync --extra build

# Install spaCy model
echo "📦 Installing spaCy English model..."
uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf build dist __pycache__
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Build the executable
echo "🔨 Building executable with PyInstaller..."
uv run pyinstaller anonymize.spec --clean

echo ""
echo "✅ Build complete!"
echo ""
echo "📦 Executable location: dist/anonymize"
echo "📏 Size: $(du -h dist/anonymize | cut -f1)"
echo ""
echo "Test the executable with:"
echo "  ./dist/anonymize examples/sample_input.txt -o test_output.txt"
echo ""
echo "📤 To distribute, simply share the 'dist/anonymize' file."
echo "   The recipient can run it directly without installing Python or dependencies!"
