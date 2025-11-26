#!/usr/bin/env bash
# Setup script for PII Anonymization Tool

set -e

echo "🚀 Setting up PII Anonymization Tool..."

# Install spaCy model
echo "📦 Installing spaCy English model..."
uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

echo ""
echo "✅ Setup complete!"
echo ""
echo "Usage: uv run anonymize input.txt -o output.txt"
