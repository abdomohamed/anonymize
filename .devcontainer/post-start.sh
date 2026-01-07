#!/bin/bash
# Post-start script for devcontainer
# This runs every time the container starts

set -e

echo "🔧 Installing Python dependencies..."
cd /workspaces/anonymize
uv sync --all-extras

echo "✅ Dependencies installed successfully!"
