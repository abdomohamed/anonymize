"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

# Add the project root to the Python path so 'src.' imports work
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
