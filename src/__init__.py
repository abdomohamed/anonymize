"""PII Anonymization Tool package."""

__version__ = "1.0.0"
__author__ = "Your Name"
__description__ = "A tool for detecting and anonymizing PII in text files"

from src.models import PIIMatch, ProcessResult, PIIType, AnonymizationStrategy
from src.processors import FileProcessor
from src.config import ConfigManager

__all__ = [
    'PIIMatch',
    'ProcessResult',
    'PIIType',
    'AnonymizationStrategy',
    'FileProcessor',
    'ConfigManager',
]
