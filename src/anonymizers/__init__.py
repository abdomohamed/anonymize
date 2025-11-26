"""
Anonymizers package for PII anonymization.

This package contains all anonymizer implementations for replacing detected
PII with anonymized versions using various strategies.
"""

from src.anonymizers.base_anonymizer import BaseAnonymizer

__all__ = ['BaseAnonymizer']
