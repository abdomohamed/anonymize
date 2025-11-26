"""
Redaction anonymizer - replaces PII with [REDACTED] tokens.

This is the simplest and most privacy-preserving anonymization strategy.
"""

from src.anonymizers.base_anonymizer import BaseAnonymizer
from src.models import PIIMatch


class Redactor(BaseAnonymizer):
    """
    Redaction anonymizer that replaces PII with redaction tokens.
    
    Examples:
        - john.doe@example.com -> [REDACTED]
        - 555-123-4567 -> [PHONE_REDACTED]
        - 123-45-6789 -> [SSN_REDACTED]
    """
    
    def __init__(self, config: dict):
        """
        Initialize redactor.
        
        Args:
            config: Configuration dictionary with redaction options
        """
        super().__init__(config)
        
        # Get redaction token from config
        self.token = self.get_config_option('token', '[REDACTED]')
        
        # Whether to use type-specific tokens
        self.type_specific = self.get_config_option('type_specific', True)
    
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """
        Anonymize PII by replacing with redaction token.
        
        Args:
            match: PIIMatch object containing the PII to redact
            context: Optional full text context (unused in this strategy)
            
        Returns:
            Redaction token string
        """
        if self.type_specific:
            # Use type-specific token like [EMAIL_REDACTED]
            return f"[{match.pii_type}_REDACTED]"
        else:
            # Use generic token
            return self.token
    
    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "redact"
