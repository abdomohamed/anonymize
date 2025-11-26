"""
Hash anonymizer - replaces PII with consistent hashes.

This strategy uses cryptographic hashing to create consistent anonymized
values, useful when relationships need to be preserved.
"""

from src.anonymizers.base_anonymizer import BaseAnonymizer
from src.models import PIIMatch
from src.utils import calculate_hash, truncate_hash


class HashAnonymizer(BaseAnonymizer):
    """
    Hash anonymizer that generates consistent hashes for PII.
    
    Examples:
        - john.doe@example.com -> EMAIL_a3f5d9e1
        - Same email again -> EMAIL_a3f5d9e1 (consistent)
        - 555-123-4567 -> PHONE_b7c2e4f6
    """
    
    def __init__(self, config: dict):
        """
        Initialize hash anonymizer.
        
        Args:
            config: Configuration dictionary with hashing options
        """
        super().__init__(config)
        
        # Hash algorithm (md5, sha1, sha256)
        self.algorithm = self.get_config_option('algorithm', 'sha256')
        
        # Salt for hashing (should be kept secret)
        self.salt = self.get_config_option('salt', 'default_salt_change_in_production')
        
        # Include PII type prefix
        self.use_prefix = self.get_config_option('prefix', True)
        
        # Truncate hash to N characters
        self.truncate_length = self.get_config_option('truncate', 8)
    
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """
        Anonymize PII by generating a consistent hash.
        
        Args:
            match: PIIMatch object containing the PII to hash
            context: Optional full text context (unused in this strategy)
            
        Returns:
            Hashed string
        """
        # Calculate hash of the PII value
        hash_value = calculate_hash(
            text=match.value,
            algorithm=self.algorithm,
            salt=self.salt
        )
        
        # Truncate if configured
        if self.truncate_length:
            hash_value = truncate_hash(hash_value, self.truncate_length)
        
        # Add prefix if configured
        if self.use_prefix:
            return f"{match.pii_type}_{hash_value}"
        else:
            return hash_value
    
    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "hash"
