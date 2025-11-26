"""
Base anonymizer class for PII anonymization.

This module defines the abstract base class that all anonymizers must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from src.models import PIIMatch


class BaseAnonymizer(ABC):
    """
    Abstract base class for all anonymization strategies.
    
    All anonymizer implementations must inherit from this class and implement
    the anonymize() method. Anonymizers are responsible for replacing detected
    PII with anonymized versions.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the anonymizer with configuration.
        
        Args:
            config: Configuration dictionary for the anonymizer
        """
        self.config = config
        self.name = self.__class__.__name__
    
    @abstractmethod
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """
        Anonymize a single PII match.
        
        This is the main method that each anonymizer must implement. It should
        take a PIIMatch object and return the anonymized replacement string.
        
        Args:
            match: PIIMatch object containing the PII to anonymize
            context: Optional context string (full text) for context-aware anonymization
            
        Returns:
            Anonymized replacement string
        """
        pass
    
    @abstractmethod
    def get_strategy_name(self) -> str:
        """
        Get the name of this anonymization strategy.
        
        Returns:
            String representing the strategy name (e.g., "redact", "mask")
        """
        pass
    
    def anonymize_batch(self, matches: List[PIIMatch], text: str) -> str:
        """
        Anonymize multiple PII matches in text.
        
        This method efficiently replaces all detected PII in the text with
        anonymized versions. It processes matches in reverse order to maintain
        correct string positions.
        
        Args:
            matches: List of PIIMatch objects to anonymize
            text: The original text containing the PII
            
        Returns:
            Text with all PII anonymized
        """
        if not matches:
            return text
        
        # Sort matches by position in reverse order to maintain string indices
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        
        result = text
        for match in sorted_matches:
            # Get the anonymized replacement
            replacement = self.anonymize(match, text)
            
            # Replace the PII in the text
            result = result[:match.start] + replacement + result[match.end:]
        
        return result
    
    def get_config_option(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration option for this anonymizer.
        
        Args:
            key: Configuration key to retrieve
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def __repr__(self) -> str:
        """String representation of the anonymizer."""
        return f"{self.name}(strategy={self.get_strategy_name()})"
