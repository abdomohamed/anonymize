"""
Data models for PII Anonymization Tool.

This module defines the core data structures used throughout the application.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class PIIType(Enum):
    """Enumeration of supported PII types."""
    
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    NAME = "NAME"
    ADDRESS = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    CUSTOM = "CUSTOM"


class AnonymizationStrategy(Enum):
    """Enumeration of anonymization strategies."""
    
    REDACT = "redact"
    MASK = "mask"
    REPLACE = "replace"
    HASH = "hash"


@dataclass
class PIIMatch:
    """
    Represents a detected PII instance in text.
    
    Attributes:
        pii_type: Type of PII detected (EMAIL, PHONE, etc.)
        value: The actual PII value found in text
        start: Start position in the text (character index)
        end: End position in the text (character index)
        confidence: Confidence score of the detection (0.0 - 1.0)
        context: Surrounding text for context (optional)
        detector_name: Name of the detector that found this PII
    """
    
    pii_type: str
    value: str
    start: int
    end: int
    confidence: float
    context: str = ""
    detector_name: str = "unknown"
    
    def __post_init__(self):
        """Validate the PIIMatch after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.start < 0 or self.end < 0:
            raise ValueError(f"Start and end positions must be non-negative")
        if self.start >= self.end:
            raise ValueError(f"Start position must be less than end position")
    
    def overlaps_with(self, other: 'PIIMatch') -> bool:
        """
        Check if this match overlaps with another match.
        
        Args:
            other: Another PIIMatch instance
            
        Returns:
            True if matches overlap, False otherwise
        """
        return not (self.end <= other.start or self.start >= other.end)
    
    def length(self) -> int:
        """Return the length of the matched PII."""
        return self.end - self.start


@dataclass
class ProcessResult:
    """
    Result of processing a single file.
    
    Attributes:
        success: Whether processing was successful
        input_path: Path to the input file
        output_path: Path to the output file (if successful)
        pii_found: Number of PII instances detected
        pii_anonymized: Number of PII instances actually anonymized
        errors: List of error messages encountered
        warnings: List of warning messages
        processing_time: Time taken to process (in seconds)
        matches: List of all PII matches found (optional)
    """
    
    success: bool
    input_path: str
    output_path: Optional[str] = None
    pii_found: int = 0
    llm_pii_found: int = 0
    pii_anonymized: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    processing_time: float = 0.0
    matches: Optional[List[PIIMatch]] = None
    
    def add_error(self, error: str) -> None:
        """Add an error message to the result."""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning message to the result."""
        self.warnings.append(warning)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "success": self.success,
            "input_path": self.input_path,
            "output_path": self.output_path,
            "pii_found": self.pii_found,
            "pii_anonymized": self.pii_anonymized,
            "errors": self.errors,
            "warnings": self.warnings,
            "processing_time": self.processing_time,
        }


@dataclass
class AuditLogEntry:
    """
    Entry in the audit log for a single anonymization action.
    
    Attributes:
        pii_type: Type of PII anonymized
        position: Position in original text
        anonymization_strategy: Strategy used for anonymization
        timestamp: ISO format timestamp of anonymization
        hash_value: Optional hash of the original value (for tracking)
    """
    
    pii_type: str
    position: int
    anonymization_strategy: str
    timestamp: str
    hash_value: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization."""
        return {
            "pii_type": self.pii_type,
            "position": self.position,
            "strategy": self.anonymization_strategy,
            "timestamp": self.timestamp,
            "hash": self.hash_value,
        }


@dataclass
class DetectorConfig:
    """
    Configuration for a PII detector.
    
    Attributes:
        name: Name of the detector
        enabled: Whether this detector is enabled
        confidence_threshold: Minimum confidence for detection
        patterns: Custom regex patterns (for regex detectors)
        options: Additional detector-specific options
    """
    
    name: str
    enabled: bool = True
    confidence_threshold: float = 0.7
    patterns: Dict[str, str] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnonymizerConfig:
    """
    Configuration for an anonymization strategy.
    
    Attributes:
        strategy: The anonymization strategy to use
        options: Strategy-specific options
    """
    
    strategy: str
    options: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate strategy."""
        valid_strategies = [s.value for s in AnonymizationStrategy]
        if self.strategy not in valid_strategies:
            raise ValueError(f"Invalid strategy: {self.strategy}. Must be one of {valid_strategies}")


@dataclass
class Config:
    """
    Main configuration for the PII Anonymization Tool.
    
    Attributes:
        detection: Detection configuration
        anonymization: Anonymization configuration
        processing: Processing options
        whitelist: List of values to never anonymize
        blacklist: List of values to always anonymize
        logging: Logging configuration
    """
    
    detection: Dict[str, Any]
    anonymization: Dict[str, Any]
    processing: Dict[str, Any]
    whitelist: Dict[str, List[str]] = field(default_factory=dict)
    blacklist: List[str] = field(default_factory=list)
    logging: Dict[str, Any] = field(default_factory=dict)
