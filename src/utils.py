"""
Utility functions for PII Anonymization Tool.

This module provides common utility functions used across the application.
"""

import hashlib
import re
from typing import List, Set
from datetime import datetime


def calculate_hash(text: str, algorithm: str = "sha256", salt: str = "") -> str:
    """
    Calculate hash of text using specified algorithm.
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm to use (md5, sha1, sha256)
        salt: Salt to add to hash
        
    Returns:
        Hexadecimal hash string
    """
    salted_text = f"{salt}{text}".encode('utf-8')
    
    if algorithm == "md5":
        return hashlib.md5(salted_text).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(salted_text).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(salted_text).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def truncate_hash(hash_str: str, length: int = 8) -> str:
    """
    Truncate hash string to specified length.
    
    Args:
        hash_str: Full hash string
        length: Number of characters to keep
        
    Returns:
        Truncated hash string
    """
    return hash_str[:length]


def get_context(text: str, start: int, end: int, context_chars: int = 20) -> str:
    """
    Extract context around a matched PII.
    
    Args:
        text: Full text
        start: Start position of match
        end: End position of match
        context_chars: Number of characters to include before and after
        
    Returns:
        Context string with match highlighted
    """
    context_start = max(0, start - context_chars)
    context_end = min(len(text), end + context_chars)
    
    before = text[context_start:start]
    match = text[start:end]
    after = text[end:context_end]
    
    return f"...{before}[{match}]{after}..."


def is_valid_email_domain(domain: str) -> bool:
    """
    Check if email domain is valid.
    
    Args:
        domain: Email domain to validate
        
    Returns:
        True if domain appears valid, False otherwise
    """
    # Check for valid TLD (at least 2 characters)
    if '.' not in domain:
        return False
    
    parts = domain.split('.')
    tld = parts[-1]
    
    # TLD should be at least 2 characters and contain only letters
    return len(tld) >= 2 and tld.isalpha()


def validate_luhn(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.
    
    Args:
        card_number: Credit card number (digits only)
        
    Returns:
        True if valid according to Luhn algorithm, False otherwise
    """
    # Remove any non-digit characters
    digits = re.sub(r'\D', '', card_number)
    
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    
    # Luhn algorithm
    total = 0
    is_second = False
    
    for i in range(len(digits) - 1, -1, -1):
        digit = int(digits[i])
        
        if is_second:
            digit *= 2
            if digit > 9:
                digit -= 9
        
        total += digit
        is_second = not is_second
    
    return total % 10 == 0


def is_valid_ssn(ssn: str) -> bool:
    """
    Validate US Social Security Number.
    
    Args:
        ssn: SSN in format XXX-XX-XXXX
        
    Returns:
        True if SSN format is valid, False otherwise
    """
    # Extract digits
    digits = re.sub(r'\D', '', ssn)
    
    if len(digits) != 9:
        return False
    
    # Check for invalid area numbers (first 3 digits)
    area = int(digits[:3])
    
    # Invalid area numbers: 000, 666, 900-999
    if area == 0 or area == 666 or area >= 900:
        return False
    
    # Check for all zeros in group or serial number
    group = digits[3:5]
    serial = digits[5:9]
    
    if group == "00" or serial == "0000":
        return False
    
    return True


def merge_overlapping_matches(matches: List) -> List:
    """
    Merge overlapping PII matches, keeping the one with higher confidence.
    
    Args:
        matches: List of PIIMatch objects
        
    Returns:
        List of non-overlapping PIIMatch objects
    """
    if not matches:
        return []
    
    # Sort by start position
    sorted_matches = sorted(matches, key=lambda m: m.start)
    
    result = []
    current = sorted_matches[0]
    
    for next_match in sorted_matches[1:]:
        if current.overlaps_with(next_match):
            # Keep the match with higher confidence, or longer match if equal confidence
            if next_match.confidence > current.confidence:
                current = next_match
            elif next_match.confidence == current.confidence and next_match.length() > current.length():
                current = next_match
            # Otherwise keep current
        else:
            result.append(current)
            current = next_match
    
    result.append(current)
    return result


def deduplicate_matches(matches: List) -> List:
    """
    Remove exact duplicate matches (same position and type).
    
    Args:
        matches: List of PIIMatch objects
        
    Returns:
        List of unique PIIMatch objects
    """
    seen = set()
    unique = []
    
    for match in matches:
        key = (match.start, match.end, match.pii_type)
        if key not in seen:
            seen.add(key)
            unique.append(match)
        else:
            # If duplicate, keep one with higher confidence
            existing_idx = next(i for i, m in enumerate(unique) 
                              if m.start == match.start and m.end == match.end and m.pii_type == match.pii_type)
            if match.confidence > unique[existing_idx].confidence:
                unique[existing_idx] = match
    
    return unique


def get_timestamp() -> str:
    """
    Get current timestamp in ISO format.
    
    Returns:
        ISO format timestamp string
    """
    return datetime.utcnow().isoformat() + "Z"


def is_whitelisted(value: str, whitelist: dict) -> bool:
    """
    Check if a value is in the whitelist.
    
    Args:
        value: Value to check
        whitelist: Whitelist configuration dictionary
        
    Returns:
        True if value should not be anonymized, False otherwise
    """
    # Check exact email matches
    if 'emails' in whitelist and value in whitelist['emails']:
        return True
    
    # Check domain matches for emails
    if 'domains' in whitelist and '@' in value:
        domain = value.split('@')[1]
        if domain in whitelist['domains']:
            return True
    
    # Check pattern matches
    if 'patterns' in whitelist:
        for pattern in whitelist['patterns']:
            if re.search(pattern, value):
                return True
    
    return False


def is_blacklisted(value: str, blacklist: List[str]) -> bool:
    """
    Check if a value is in the blacklist.
    
    Args:
        value: Value to check
        blacklist: List of blacklisted values
        
    Returns:
        True if value should always be anonymized, False otherwise
    """
    return value in blacklist


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: File size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"
