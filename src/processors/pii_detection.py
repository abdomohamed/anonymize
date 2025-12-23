"""
Shared PII detection utilities for processors.

This module contains the core detection logic shared between
file_processor and csv_processor.
"""

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine

from src.models import PIIMatch
from src.utils import get_context


# Words that spaCy NER incorrectly identifies as PERSON/ORGANIZATION
# Used to filter false positives during PII detection
FALSE_POSITIVE_WORDS = frozenset({
    # Technical terms misidentified as PERSON
    'upload', 'download', 'sync', 'backup', 'update', 'install',
    'login', 'logout', 'signup', 'signin', 'reset', 'refresh',
    # Business terms misidentified as ORG
    'credit', 'debit', 'account', 'balance', 'payment', 'invoice',
    'service', 'support', 'sales', 'billing', 'admin', 'system',
    'customer', 'client', 'user', 'member',
    # Speed/network terms
    'speed', 'ping', 'latency', 'bandwidth', 'upstream', 'downstream',
    'mbps', 'kbps', 'gbps',
    # Telco/system-specific terms
    'telstra', 'console', 'mica', 'bill', 'siebel', 'flexcab',
    'debitors', 'pega', 'braintree', 'salesforce',
    # Australian state abbreviations (misidentified as ORG)
    'nsw', 'vic', 'qld', 'wa', 'sa', 'tas', 'act', 'nt',
    # Australian timezone abbreviations
    'aest', 'aedt', 'acst', 'acdt', 'awst', 'awdt',
    # Common words misidentified as ORG
    'medicare', 'centrelink', 'driver', 'license', 'licence',
    # Regulatory bodies
    'tio', 'acma',
    # Payment/billing terms
    'bpay', 'paypal',
    # Status/workflow words
    'escalated', 'provisioning', 'activated', 'cancelled', 'canceled',
    'retention', 'winback', 'churn',
    # Other common abbreviations
    'dob', 'eta', 'asap', 'tba', 'tbd', 'fyi', 'pm', 'am',
})


def normalize_caps_for_ner(text: str) -> str:
    """
    Convert ALL CAPS names with titles to Title Case for better NER detection.

    Only normalizes when a title prefix (MR, MS, DR, etc.) is present to avoid
    false positives on technical terms like "UPLOAD SPEED" or "DOWNLOAD SPEED".

    Examples:
        "Contacted MR BERNARD HYNES about" -> "Contacted Mr Bernard Hynes about"
        "Customer MS JANE O'BRIEN called" -> "Customer Ms Jane O'Brien called"
        "DR SMITH-JONES arrived" -> "Dr Smith-Jones arrived"
        "UPLOAD SPEED 24.95" -> unchanged (no title prefix)

    Since character count is preserved, entity positions map back exactly.
    """
    def title_case_match(match):
        return match.group(0).title()

    # Only match title + 1-3 ALL CAPS name words
    # Requires: MR/MS/DR/etc prefix to avoid false positives on technical terms
    # Each name word: 2+ letters OR apostrophe pattern (O'BRIEN) OR hyphenated (SMITH-JONES)
    # Name component: capitals with optional apostrophe/hyphen followed by more capitals
    name_part = r"(?:[A-Z]+'[A-Z]+|[A-Z]{2,}(?:-[A-Z]+)*)"
    pattern = rf"\b(?:MR|MRS|MS|MISS|DR|PROF|REV|SIR|DAME|LORD|LADY)\s+{name_part}(?:\s+{name_part}){{0,2}}\b"

    return re.sub(pattern, title_case_match, text)


def analyze_text_for_pii(analyzer: "AnalyzerEngine", text: str, language: str = 'en') -> list[PIIMatch]:
    """
    Analyze text for PII using Presidio analyzer with normalization and false positive filtering.

    This is the shared detection function used by both file and CSV processors.

    Args:
        analyzer: Presidio AnalyzerEngine instance
        text: Text to analyze
        language: Language code (default: 'en')

    Returns:
        List of PIIMatch objects
    """
    # Normalize ALL CAPS sequences for better NER detection
    # "MR BERNARD HYNES" -> "Mr Bernard Hynes" (same length, positions map 1:1)
    normalized_text = normalize_caps_for_ner(text)

    # Analyze with Presidio on normalized text
    # Use score_threshold to filter out low-confidence matches (e.g., bare dates without context)
    results = analyzer.analyze(
        text=normalized_text,
        language=language,
        score_threshold=0.5
    )

    if not results:
        return []

    # Entity types to skip (spaCy NER detects these but they're too noisy)
    # DATE_TIME catches all dates - we only want DOB with context
    SKIP_ENTITIES = {'DATE_TIME', 'CARDINAL', 'ORDINAL', 'QUANTITY', 'MONEY'}

    # Titles that indicate a following word is likely a person name
    TITLE_PREFIXES = {'mr', 'mrs', 'ms', 'miss', 'dr', 'prof', 'rev', 'sir', 'dame', 'lord', 'lady'}

    # Convert to PIIMatch objects, filtering out known false positives
    matches = []
    for result in results:
        # Skip noisy entity types from spaCy NER
        if result.entity_type in SKIP_ENTITIES:
            continue

        matched_value = text[result.start:result.end]
        matched_lower = matched_value.lower()

        # Skip known false positives for PERSON/ORG entities
        if result.entity_type in ('PERSON', 'ORGANIZATION'):
            matched_words = matched_lower.split()
            if any(word in FALSE_POSITIVE_WORDS for word in matched_words):
                continue

            # Fix spaCy misclassification: ORG that follows a title is likely PERSON
            # e.g., "DR SMITH-JONES" where spaCy only detects "SMITH-JONES" as ORG
            if result.entity_type == 'ORGANIZATION':
                # Check if preceded by a title
                prefix_start = max(0, result.start - 10)
                prefix_text = text[prefix_start:result.start].lower().split()
                if prefix_text and prefix_text[-1].rstrip('.') in TITLE_PREFIXES:
                    # Reclassify as PERSON
                    result = result._replace(entity_type='PERSON') if hasattr(result, '_replace') else result
                    # For RecognizerResult, we need to create a new match with PERSON type
                    matches.append(PIIMatch(
                        pii_type='PERSON',
                        value=matched_value,
                        start=result.start,
                        end=result.end,
                        confidence=result.score,
                        context=get_context(text, result.start, result.end),
                        detector_name="Presidio"
                    ))
                    continue

        matches.append(PIIMatch(
            pii_type=result.entity_type,
            value=matched_value,
            start=result.start,
            end=result.end,
            confidence=result.score,
            context=get_context(text, result.start, result.end),
            detector_name="Presidio"
        ))

    return matches
