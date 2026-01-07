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
from src.config.config_manager import ConfigManager


# Load false positive words from config at module level
_config = ConfigManager.load()
_fp_words_list = _config.config_data.get('false_positive_words', [])
FALSE_POSITIVE_WORDS: frozenset[str] = frozenset(w.lower() for w in _fp_words_list)


def normalize_caps_for_ner(text: str) -> str:
    """
    Convert ALL CAPS names with titles to Title Case for better NER detection.

    Only normalizes when a title prefix (MR, MS, DR, etc.) is present to avoid
    false positives on technical terms like "UPLOAD SPEED" or "DOWNLOAD SPEED".

    Examples:
        "Contacted MR BERNARD FANNING about" -> "Contacted Mr Bernard Fanning about"
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


def analyze_text_for_pii(
    analyzer: "AnalyzerEngine",
    text: str,
    language: str = 'en',
) -> list[PIIMatch]:
    """
    Analyze text for PII using Presidio analyzer with normalization and false positive filtering.

    This is the shared detection function used by both file and CSV processors.
    False positive words are loaded from config at module import time.

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

        # Skip known false positives for PERSON/ORG/LOCATION entities
        if result.entity_type in ('PERSON', 'ORGANIZATION', 'LOCATION'):
            matched_words = matched_lower.split()
            # For PERSON: only skip if the FIRST word is a false positive
            # This allows "felicity cac" (name + abbreviation) to pass through
            # For ORG/LOCATION: skip if ANY word is a false positive
            if result.entity_type == 'PERSON':
                if matched_words and matched_words[0] in FALSE_POSITIVE_WORDS:
                    continue
            else:
                if any(word in FALSE_POSITIVE_WORDS for word in matched_words):
                    continue

        # Reclassify ORGANIZATION/LOCATION as PERSON when it looks like a name
        # spaCy often misclassifies names in business context (e.g., "Bernard" as ORG)
        if result.entity_type in ('ORGANIZATION', 'LOCATION'):
            # Check if preceded by a title - definitely a PERSON
            prefix_start = max(0, result.start - 10)
            prefix_text = text[prefix_start:result.start].lower().split()
            preceded_by_title = prefix_text and prefix_text[-1].rstrip('.') in TITLE_PREFIXES

            # Single capitalized word that looks like a name (not all caps tech term)
            is_single_name = (
                len(matched_words) == 1 and
                matched_value[0].isupper() and
                not matched_value.isupper() and  # Not ALL CAPS (likely acronym)
                len(matched_value) > 2  # Not short abbreviation
            )

            if preceded_by_title or is_single_name:
                # Reclassify as PERSON
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
