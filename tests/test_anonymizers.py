"""
Unit tests for anonymizers.

This module tests all anonymization strategies.
"""

import pytest

from src.anonymizers.hash_anonymizer import HashAnonymizer
from src.anonymizers.masker import Masker
from src.anonymizers.redactor import Redactor
from src.models import PIIMatch


class TestRedactor:
    """Test redaction anonymizer."""

    def test_generic_redaction(self):
        """Test generic redaction."""
        anonymizer = Redactor({'token': '[REDACTED]', 'type_specific': False})

        match = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        result = anonymizer.anonymize(match)
        assert result == "[REDACTED]"

    def test_type_specific_redaction(self):
        """Test type-specific redaction."""
        anonymizer = Redactor({'token': '[REDACTED]', 'type_specific': True})

        match = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        result = anonymizer.anonymize(match)
        assert result == "[EMAIL_REDACTED]"


class TestMasker:
    """Test masking anonymizer."""

    def test_email_masking(self):
        """Test email masking."""
        anonymizer = Masker({'mask_char': '*', 'email_visible_chars': 1})

        match = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        result = anonymizer.anonymize(match)
        assert result == "j***@example.com"

    def test_phone_masking(self):
        """Test phone number masking."""
        anonymizer = Masker({'mask_char': '*', 'phone_visible_chars': 3})

        match = PIIMatch(
            pii_type="PHONE",
            value="555-123-4567",
            start=0,
            end=12,
            confidence=0.90
        )

        result = anonymizer.anonymize(match)
        assert result == "555-***-****"

    def test_ssn_masking(self):
        """Test SSN masking."""
        anonymizer = Masker({'mask_char': '*', 'ssn_visible_chars': 4})

        match = PIIMatch(
            pii_type="SSN",
            value="123-45-6789",
            start=0,
            end=11,
            confidence=0.95
        )

        result = anonymizer.anonymize(match)
        assert result == "***-**-6789"

    def test_credit_card_masking(self):
        """Test credit card masking."""
        anonymizer = Masker({'mask_char': '*', 'credit_card_visible_chars': 4})

        match = PIIMatch(
            pii_type="CREDIT_CARD",
            value="4532-1488-0343-6467",
            start=0,
            end=19,
            confidence=0.95
        )

        result = anonymizer.anonymize(match)
        assert result == "****-****-****-6467"


class TestHashAnonymizer:
    """Test hash anonymizer."""

    def test_hash_consistency(self):
        """Test that same input produces same hash."""
        anonymizer = HashAnonymizer({
            'algorithm': 'sha256',
            'salt': 'test_salt',
            'prefix': True,
            'truncate': 8
        })

        match1 = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        match2 = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=20,
            end=37,
            confidence=0.95
        )

        result1 = anonymizer.anonymize(match1)
        result2 = anonymizer.anonymize(match2)

        assert result1 == result2
        assert result1.startswith("EMAIL_")

    def test_different_values_different_hashes(self):
        """Test that different inputs produce different hashes."""
        anonymizer = HashAnonymizer({
            'algorithm': 'sha256',
            'salt': 'test_salt',
            'prefix': False,
            'truncate': 8
        })

        match1 = PIIMatch(
            pii_type="EMAIL",
            value="john@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        match2 = PIIMatch(
            pii_type="EMAIL",
            value="jane@example.com",
            start=0,
            end=17,
            confidence=0.95
        )

        result1 = anonymizer.anonymize(match1)
        result2 = anonymizer.anonymize(match2)

        assert result1 != result2


class TestBatchAnonymization:
    """Test batch anonymization."""

    def test_batch_anonymization(self):
        """Test anonymizing multiple matches in text."""
        anonymizer = Redactor({'token': '[REDACTED]', 'type_specific': False})

        text = "Email john@test.com and phone 555-1234"

        matches = [
            PIIMatch(
                pii_type="EMAIL",
                value="john@test.com",
                start=6,
                end=20,
                confidence=0.95
            ),
            PIIMatch(
                pii_type="PHONE",
                value="555-1234",
                start=31,
                end=39,
                confidence=0.90
            )
        ]

        result = anonymizer.anonymize_batch(matches, text)

        assert "john@test.com" not in result
        assert "555-1234" not in result
        assert "[REDACTED]" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
