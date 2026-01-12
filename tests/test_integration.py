"""Integration tests for end-to-end processing."""

import os
import tempfile

import pytest

from src.processors.file_processor import FileProcessor


class TestFileProcessing:
    """Test file processing with Presidio."""

    def test_single_file_processing(self):
        """Test processing a single file."""
        # Create temporary input file
        # Note: Phone numbers like 555-123-4567 only score ~0.4 confidence
        # so we focus on email and person detection here
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Contact John Doe at john.doe@company.com")
            input_path = f.name

        try:
            # Create minimal config for Presidio
            config = {
                'detection': {
                    'language': 'en',
                    'confidence_threshold': 0.5,  # Lower threshold for better detection
                    'enabled_entities': ['EMAIL_ADDRESS', 'PERSON']
                },
                'anonymization': {
                    'strategy': 'redact',
                    'redact': {'token': '[REDACTED]', 'type_specific': True}
                },
                'processing': {
                    'create_audit_log': False,
                    'backup_original': False,
                    'encoding': 'utf-8'
                },
                'whitelist': {},
                'blacklist': []
            }

            # Process file
            processor = FileProcessor(config)

            # Create temporary output file
            output_path = input_path + '_anonymized.txt'

            result = processor.process_file(input_path, output_path)

            # Verify result
            assert result.success
            assert result.pii_found >= 2  # At least email and person
            assert os.path.exists(output_path)

            # Read output and verify anonymization
            with open(output_path) as f:
                output_text = f.read()

            assert "john.doe@company.com" not in output_text
            assert "John Doe" not in output_text
            assert "[EMAIL_ADDRESS_REDACTED]" in output_text or "[REDACTED]" in output_text

            # Cleanup
            os.unlink(output_path)

        finally:
            # Cleanup input file
            os.unlink(input_path)

    def test_masking_strategy(self):
        """Test masking strategy."""
        # Create temporary input file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Email: john@example.com")
            input_path = f.name

        try:
            config = {
                'detection': {
                    'language': 'en',
                    'confidence_threshold': 0.7,
                    'enabled_entities': ['EMAIL_ADDRESS']
                },
                'anonymization': {
                    'strategy': 'mask',
                    'mask': {
                        'mask_char': '*',
                        'email_visible_chars': 1
                    }
                },
                'processing': {
                    'create_audit_log': False,
                    'backup_original': False
                },
                'whitelist': {},
                'blacklist': []
            }

            processor = FileProcessor(config)
            output_path = input_path + '_masked.txt'

            result = processor.process_file(input_path, output_path)

            assert result.success

            with open(output_path) as f:
                output_text = f.read()

            # Should be masked: j***@example.com
            assert "john@example.com" not in output_text
            assert "j***@example.com" in output_text

            os.unlink(output_path)

        finally:
            os.unlink(input_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
