"""
File processor for orchestrating PII detection and anonymization.

This module coordinates the detection and anonymization pipeline for processing files.
"""

import os
import time
import json
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.models import ProcessResult, PIIMatch, AuditLogEntry
from src.anonymizers.base_anonymizer import BaseAnonymizer
from src.anonymizers.redactor import Redactor
from src.anonymizers.masker import Masker
from src.anonymizers.faker_anonymizer import FakerAnonymizer
from src.anonymizers.hash_anonymizer import HashAnonymizer
from src.utils import (
    merge_overlapping_matches, deduplicate_matches, 
    is_whitelisted, is_blacklisted, get_timestamp
)
from presidio_analyzer import RecognizerResult, Pattern
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_analyzer.pattern_recognizer import PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

class FileProcessor:
    """
    Processor for detecting and anonymizing PII in files.
    
    This class orchestrates the entire pipeline:
    1. Read input file
    2. Run all configured detectors
    3. Merge and deduplicate matches
    4. Apply anonymization
    5. Write output file
    6. Generate audit log (optional)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize file processor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.detection_config = config.get('detection', {})
        self.anonymization_config = config.get('anonymization', {})
        self.processing_config = config.get('processing', {})
        
        # Initialize Presidio analyzer
        self.analyzer = self._init_presidio()
        
        # Initialize anonymizer
        self.anonymizer = self._init_anonymizer()
        
        # Processing options
        self.create_audit_log = self.processing_config.get('create_audit_log', True)
        self.backup_original = self.processing_config.get('backup_original', False)
        self.encoding = self.processing_config.get('encoding', 'utf-8')
        self.output_suffix = self.processing_config.get('output_suffix', '_anonymized')
    
    def _init_presidio(self):
        """
        Initialize Presidio AnalyzerEngine.
        
        Returns:
            AnalyzerEngine instance or None
        """
        try:
            import logging
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
            from presidio_analyzer.recognizer_registry import RecognizerRegistry
            from presidio_analyzer.pattern_recognizer import PatternRecognizer

            language = self.detection_config.get('language', 'en')
            
            # Configure NLP engine
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": "en_core_web_sm"}],
            }
        
            provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
            nlp_engine = provider.create_engine()
            nlp_engine.nlp["en"].max_length = 20000000
            
            registry = RecognizerRegistry()
        
            # Add default recognizers
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)
            
            # Add custom recognizers
            # member_number_recognizer = self._create_member_number_recognizer()
            enhanced_address_recognizer = self._create_enhanced_address_recognizer()
            generic_number_recognizer = self._create_generic_number_recognizer()
            au_phone_recognizer = self._create_australian_phone_recognizer()
            dob_recognizer = self._dob_recognizer()
            
            # registry.add_recognizer(member_number_recognizer)
            registry.add_recognizer(enhanced_address_recognizer)
            registry.add_recognizer(generic_number_recognizer)
            registry.add_recognizer(au_phone_recognizer)
            registry.add_recognizer(dob_recognizer)

            # Create analyzer with custom registry
            analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry
            )
            
            print(f"✓ Presidio initialized (language: {language})")
            return analyzer
            
        except ImportError:
            print("✗ Error: presidio-analyzer not installed")
            print("  Install with: pip install presidio-analyzer")
            return None
        except Exception as e:
            print(f"✗ Error initializing Presidio: {e}")
            return None
    
    
    def _create_australian_phone_recognizer(self) -> PatternRecognizer:
            """Create custom recognizer for Australian phone numbers."""
            # Australian phone number patterns
            australian_phone_patterns = [
                Pattern(
                    name="au_landline",
                    regex=r'\b0[2-9]\s?\d{4}\s?\d{4}\b',       # 0X XXXX XXXX (landline)
                    score=0.85
                ),
                Pattern(
                    name="au_mobile_standard",
                    regex=r'\b04\d{2}\s?\d{3}\s?\d{3}\b',      # 04XX XXX XXX (mobile)
                    score=0.9
                ),
                Pattern(
                    name="au_mobile_compact",
                    regex=r'\b04\d{8}\b',                      # 04XXXXXXXX (mobile)
                    score=0.9
                ),
                Pattern(
                    name="au_international",
                    regex=r'\b\+61\s?[2-9]\s?\d{4}\s?\d{4}\b', # +61 X XXXX XXXX (international)
                    score=0.95
                ),
                Pattern(
                    name="au_synthetic",
                    regex=r'\b04\d{4}\s?\d{3}\s?\d{3}\b',      # 04XXXX XXX XXX (synthetic data)
                    score=0.7
                )
            ]
            
            return PatternRecognizer(
                supported_entity="AU_PHONE_NUMBER",
                patterns=australian_phone_patterns,
                name="australian_phone_recognizer",
                context=["phone", "mobile", "cell", "number", "call"]
            )
        
    def _create_generic_number_recognizer(self) -> PatternRecognizer:
        """Create custom recognizer for any sequence of digits."""
        number_patterns = [
            Pattern(
                name="eight_digit_sequence",
                regex=r"\b\d{8}\b",  # Specifically target 8-digit sequences
                score=1.0 
            ),
            Pattern(
                name="any_digit_sequence",
                regex=r"\b\d{1,16}\b",  # Aggresively masking 1-16 digit sequences 
                score=0.9  
            ),
            Pattern(
                name="formatted_numbers",
                regex=r"\b\d{1,3}(,\d{3})+\b",  # Matches numbers with commas like 1,000,000
                score=0.65
            ),
            Pattern(
                name="decimal_numbers",
                regex=r"\b\d+\.\d+\b",  # Matches decimal numbers like 123.45
                score=0.65
            )
        ]
        
        return PatternRecognizer(
            supported_entity="GENERIC_NUMBER",
            patterns=number_patterns,
            name="generic_number_recognizer",
            context=["number", "digit", "id", "member", "account"]  
        )
    
    def _dob_recognizer(self) -> PatternRecognizer:
        """Create custom recognizer for Date of Birth in DD/MM/YYYY format."""
        dob_patterns = [
            Pattern(
                name="dob_ddmmyyyy",
                regex=r'\b(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[0-2])\/(19|20)\d{2}\b',  # DD/MM/YYYY
                score=0.65
            ),
            Pattern(
                name="dob_mmddyyyy",
                regex=r'\b((0[1-9]|1[0-2])\/(0[1-9]|[12][0-9]|3[01]))\/(19|20)\d{2}\b',  # MM/DD/YYYY
                score=0.65
            )
        ]
        
        return PatternRecognizer(
            supported_entity="DATE_OF_BIRTH",
            patterns=dob_patterns,
            name="dob_recognizer",
            context=["date of birth", "dob", "birthdate", "born"],
        )
    
    def _create_enhanced_address_recognizer(self) -> PatternRecognizer:
        """Create enhanced address recognizer for Australian addresses."""
        # Australian address patterns
        australian_address_patterns = [
            Pattern(
                name="australian_street_address",
                regex=r"\b\d{1,3}\s+(?:[A-Za-z]+\s+){1,5}(Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Circuit|Cct|Court|Ct|Place|Pl|Way|Crescent|Cres)\b,?\s*(?:[A-Za-z]+\s+){1,3}(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)\s+\d{4}\b",
                score=0.95
            ),
            Pattern(
                name="australian_street_simple",
                regex=r"\b\d{1,3}\s+(?:[A-Za-z]+\s+){1,5}(Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Circuit|Cct|Court|Ct|Place|Pl|Way|Crescent|Cres)\b",
                score=0.7
            )
        ]
        
        return PatternRecognizer(
            supported_entity="AU_ADDRESS",
            patterns=australian_address_patterns,
            name="australian_address_recognizer"
        )
        
    def _init_anonymizer(self) -> BaseAnonymizer:
        """
        Initialize anonymizer based on configured strategy.
        
        Returns:
            Anonymizer instance
        """
        strategy = self.anonymization_config.get('strategy', 'redact')
        strategy_config = self.anonymization_config.get(strategy, {})
        
        anonymizer_map = {
            'redact': Redactor,
            'mask': Masker,
            'replace': FakerAnonymizer,
            'hash': HashAnonymizer,
        }
        
        if strategy not in anonymizer_map:
            print(f"Warning: Unknown strategy '{strategy}', defaulting to 'redact'")
            strategy = 'redact'
        
        anonymizer_class = anonymizer_map[strategy]
        return anonymizer_class(strategy_config)
    
    def process_file(self, input_path: str, output_path: Optional[str] = None) -> ProcessResult:
        """
        Process a single file for PII detection and anonymization.
        
        Args:
            input_path: Path to input file
            output_path: Path to output file (auto-generated if None)
            
        Returns:
            ProcessResult object with processing details
        """
        start_time = time.time()
        result = ProcessResult(success=False, input_path=input_path)
        
        try:
            # Validate input file
            if not os.path.exists(input_path):
                result.add_error(f"Input file not found: {input_path}")
                return result
            
            if not os.path.isfile(input_path):
                result.add_error(f"Input path is not a file: {input_path}")
                return result
            
            # Generate output path if not provided
            if output_path is None:
                output_path = self._generate_output_path(input_path)
            
            result.output_path = output_path
            
            # Backup original if configured
            if self.backup_original:
                self._backup_file(input_path)
            
            # Read input file
            print(f"Reading file: {input_path}")
            text = self._read_file(input_path)
            
            # Detect PII
            print("Detecting PII...")
            matches = self._detect_all_pii(text)
            result.pii_found = len(matches)
            result.matches = matches
            
            print(f"Found {len(matches)} PII instances")
            
            # Apply whitelist/blacklist filtering
            matches = self._apply_filters(matches)
            
            # Anonymize text
            print("Anonymizing PII...")
            anonymized_text = self.anonymizer.anonymize_batch(matches, text)
            result.pii_anonymized = len(matches)
            
            # Write output file
            print(f"Writing output: {output_path}")
            self._write_file(output_path, anonymized_text)
            
            # Generate audit log if configured
            if self.create_audit_log:
                audit_path = self._generate_audit_path(output_path)
                self._write_audit_log(audit_path, matches)
                print(f"Audit log written: {audit_path}")
            
            result.success = True
            print("Processing completed successfully")
            
        except Exception as e:
            result.add_error(f"Error processing file: {str(e)}")
            print(f"Error: {e}")
        
        finally:
            result.processing_time = time.time() - start_time
        
        return result
    
    def process_directory(
        self, 
        input_dir: str, 
        output_dir: Optional[str] = None,
        recursive: bool = False
    ) -> List[ProcessResult]:
        """
        Process all files in a directory.
        
        Args:
            input_dir: Path to input directory
            output_dir: Path to output directory (auto-generated if None)
            recursive: Whether to process subdirectories recursively
            
        Returns:
            List of ProcessResult objects, one per file
        """
        if output_dir is None:
            output_dir = input_dir + "_anonymized"
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        results = []
        
        # Get list of files
        if recursive:
            files = list(Path(input_dir).rglob('*.txt'))
        else:
            files = list(Path(input_dir).glob('*.txt'))
        
        print(f"Found {len(files)} files to process")
        
        for file_path in files:
            # Calculate relative path for output
            rel_path = file_path.relative_to(input_dir)
            output_path = os.path.join(output_dir, str(rel_path))
            
            # Create subdirectories if needed
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Process file
            result = self.process_file(str(file_path), output_path)
            results.append(result)
        
        # Print summary
        successful = sum(1 for r in results if r.success)
        print(f"\nProcessing complete: {successful}/{len(results)} files successful")
        
        return results
    
    def _detect_all_pii(self, text: str) -> List[PIIMatch]:
        """
        Detect PII using Presidio.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of PIIMatch objects
        """
        if not self.analyzer:
            print("  Warning: Presidio not initialized")
            return []
        
        try:
            # Get configuration
            language = self.detection_config.get('language', 'en')
            threshold = self.detection_config.get('confidence_threshold', 0.7)
            entities = self.detection_config.get('enabled_entities', None)
            
            # Analyze with Presidio
            results = self.analyzer.analyze(
                text=text,
                language=language,
                entities=entities,
                score_threshold=threshold
            )
            
            # Convert to PIIMatch objects
            matches = []
            for result in results:
                match = PIIMatch(
                    pii_type=result.entity_type,
                    value=text[result.start:result.end],
                    start=result.start,
                    end=result.end,
                    confidence=result.score,
                    context=self._get_context(text, result.start, result.end),
                    detector_name="Presidio"
                )
                matches.append(match)
            
            print(f"  Presidio: found {len(matches)} PII instances")
            return matches
            
        except Exception as e:
            print(f"  Error during Presidio analysis: {e}")
            return []
    
    def _get_context(self, text: str, start: int, end: int, context_chars: int = 20) -> str:
        """
        Extract context around a matched PII.
        
        Args:
            text: Full text
            start: Start position
            end: End position
            context_chars: Characters to include before/after
            
        Returns:
            Context string
        """
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        before = text[context_start:start]
        match = text[start:end]
        after = text[end:context_end]
        return f"...{before}[{match}]{after}..."
    
    def _apply_filters(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """
        Apply whitelist and blacklist filters.
        
        Args:
            matches: List of PIIMatch objects
            
        Returns:
            Filtered list of matches
        """
        whitelist = self.config.get('whitelist', {})
        blacklist = self.config.get('blacklist', [])
        
        filtered = []
        
        for match in matches:
            # Check blacklist (always anonymize)
            if is_blacklisted(match.value, blacklist):
                filtered.append(match)
                continue
            
            # Check whitelist (never anonymize)
            if is_whitelisted(match.value, whitelist):
                continue
            
            filtered.append(match)
        
        return filtered
    
    def _read_file(self, path: str) -> str:
        """
        Read file content.
        
        Args:
            path: File path
            
        Returns:
            File content as string
        """
        with open(path, 'r', encoding=self.encoding) as f:
            return f.read()
    
    def _write_file(self, path: str, content: str) -> None:
        """
        Write content to file.
        
        Args:
            path: File path
            content: Content to write
        """
        # Create directory if it doesn't exist
        directory = os.path.dirname(path)
        if directory:  # Only create if directory path is not empty
            os.makedirs(directory, exist_ok=True)
        
        with open(path, 'w', encoding=self.encoding) as f:
            f.write(content)
    
    def _generate_output_path(self, input_path: str) -> str:
        """
        Generate output path from input path.
        
        Args:
            input_path: Input file path
            
        Returns:
            Output file path
        """
        path = Path(input_path)
        return str(path.parent / f"{path.stem}{self.output_suffix}{path.suffix}")
    
    def _generate_audit_path(self, output_path: str) -> str:
        """
        Generate audit log path from output path.
        
        Args:
            output_path: Output file path
            
        Returns:
            Audit log file path
        """
        path = Path(output_path)
        return str(path.parent / f"{path.stem}_audit.json")
    
    def _backup_file(self, path: str) -> None:
        """
        Create backup of file.
        
        Args:
            path: File path to backup
        """
        import shutil
        backup_path = f"{path}.backup"
        shutil.copy2(path, backup_path)
        print(f"Backup created: {backup_path}")
    
    def _write_audit_log(self, path: str, matches: List[PIIMatch]) -> None:
        """
        Write audit log with anonymization details.
        
        Args:
            path: Audit log file path
            matches: List of PIIMatch objects
        """
        timestamp = get_timestamp()
        
        entries = []
        for match in matches:
            entry = AuditLogEntry(
                pii_type=match.pii_type,
                position=match.start,
                anonymization_strategy=self.anonymizer.get_strategy_name(),
                timestamp=timestamp
            )
            entries.append(entry.to_dict())
        
        audit_data = {
            "timestamp": timestamp,
            "strategy": self.anonymizer.get_strategy_name(),
            "total_anonymized": len(matches),
            "entries": entries
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(audit_data, f, indent=2)
