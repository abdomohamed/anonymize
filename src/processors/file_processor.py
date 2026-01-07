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
from src.processors.pii_detection import analyze_text_for_pii
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

    def __init__(self, config: Dict[str, Any], silent: bool = False):
        """
        Initialize file processor.

        Args:
            config: Configuration dictionary
            silent: If True, suppress initialization messages (for workers)
        """
        self.config = config
        self.silent = silent
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
            # Import Australian recognizers (not loaded by default)
            from presidio_analyzer.predefined_recognizers import (
                AuMedicareRecognizer, AuTfnRecognizer, AuAbnRecognizer, AuAcnRecognizer
            )

            language = self.detection_config.get('language', 'en')

            # Configure NLP engine
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": "en_core_web_lg"}],
            }

            provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
            nlp_engine = provider.create_engine()
            nlp_engine.nlp["en"].max_length = 20000000

            registry = RecognizerRegistry()

            # Add default recognizers
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            # Remove Presidio's DateRecognizer - we only want DOB matches with explicit context
            # DateRecognizer catches ALL dates which creates noise (meeting dates, timestamps, etc.)
            registry.remove_recognizer("DateRecognizer")

            # Add Australian recognizers (not loaded by load_predefined_recognizers)
            # These provide checksum validation for AU_TFN, AU_MEDICARE, AU_ABN, AU_ACN
            registry.add_recognizer(AuMedicareRecognizer())
            registry.add_recognizer(AuTfnRecognizer())
            registry.add_recognizer(AuAbnRecognizer())
            registry.add_recognizer(AuAcnRecognizer())

            # Custom recognizers for entities NOT in Presidio
            enhanced_address_recognizer = self._create_enhanced_address_recognizer()
            # generic_number_recognizer = self._create_generic_number_recognizer()
            au_phone_recognizer = self._create_australian_phone_recognizer()
            dob_recognizer = self._dob_recognizer()

            # NBN/Telecom IDs (unique to AU telecom)
            nbn_loc_recognizer = self._create_nbn_location_recognizer()
            nbn_service_recognizer = self._create_nbn_service_recognizer()
            special_phone_recognizer = self._create_special_phone_recognizer()

            # Address patterns
            po_box_recognizer = self._create_po_box_recognizer()

            # Device Identifiers
            imei_recognizer = self._create_imei_recognizer()
            iccid_recognizer = self._create_iccid_recognizer()
            ntd_serial_recognizer = self._create_ntd_serial_recognizer()

            # Australian Identity Documents
            driver_license_recognizer = self._create_driver_license_recognizer()
            passport_recognizer = self._create_passport_recognizer()
            centrelink_recognizer = self._create_centrelink_recognizer()
            # Register custom recognizers (supplements Presidio defaults)
            registry.add_recognizer(enhanced_address_recognizer)
            registry.add_recognizer(au_phone_recognizer)
            registry.add_recognizer(dob_recognizer)
            registry.add_recognizer(nbn_loc_recognizer)
            registry.add_recognizer(nbn_service_recognizer)
            registry.add_recognizer(special_phone_recognizer)
            registry.add_recognizer(po_box_recognizer)
            registry.add_recognizer(imei_recognizer)
            registry.add_recognizer(iccid_recognizer)
            registry.add_recognizer(ntd_serial_recognizer)
            registry.add_recognizer(driver_license_recognizer)
            registry.add_recognizer(passport_recognizer)
            registry.add_recognizer(centrelink_recognizer)


            # Create analyzer with custom registry
            analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry
            )

            if not self.silent:
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
        australian_phone_patterns = [
            # Landline: flexible separators (spaces, dashes, or none)
            Pattern(
                name="au_landline",
                regex=r'\b\(?0[2-9]\)?[-\s]?\d{4}[-\s]?\d{4}\b',
                score=0.85
            ),
            # Mobile: 04XX format with flexible separators
            Pattern(
                name="au_mobile",
                regex=r'\b04\d{2}[-\s.]?\d{3}[-\s.]?\d{3}\b',
                score=0.9
            ),
            # International: +61 or 61 prefix
            Pattern(
                name="au_international",
                regex=r'\b\+?61[-\s]?\(?0?\)?[-\s]?[2-9][-\s]?\d{4}[-\s]?\d{4}\b',
                score=0.95
            ),
            Pattern(
                name="au_international_mobile",
                regex=r'\b\+?61[-\s]?4\d{2}[-\s]?\d{3}[-\s]?\d{3}\b',
                score=0.95
            ),
            # Partial mobile (common in CRM - missing digits)
            Pattern(
                name="au_mobile_partial",
                regex=r'\b04\d{2}[-\s]?\d{2,3}[-\s]?\d{2,3}\b',
                score=0.6
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_PHONE_NUMBER",
            patterns=australian_phone_patterns,
            name="australian_phone_recognizer",
            context=["phone", "mobile", "cell", "number", "call", "contact", "tel", "ph"]
        )

    def _create_generic_number_recognizer(self) -> PatternRecognizer:
        """Create custom recognizer for any sequence of digits.

        NOTE: Scores are kept LOW to act as a fallback when no other
        recognizer matches. More specific recognizers (AU_ADDRESS,
        AU_DRIVER_LICENSE, etc.) should have higher confidence scores.
        """
        number_patterns = [
            # General digit sequence fallback (4-16 digits)
            # NOTE: 8-digit is handled by driver license recognizer
            Pattern(
                name="any_digit_sequence",
                regex=r"\b\d{4,16}\b",
                score=0.4
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
        """Create custom recognizer for Date of Birth with REQUIRED context.

        Only matches dates when DOB-related keywords are nearby.
        This prevents matching meeting dates, timestamps, etc.
        """
        dob_patterns = [
            # High confidence: explicit DOB context prefix
            Pattern(
                name="dob_with_prefix",
                regex=r'(?i)(?:dob|d\.o\.b\.?|date\s*of\s*birth|birth\s*date|born)[:\s]+(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
                score=0.95
            ),
            Pattern(
                name="dob_written_with_prefix",
                regex=r'(?i)(?:dob|d\.o\.b\.?|date\s*of\s*birth|birth\s*date|born)[:\s]+(\d{1,2})(?:st|nd|rd|th)?\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{2,4}',
                score=0.95
            ),
            # Low confidence bare dates - REQUIRE context keywords to boost above threshold
            # These won't match on their own (score 0.3 < threshold 0.7)
            Pattern(
                name="dob_ddmmyyyy_slash",
                regex=r'\b(0?[1-9]|[12][0-9]|3[01])\/(0?[1-9]|1[0-2])\/(19|20)\d{2}\b',
                score=0.3
            ),
            Pattern(
                name="dob_ddmmyyyy_dash",
                regex=r'\b(0?[1-9]|[12][0-9]|3[01])-(0?[1-9]|1[0-2])-(19|20)\d{2}\b',
                score=0.3
            ),
            Pattern(
                name="dob_iso_format",
                regex=r'\b(19|20)\d{2}-(0?[1-9]|1[0-2])-(0?[1-9]|[12][0-9]|3[01])\b',
                score=0.3
            ),
            Pattern(
                name="dob_written_long",
                regex=r'(?i)\b(\d{1,2})(?:st|nd|rd|th)?\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(19|20)\d{2}\b',
                score=0.3
            ),
        ]

        return PatternRecognizer(
            supported_entity="DATE_OF_BIRTH",
            patterns=dob_patterns,
            name="dob_recognizer",
            context=["date of birth", "dob", "d.o.b", "birthdate", "born", "birthday", "age"]
        )

    def _create_enhanced_address_recognizer(self) -> PatternRecognizer:
        """Create enhanced address recognizer for Australian addresses."""
        # Australian address patterns
        australian_address_patterns = [
            # Full address with state and postcode
            Pattern(
                name="australian_street_address",
                regex=r"\b\d{1,3}\s+(?:[A-Za-z]+\s+){1,5}(Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Circuit|Cct|Court|Ct|Place|Pl|Way|Crescent|Cres)\b,?\s*(?:[A-Za-z]+\s+){1,3}(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)\s+\d{4}\b",
                score=0.95
            ),
            # Street address with suburb (no state/postcode)
            Pattern(
                name="australian_street_with_suburb",
                regex=r"\b\d{1,3}\s+(?:[A-Za-z]+\s+){1,5}(Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Circuit|Cct|Court|Ct|Place|Pl|Way|Crescent|Cres)\b,?\s+[A-Za-z]+(?:\s+[A-Za-z]+){0,2}\b",
                score=0.8
            ),
            # Simple street address only
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

    # =========================================================================
    # NBN/Telecom IDs (unique to AU telecom - not in Presidio)
    # NOTE: AU_TFN, AU_MEDICARE, AU_ABN, AU_ACN are provided by Presidio
    #       with checksum validation - see AuTfnRecognizer, AuMedicareRecognizer,
    #       AuAbnRecognizer, AuAcnRecognizer
    # =========================================================================

    def _create_nbn_location_recognizer(self) -> PatternRecognizer:
        """Create recognizer for NBN Location IDs (LOC ID)."""
        nbn_loc_patterns = [
            # LOC prefix pattern (covers both alphanumeric and numeric)
            Pattern(
                name="nbn_loc_id_standard",
                regex=r"(?i)\bLOC[-\s]?([A-Z0-9]{10,12})\b",
                score=0.9
            ),
            # Context-enhanced (higher confidence)
            Pattern(
                name="nbn_loc_id_with_context",
                regex=r"(?i)(?:location\s*id|loc\s*id|nbn\s*location)[:\s#]*(LOC)?[-\s]?([A-Z0-9]{10,12})",
                score=0.95
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_NBN_LOC_ID",
            patterns=nbn_loc_patterns,
            name="nbn_location_id_recognizer",
            context=["location id", "loc id", "nbn location", "premises", "nbn address", "service address"]
        )

    def _create_nbn_service_recognizer(self) -> PatternRecognizer:
        """Create recognizer for NBN Service IDs (AVC/CVC)."""
        nbn_service_patterns = [
            Pattern(
                name="nbn_avc_id",
                regex=r"(?i)\bAVC[-\s]?([A-Z0-9]{10,12})\b",
                score=0.9
            ),
            Pattern(
                name="nbn_cvc_id",
                regex=r"(?i)\bCVC[-\s]?([A-Z0-9]{6,12})\b",
                score=0.9
            ),
            Pattern(
                name="nbn_poi_id",
                regex=r"(?i)\bPOI[-:\s]?([A-Z0-9]{3,15})\b",
                score=0.8
            ),
            Pattern(
                name="nbn_service_class",
                regex=r"(?i)\b(?:Service\s*Class|SC)[-\s]?([0-9]{1,2})\b",
                score=0.7
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_NBN_SERVICE_ID",
            patterns=nbn_service_patterns,
            name="nbn_service_id_recognizer",
            context=["avc", "cvc", "virtual circuit", "nbn service", "access circuit", "poi", "service class"]
        )

    def _create_special_phone_recognizer(self) -> PatternRecognizer:
        """Create recognizer for 1300/1800/13 special phone numbers."""
        special_phone_patterns = [
            # 1300/1800 with flexible separators (covers compact format too)
            Pattern(
                name="au_1300_number",
                regex=r"\b1300[-\s]?\d{3}[-\s]?\d{3}\b",
                score=0.9
            ),
            Pattern(
                name="au_1800_number",
                regex=r"\b1800[-\s]?\d{3}[-\s]?\d{3}\b",
                score=0.9
            ),
            Pattern(
                name="au_13_number",
                regex=r"\b13[-\s]?\d{2}[-\s]?\d{2}\b",
                score=0.85
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_SPECIAL_PHONE",
            patterns=special_phone_patterns,
            name="australian_special_phone_recognizer",
            context=["phone", "call", "contact", "helpline", "support", "hotline", "number"]
        )

    # =========================================================================
    # Phase 3: Address & Network IDs
    # =========================================================================

    def _create_po_box_recognizer(self) -> PatternRecognizer:
        """Create recognizer for PO Box addresses."""
        po_box_patterns = [
            Pattern(
                name="po_box_standard",
                regex=r"(?i)\bP\.?\s*O\.?\s*Box\s+\d{1,6}\b",
                score=0.85
            ),
            Pattern(
                name="gpo_box",
                regex=r"(?i)\bGPO\s*Box\s+\d{1,6}\b",
                score=0.85
            ),
            Pattern(
                name="locked_bag",
                regex=r"(?i)\bLocked\s+Bag\s+\d{1,6}\b",
                score=0.85
            ),
            Pattern(
                name="private_bag",
                regex=r"(?i)\bPrivate\s+Bag\s+\d{1,6}\b",
                score=0.85
            ),
            Pattern(
                name="po_box_full_address",
                regex=r"(?i)\b(?:P\.?\s*O\.?\s*Box|GPO\s*Box)\s+\d{1,6}\s*,?\s*[A-Za-z][A-Za-z\s]{2,25}\s+(?:NSW|VIC|QLD|WA|SA|TAS|ACT|NT)\s+\d{4}\b",
                score=0.95
            ),
            Pattern(
                name="cmb_rmb_rural",
                regex=r"(?i)\b(?:CMB|RMB|RSD|MS)\s*\.?\s*\d{1,6}\b",
                score=0.8
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_PO_BOX",
            patterns=po_box_patterns,
            name="po_box_recognizer",
            context=["postal", "mail", "correspondence", "send to", "address", "post"]
        )

    # =========================================================================
    # Device Identifiers (telecom-specific)
    # =========================================================================

    def _create_imei_recognizer(self) -> PatternRecognizer:
        """Create recognizer for IMEI numbers."""
        imei_patterns = [
            Pattern(
                name="imei_with_context",
                regex=r"(?i)(?:imei|device\s*id|handset)[:\s#]*(\d{15,17})",
                score=0.95
            ),
            Pattern(
                name="imei_15_digit",
                regex=r"\b\d{15}\b",
                score=0.4  # Low without context - could be other long number
            ),
            Pattern(
                name="imei_formatted",
                regex=r"\b\d{2}[-\s]?\d{6}[-\s]?\d{6}[-\s]?\d{1}\b",
                score=0.7
            )
        ]

        return PatternRecognizer(
            supported_entity="IMEI",
            patterns=imei_patterns,
            name="imei_recognizer",
            context=["imei", "device id", "handset", "phone serial", "mobile device", "device"]
        )

    def _create_iccid_recognizer(self) -> PatternRecognizer:
        """Create recognizer for ICCID (SIM card) numbers."""
        iccid_patterns = [
            # With explicit context (highest confidence)
            Pattern(
                name="iccid_with_context",
                regex=r"(?i)(?:iccid|sim|sim\s*card|sim\s*number)[:\s#]*(89\d{17,19})",
                score=0.95
            ),
            # All ICCIDs start with 89 (covers Australian 8961/8964 prefixes)
            Pattern(
                name="iccid_generic",
                regex=r"\b89\d{17,19}\b",
                score=0.85
            )
        ]

        return PatternRecognizer(
            supported_entity="ICCID",
            patterns=iccid_patterns,
            name="iccid_recognizer",
            context=["iccid", "sim", "sim card", "sim number", "icc", "sim serial"]
        )

    def _create_ntd_serial_recognizer(self) -> PatternRecognizer:
        """Create recognizer for NBN NTD (Network Termination Device) serial numbers."""
        ntd_patterns = [
            Pattern(
                name="ntd_prefixed",
                regex=r"(?i)\bNTD[-\s]?([A-Z0-9]{8,16})\b",
                score=0.9
            ),
            Pattern(
                name="ntd_nokia",
                regex=r"\bNOKA[A-Z0-9]{8,14}\b",
                score=0.85
            ),
            Pattern(
                name="ntd_alcatel",
                regex=r"\bALCL[A-Z0-9]{8,14}\b",
                score=0.85
            ),
            Pattern(
                name="ntd_hfc_modem",
                regex=r"\b[23]M[A-Z0-9]{8,12}\b",
                score=0.8
            ),
            Pattern(
                name="ntd_with_context",
                regex=r"(?i)(?:ntd|network\s*termination|connection\s*box|nbn\s*device)[:\s#]*([A-Z0-9]{8,16})",
                score=0.95
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_NTD_SERIAL",
            patterns=ntd_patterns,
            name="ntd_serial_recognizer",
            context=["ntd", "network termination", "connection box", "nbn device", "nbn equipment", "modem serial"]
        )

    # =========================================================================
    # Australian Identity Documents
    # =========================================================================

    def _create_driver_license_recognizer(self) -> PatternRecognizer:
        """Create recognizer for Australian Driver License numbers.

        Format varies by state:
        - NSW: 8 digits
        Australian licenses have NO checksum validation. Detection relies on:
        1. Context keywords (license, licence, lic, DL, etc.)
        2. State-prefixed patterns (e.g., "license vic 060241481")

        Bare digit patterns (8-9 digits) have very low scores and require
        strong context boost to avoid false positives on phone numbers, dates, etc.
        """
        driver_license_patterns = [
            # === HIGH CONFIDENCE: Explicit context patterns ===
            # These have context baked into the regex itself
            Pattern(
                name="au_dl_with_context",
                regex=r"(?i)(?:driver[']?s?\s*licen[cs]e|DL|licen[cs]e\s*(?:no|number|num|#))[:\s#]*([A-Za-z]?\d{6,9})",
                score=0.9
            ),
            Pattern(
                name="au_dl_number_prefix",
                regex=r"(?i)(?:licen[cs]e|DL)[:\s#]*([A-Za-z0-9]{6,10})",
                score=0.85
            ),
            # State-prefixed: "license vic 060241481", "lic nsw 12345678"
            Pattern(
                name="au_dl_state_prefix",
                regex=r"(?i)(?:licen[cs]e|lic\.?)\s+(?:vic|nsw|qld|sa|wa|tas|nt|act)\s+(\d{6,10})\b",
                score=0.9
            ),
            # State after keyword: "vic licence 123456789"
            Pattern(
                name="au_dl_license_state",
                regex=r"(?i)\b(?:vic|nsw|qld|sa|wa|tas|nt|act)\s+(?:licen[cs]e|lic\.?)\s*[:\-#]?\s*(\d{6,10})\b",
                score=0.9
            ),

            # === MEDIUM CONFIDENCE: Distinctive formats ===
            # VIC alpha prefix (letter + 8 digits) - reasonably unique
            Pattern(
                name="au_dl_vic_alpha",
                regex=r"\b[A-Za-z]\d{8}\b",
                score=0.5
            ),
            # SA format (letter + 5 digits, e.g., S12345)
            Pattern(
                name="au_dl_sa",
                regex=r"\b[A-Za-z]\d{5}\b",
                score=0.4
            ),

            # === LOW CONFIDENCE: Bare digit patterns ===
            # These REQUIRE context keywords to be useful
            # NSW/QLD: 8 digits
            Pattern(
                name="au_dl_8digit",
                regex=r"\b\d{8}\b",
                score=0.01
            ),
            # VIC/QLD: 9 digits
            Pattern(
                name="au_dl_9digit",
                regex=r"\b\d{9}\b",
                score=0.01
            ),
        ]

        return PatternRecognizer(
            supported_entity="AU_DRIVER_LICENSE",
            patterns=driver_license_patterns,
            name="australian_driver_license_recognizer",
            context=["driver license", "driver licence", "drivers license", "drivers licence",
                     "driving license", "driving licence", "DL", "licence number",
                     "license number", "licence no", "license no",
                     "lic", "drv", "d/l", "dl#"]
        )

    def _create_passport_recognizer(self) -> PatternRecognizer:
        """Create recognizer for Australian Passport numbers.

        Format: 2 letters + 7 digits (e.g., PA1234567, N1234567)
        First letter typically P, N, or E
        """
        passport_patterns = [
            # Standard format: 2 letters + 7 digits
            Pattern(
                name="au_passport_standard",
                regex=r"\b[PNE][A-Za-z]\d{7}\b",
                score=0.7
            ),
            # Single letter + 7 digits (older format)
            Pattern(
                name="au_passport_single_letter",
                regex=r"\b[PNELM]\d{7}\b",
                score=0.65
            ),
            # Any 2 letters + 7 digits
            Pattern(
                name="au_passport_generic",
                regex=r"\b[A-Za-z]{2}\d{7}\b",
                score=0.5
            ),
            # With explicit context
            Pattern(
                name="au_passport_with_context",
                regex=r"(?i)(?:passport|passport\s*(?:no|number|num|#)|travel\s*document)[:\s#]*([A-Za-z]{1,2}\d{7})",
                score=0.95
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_PASSPORT",
            patterns=passport_patterns,
            name="australian_passport_recognizer",
            context=["passport", "passport number", "travel document", "passport no",
                     "australian passport", "au passport"]
        )

    def _create_centrelink_recognizer(self) -> PatternRecognizer:
        """Create recognizer for Centrelink Customer Reference Numbers (CRN).

        Format: 9 digits followed by a letter (e.g., 123456789A)
        """
        centrelink_patterns = [
            # Standard CRN format: 9 digits + letter
            Pattern(
                name="au_crn_standard",
                regex=r"\b\d{9}[A-Za-z]\b",
                score=0.75
            ),
            # With explicit context (highest confidence)
            Pattern(
                name="au_crn_with_context",
                regex=r"(?i)(?:centrelink|CRN|customer\s*reference\s*(?:no|number|num)?|reference\s*(?:no|number|num))[:\s#]*(\d{9}[A-Za-z])",
                score=0.95
            ),
            # Pension/concession card context
            Pattern(
                name="au_crn_pension",
                regex=r"(?i)(?:pension|concession|health\s*care|seniors)[\s]*(?:card)?[:\s#]*(\d{9}[A-Za-z])",
                score=0.9
            )
        ]

        return PatternRecognizer(
            supported_entity="AU_CENTRELINK_CRN",
            patterns=centrelink_patterns,
            name="centrelink_crn_recognizer",
            context=["centrelink", "CRN", "customer reference number", "reference number",
                     "pension", "concession", "health care card", "seniors card"]
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

            # Deduplicate and merge overlapping matches
            matches = deduplicate_matches(matches)
            matches = merge_overlapping_matches(matches)

            # Anonymize text (Pass 1: spaCy/Presidio)
            print("Anonymizing PII...")
            anonymized_text = self.anonymizer.anonymize_batch(matches, text)
            result.pii_anonymized = len(matches)

            # Pass 2: LLM second pass (if enabled)
            llm_config = self.config.get('llm_detection', {})
            if llm_config.get('enabled', False):
                print("Running LLM second pass...")
                llm_matches = self._detect_llm_pii(anonymized_text)
                if llm_matches:
                    print(f"  LLM: found {len(llm_matches)} additional PII instances")
                    llm_matches = deduplicate_matches(llm_matches)
                    llm_matches = merge_overlapping_matches(llm_matches)
                    anonymized_text = self.anonymizer.anonymize_batch(llm_matches, anonymized_text)
                    result.llm_pii_found = len(llm_matches)
                    result.pii_anonymized += len(llm_matches)
                    result.matches.extend(llm_matches)

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
            # Use shared analysis function (handles normalization and false positive filtering)
            matches = analyze_text_for_pii(self.analyzer, text)

            print(f"  Presidio: found {len(matches)} PII instances")
            return matches

        except Exception as e:
            print(f"  Error during Presidio analysis: {e}")
            return []

    def _detect_llm_pii(self, text: str) -> List[PIIMatch]:
        """
        Detect PII using LLM second pass.

        Args:
            text: Text to analyze (typically already partially redacted)

        Returns:
            List of PIIMatch objects from LLM detection
        """
        from src.processors.pii_detection import apply_llm_second_pass

        llm_config = self.config.get('llm_detection', {})
        results = apply_llm_second_pass([text], llm_config)
        return results[0] if results else []

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
