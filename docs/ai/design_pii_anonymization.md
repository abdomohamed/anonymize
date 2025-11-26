# PII Anonymization Tool - Design Document

## Overview

This document describes the design and architecture of the PII (Personally Identifiable Information) Anonymization Tool - a Python-based solution for detecting and anonymizing sensitive personal information in text files.

**Version**: 1.0  
**Date**: November 26, 2025  
**Status**: Implementation

---

## Table of Contents

1. [Purpose and Goals](#purpose-and-goals)
2. [Architecture Overview](#architecture-overview)
3. [Component Design](#component-design)
4. [PII Types and Detection](#pii-types-and-detection)
5. [Anonymization Strategies](#anonymization-strategies)
6. [Data Flow](#data-flow)
7. [Configuration](#configuration)
8. [Error Handling](#error-handling)
9. [Performance Considerations](#performance-considerations)
10. [Future Enhancements](#future-enhancements)

---

## Purpose and Goals

### Primary Goals

1. **Detect PII**: Automatically identify various types of personally identifiable information using Microsoft Presidio
2. **Anonymize Data**: Replace detected PII with anonymized versions while maintaining document structure
3. **Flexibility**: Support multiple anonymization strategies (redaction, masking, replacement)
4. **Leverage Presidio**: Use production-tested detection framework instead of custom regex patterns
5. **Usability**: Simple CLI interface for common use cases

### Non-Goals (Phase 1)

- Real-time processing of streaming data
- GUI interface
- Database integration
- Multi-language support (Phase 1 focuses on English)
- Image/PDF text extraction (text files only)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Interface                        │
│                         (cli.py)                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     File Processor                          │
│                  (processors/file_processor.py)             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ - Read input file                                     │  │
│  │ - Coordinate detection and anonymization             │  │
│  │ - Write anonymized output                            │  │
│  │ - Generate audit logs                                │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────┬────────────────────────────┬────────────────┘
                │                            │
                ▼                            ▼
┌───────────────────────────┐  ┌───────────────────────────┐
│   Microsoft Presidio      │  │     Anonymizers           │
│ (presidio-analyzer)       │  │ (anonymizers/)            │
│ ┌───────────────────────┐ │  │ ┌───────────────────────┐ │
│ │ - AnalyzerEngine      │ │  │ │ - Redactor            │ │
│ │ - Built-in Recognizers│ │  │ │ - Masker              │ │
│ │ - Pattern Recognizers │ │  │ │ - FakerAnonymizer     │ │
│ │ - NER Models          │ │  │ │ - HashAnonymizer      │ │
│ │ - Custom Recognizers  │ │  │ └───────────────────────┘ │
│ └───────────────────────┘ │  └───────────────────────────┘
└───────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────┐
│                  Configuration Manager                     │
│              (config/config_manager.py)                    │
│  - Load detection rules                                    │
│  - Load anonymization strategies                           │
│  - Manage whitelist/blacklist                             │
└───────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Separation of Concerns**: Detection and anonymization are separate, composable operations
2. **Plugin Architecture**: Easy to add new detectors and anonymizers
3. **Configuration-Driven**: Behavior controlled through YAML/JSON configuration
4. **Fail-Safe**: Errors should not result in partial anonymization
5. **Idempotency**: Running twice on the same input produces the same output

---

## Component Design

### 1. Microsoft Presidio AnalyzerEngine

**Responsibility**: PII detection using Microsoft's production-grade framework

**Key Features**:
- 30+ built-in recognizers (EMAIL, PHONE, SSN, CREDIT_CARD, etc.)
- NLP-based recognition using spaCy for context-aware detection
- Multi-language support (English, Spanish, French, German, etc.)
- Pattern-based and ML-based detection
- Customizable with additional recognizers
- Configurable confidence thresholds

**Usage**:
```python
from presidio_analyzer import AnalyzerEngine

analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
results = analyzer.analyze(
    text=text,
    language='en',
    entities=['EMAIL_ADDRESS', 'PHONE_NUMBER', 'PERSON'],
    score_threshold=0.7
)
```

**Supported Entity Types** (selection):
- EMAIL_ADDRESS, PHONE_NUMBER
- CREDIT_CARD (Luhn validated)
- US_SSN, UK_NHS, SG_NRIC_FIN
- US_PASSPORT, US_DRIVER_LICENSE, US_ITIN
- IBAN_CODE, CRYPTO (wallet addresses)
- IP_ADDRESS (IPv4/IPv6)
- PERSON, LOCATION (NER-based)
- DATE_TIME
- And many more...

**PIIMatch Data Structure**:
```python
@dataclass
class PIIMatch:
    pii_type: str           # e.g., "EMAIL_ADDRESS", "PHONE_NUMBER"
    value: str              # The actual PII found
    start: int              # Start position in text
    end: int                # End position in text
    confidence: float       # Confidence score (0.0 - 1.0)
    context: str = ""       # Surrounding text for context
    detector_name: str      # "Presidio"
```

### 2. Base Anonymizer (`anonymizers/base_anonymizer.py`)

**Responsibility**: Abstract base class for anonymization strategies

**Interface**:
```python
class BaseAnonymizer(ABC):
    def __init__(self, config: Dict):
        """Initialize anonymizer with configuration"""
        
    @abstractmethod
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """Return anonymized version of the PII"""
        
    def anonymize_batch(self, matches: List[PIIMatch], text: str) -> str:
        """Anonymize multiple matches in text efficiently"""
```

### 5. Anonymization Strategies

#### Redactor (`anonymizers/redactor.py`)
- Replaces PII with `[REDACTED]` or custom token
- Options: `[REDACTED]`, `***`, `[EMAIL_REDACTED]`, etc.
- Simplest and most privacy-preserving

#### Masker (`anonymizers/masker.py`)
- Partial masking: shows some characters, hides others
- Examples:
  - Email: `j***@example.com`
  - Phone: `555-***-1234`
  - SSN: `***-**-1234`
- Configurable mask character and visible portions

#### Faker Anonymizer (`anonymizers/faker_anonymizer.py`)
- Generates realistic fake data using Faker library
- Maintains data format and structure
- Examples:
  - Real email `john.doe@company.com` → Fake `jane.smith@example.com`
  - Real phone `555-1234` → Fake `555-9876`
- Useful for testing and development environments

#### Hash Anonymizer (`anonymizers/hash_anonymizer.py`)
- Consistent hashing: same input → same output
- Format: `<HASH_PREFIX>_<HASH_VALUE>`
- Examples:
  - `john.doe@example.com` → `EMAIL_a3f5d9e1`
  - Same email appears again → `EMAIL_a3f5d9e1` (consistent)
- Useful when relationships need to be preserved

### 6. File Processor (`processors/file_processor.py`)

**Responsibility**: Orchestrate file reading, detection, anonymization, and writing

**Key Methods**:
```python
class FileProcessor:
    def process_file(self, input_path: str, output_path: str) -> ProcessResult
    def process_directory(self, input_dir: str, output_dir: str) -> List[ProcessResult]
    def generate_audit_log(self, result: ProcessResult) -> AuditLog
```

**Processing Pipeline**:
1. Read input file
2. Run all configured detectors
3. Merge and deduplicate matches
4. Sort matches by position (reverse order for replacement)
5. Apply anonymization strategy
6. Write output file
7. Generate audit log (optional)

**Error Handling**:
- Validate file exists and is readable
- Check for write permissions
- Handle encoding issues (UTF-8 default)
- Transaction-like behavior: output only written if successful

### 7. Configuration Manager (`config/config_manager.py`)

**Responsibility**: Load and manage configuration

**Configuration Structure** (`config/default_config.yaml`):
```yaml
detection:
  enabled_detectors:
    - email
    - phone
    - ssn
    - name
    
  confidence_threshold: 0.7
  
  regex_patterns:
    custom_pattern_1: "regex_here"
  
  nlp:
    model: "en_core_web_sm"
    entity_types:
      - PERSON
      - ORG
      - GPE

anonymization:
  strategy: "redact"  # redact, mask, replace, hash
  
  redact:
    token: "[REDACTED]"
    type_specific: true  # Use [EMAIL_REDACTED], [PHONE_REDACTED]
  
  mask:
    mask_char: "*"
    email_visible_chars: 1  # Show first char
    phone_visible_chars: 3  # Show area code
  
  replace:
    locale: "en_US"
    seed: null  # For reproducible fake data
  
  hash:
    algorithm: "sha256"
    prefix: true  # Include PII type in hash
    salt: "random_salt_here"

processing:
  batch_size: 1000  # Lines to process at once
  preserve_formatting: true
  create_audit_log: true
  backup_original: false

whitelist:
  - "noreply@example.com"
  - "support@company.com"

blacklist:
  - "test@test.com"  # Force detection even if pattern doesn't match
```

---

## PII Types and Detection

### Phase 1 - Supported PII Types

| PII Type | Detection Method | Regex Pattern | Validation |
|----------|------------------|---------------|------------|
| Email | Regex | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | Check TLD validity |
| Phone (US) | Regex | Multiple formats | Length validation |
| SSN (US) | Regex | `\d{3}-\d{2}-\d{4}` | Area number validation |
| Credit Card | Regex | Luhn algorithm pattern | Luhn checksum |
| IP Address | Regex | IPv4/IPv6 patterns | Range validation |
| Names | NLP (spaCy) | N/A | Confidence threshold |
| Addresses | NLP (spaCy) | N/A | Confidence threshold |
| Dates | Regex + NLP | Common date formats | Age validation for DOB |

### Detection Algorithm

```python
def detect_all_pii(text: str, detectors: List[BaseDetector]) -> List[PIIMatch]:
    """
    1. Run all detectors in parallel (or sequentially)
    2. Collect all matches
    3. Remove duplicates (same position, prefer higher confidence)
    4. Resolve overlaps (longer match wins, or higher confidence)
    5. Return sorted list by position
    """
```

### False Positive Reduction

1. **Context Analysis**: Check surrounding words
2. **Validation**: Apply format-specific validation (Luhn for CC, area codes for phones)
3. **Whitelist**: Skip known non-PII values
4. **Confidence Threshold**: Filter low-confidence matches
5. **Dictionary Check**: For names, verify against common word dictionary

---

## Data Flow

### Single File Processing Flow

```
┌─────────────┐
│ Input File  │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│ Read File (UTF-8)   │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Run Detectors       │
│ - Email Detector    │
│ - Phone Detector    │
│ - SSN Detector      │
│ - NLP Detector      │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Merge & Deduplicate │
│ - Remove duplicates │
│ - Resolve overlaps  │
│ - Sort by position  │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Apply Anonymization │
│ - Replace from end  │
│ - Maintain offsets  │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Write Output File   │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ Generate Audit Log  │
│ (Optional)          │
└─────────────────────┘
```

### Batch Processing Flow

```
Input Directory
    │
    ├─── file1.txt ──┐
    ├─── file2.txt ──┼──► Process Each File ──► Output Directory
    └─── file3.txt ──┘                              │
                                                    ├─── file1_anonymized.txt
                                                    ├─── file2_anonymized.txt
                                                    └─── file3_anonymized.txt
```

---

## Configuration

### Configuration Hierarchy

1. **Default Configuration**: Built-in defaults in `config/default_config.yaml`
2. **User Configuration**: Override with custom config file
3. **CLI Arguments**: Override specific options via command line
4. **Environment Variables**: For sensitive data (API keys, salts)

### Runtime Configuration

```python
# Configuration is loaded at startup
config = ConfigManager.load(
    default_path="config/default_config.yaml",
    user_path=args.config,
    cli_overrides=args
)

# Detectors and anonymizers are initialized with config
detectors = DetectorFactory.create_all(config.detection)
anonymizer = AnonymizerFactory.create(config.anonymization)
```

---

## Error Handling

### Error Categories

1. **Input Errors**
   - File not found
   - File not readable
   - Invalid encoding
   - Action: Log error, skip file, continue with others

2. **Detection Errors**
   - Detector initialization failure
   - Model loading failure
   - Action: Disable failing detector, log warning, continue

3. **Anonymization Errors**
   - Strategy not found
   - Invalid configuration
   - Action: Abort processing, return error

4. **Output Errors**
   - No write permission
   - Disk full
   - Action: Abort, ensure no partial files, return error

### Error Handling Strategy

```python
class ProcessResult:
    success: bool
    input_path: str
    output_path: str
    pii_found: int
    pii_anonymized: int
    errors: List[str]
    warnings: List[str]
    processing_time: float
```

---

## Performance Considerations

### Optimization Strategies

1. **Regex Compilation**: Pre-compile all regex patterns at initialization
2. **Batch Processing**: Process large files in chunks
3. **Lazy Loading**: Load NLP models only when needed
4. **Parallel Processing**: Process multiple files concurrently
5. **Efficient Replacement**: Replace from end to start to maintain offsets

### Performance Targets (Phase 1)

- Small files (<1MB): < 1 second
- Medium files (1-10MB): < 10 seconds
- Large files (10-100MB): < 2 minutes
- Memory usage: < 500MB for files up to 100MB

### Scalability Considerations

- Stream processing for very large files (future)
- Distributed processing for batch jobs (future)
- Caching for repeated patterns
- Incremental processing (process only changed portions)

---

## Future Enhancements

### Phase 2 Enhancements

1. **Additional File Formats**
   - CSV with column-aware processing
   - JSON with path-based anonymization
   - XML/HTML with tag preservation
   - PDF text extraction

2. **Advanced NLP**
   - Multi-language support
   - Custom entity training
   - Context-based confidence adjustment
   - Relationship detection (same person mentioned multiple times)

3. **Reversible Anonymization**
   - Token mapping for de-anonymization
   - Encrypted mapping storage
   - Key management

4. **Integration Features**
   - REST API for service deployment
   - Database connector for direct DB anonymization
   - Cloud storage integration (S3, Azure Blob)

### Phase 3 Enhancements

1. **GUI Interface**
   - Web-based UI
   - Real-time preview
   - Interactive review of detected PII

2. **Compliance Features**
   - GDPR compliance mode
   - HIPAA compliance mode
   - Audit trail with tamper detection
   - Data lineage tracking

3. **Machine Learning**
   - Custom model training on user data
   - Active learning for false positive reduction
   - Anomaly detection for unusual PII patterns

---

## Security Considerations

### Data Security

1. **In-Memory Processing**: Avoid writing sensitive data to temp files
2. **Secure Deletion**: Overwrite original files if requested
3. **Audit Logs**: Store securely, never include actual PII values
4. **Configuration**: Never store sensitive keys in config files (use env vars)

### Access Control

1. **File Permissions**: Respect system file permissions
2. **Output Validation**: Ensure anonymization was successful before writing
3. **Backup Strategy**: Optional backup before anonymization (disabled by default)

---

## Testing Strategy

### Unit Tests

- Each detector tested independently
- Each anonymizer tested independently
- Edge cases: empty strings, special characters, multiple occurrences
- Performance tests: large inputs, many matches

### Integration Tests

- End-to-end file processing
- Multiple detectors working together
- Configuration loading and override
- Error handling and recovery

### Test Data

- Synthetic test data with known PII
- Real-world anonymized examples
- Edge cases: nested PII, unusual formats
- Performance test corpus: varying file sizes

---

## Appendix

### Technology Stack

- **Language**: Python 3.9+
- **CLI**: argparse
- **Configuration**: PyYAML
- **NLP**: spaCy (en_core_web_sm model)
- **Fake Data**: Faker
- **Testing**: pytest
- **Logging**: Python logging module

### Dependencies

```
spacy>=3.5.0
faker>=18.0.0
pyyaml>=6.0
regex>=2023.0.0
```

### File Structure

```
anonymize/
├── docs/
│   └── ai/
│       └── design_pii_anonymization.md
├── src/
│   ├── __init__.py
│   ├── anonymizers/          # Custom anonymization strategies
│   │   ├── __init__.py
│   │   ├── base_anonymizer.py
│   │   ├── redactor.py
│   │   ├── masker.py
│   │   ├── faker_anonymizer.py
│   │   └── hash_anonymizer.py
│   ├── processors/
│   │   ├── __init__.py
│   │   └── file_processor.py  # Uses Presidio directly
│   ├── config/
│   │   ├── __init__.py
│   │   └── config_manager.py
│   ├── models.py
│   ├── utils.py
│   └── cli.py
├── tests/
│   ├── test_anonymizers.py
│   ├── test_integration.py
├── config/
│   └── default_config.yaml
├── examples/
│   └── sample_input.txt
├── requirements.txt
└── README.md
```

**Note**: No custom detector layer needed - Presidio AnalyzerEngine is used directly.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-26 | System | Initial design document |

