# PII Recognizer Implementation Plan

## Status: ✅ IMPLEMENTED (18 December 2025)

## Overview

This document outlines the implementation plan for adding 10 new PII recognizers to the anonymization system, specifically tailored for Australian telecom CRM free-text fields.

**Target File:** `src/processors/file_processor.py`

**Priority Order:** Based on sensitivity, frequency of occurrence, and false positive risk.

---

## Implementation Summary

| # | PII Type | Entity Name | Complexity | Status |
|---|----------|-------------|------------|--------|
| 1 | Tax File Number (TFN) | `AU_TFN` | Medium | ✅ Presidio Built-in |
| 2 | Medicare Number | `AU_MEDICARE` | Medium | ✅ Presidio Built-in |
| 3 | ABN/ACN | `AU_ABN`, `AU_ACN` | Medium | ✅ Presidio Built-in |
| 4 | NBN Location ID | `AU_NBN_LOC_ID` | Low | ✅ Custom |
| 5 | 1300/1800 Numbers | `AU_SPECIAL_PHONE` | Low | ✅ Custom |
| 6 | AVC/CVC IDs | `AU_NBN_SERVICE_ID` | Low | ✅ Custom |
| 7 | PO Box Addresses | `AU_PO_BOX` | Medium | ✅ Custom |
| 8 | MAC Addresses | `MAC_ADDRESS` | Low | ❌ Removed (not needed) |
| 9 | IMEI/ICCID | `IMEI`, `ICCID` | Low | ✅ Custom |
| 10 | NTD Serial Numbers | `AU_NTD_SERIAL` | Low | ✅ Custom |
| 11 | AU Driver License | `AU_DRIVER_LICENSE` | High | ✅ Custom |
| 12 | AU Passport | `AU_PASSPORT` | Low | ✅ Custom |
| 13 | Centrelink CRN | `AU_CENTRELINK_CRN` | Medium | ✅ Custom |

**Additional Enhancements:**
- ✅ Enhanced Australian phone recognizer (added parenthetical, dashes, dots, messy spacing)
- ✅ Enhanced DOB recognizer (added dash, dot, ISO, written formats)
- ✅ Updated config with all new entity types
- ✅ Created test fixtures file
- ✅ Removed redundant recognizers (TFN, Medicare, ABN, ACN, MAC) - Presidio provides with checksums

---

## Phase 1: Critical Government IDs (Priority 1-3)

### 1. Australian Tax File Number (TFN)

**Entity Name:** `AU_TFN`

**Format:**
- 9 digits (current) or 8 digits (legacy)
- Common formats: `123 456 789`, `123-456-789`, `123456789`

**Validation:** Modulus 11 check digit algorithm

**Regex Patterns:**
```python
Pattern(
    name="tfn_with_context",
    regex=r"(?i)(?:tfn|tax\s*file\s*(?:no|number|num)?)[:\s#]*(\d{3}[\s\-]?\d{3}[\s\-]?\d{2,3})",
    score=0.9
),
Pattern(
    name="tfn_9_digit_formatted",
    regex=r"\b\d{3}[\s\-]\d{3}[\s\-]\d{3}\b",
    score=0.6
),
Pattern(
    name="tfn_8_digit_legacy",
    regex=r"\b\d{3}[\s\-]\d{3}[\s\-]\d{2}\b",
    score=0.5
)
```

**Context Words:** `tfn`, `tax file`, `tax file number`, `taxation`, `ato`

**Implementation Notes:**
- Consider adding validation function to boost confidence for valid TFNs
- 9-digit plain numbers have high false positive risk without context

---

### 2. Medicare Number

**Entity Name:** `AU_MEDICARE`

**Format:**
- 10 digits (+ optional 1-digit IRN for family member)
- First digit: 2-6 only
- Common formats: `2123 45670 1`, `21234567012`, `2123 45670 1/2`

**Regex Patterns:**
```python
Pattern(
    name="medicare_with_context",
    regex=r"(?i)(?:medicare|med\s*card)[:\s#]*([2-6]\d{3}[\s]?\d{5}[\s]?\d(?:[\s/]?[1-9])?)",
    score=0.9
),
Pattern(
    name="medicare_formatted",
    regex=r"\b[2-6]\d{3}[\s]?\d{5}[\s]?\d\b",
    score=0.65
),
Pattern(
    name="medicare_with_irn",
    regex=r"\b[2-6]\d{3}[\s]?\d{5}[\s]?\d[\s/]?[1-9]\b",
    score=0.7
)
```

**Context Words:** `medicare`, `medicare number`, `med card`, `health card`, `irn`

**Implementation Notes:**
- First digit restriction (2-6) helps reduce false positives
- IRN (Individual Reference Number) is optional 10th digit

---

### 3. ABN and ACN

**Entity Name:** `AU_ABN`, `AU_ACN`

**ABN Format:**
- 11 digits
- Common format: `51 824 753 556`
- Validation: Modulus 89 algorithm

**ACN Format:**
- 9 digits
- Common format: `004 085 616`
- Note: Same format as TFN - context is critical

**Regex Patterns:**
```python
# ABN Patterns
Pattern(
    name="abn_with_context",
    regex=r"(?i)(?:abn|australian\s*business\s*(?:no|number)?)[:\s#]*(\d{2}[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{3})",
    score=0.9
),
Pattern(
    name="abn_formatted",
    regex=r"\b\d{2}[\s\-]\d{3}[\s\-]\d{3}[\s\-]\d{3}\b",
    score=0.7
),

# ACN Patterns
Pattern(
    name="acn_with_context",
    regex=r"(?i)(?:acn|australian\s*company\s*(?:no|number)?)[:\s#]*(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})",
    score=0.85
),
Pattern(
    name="acn_formatted",
    regex=r"\b\d{3}[\s\-]\d{3}[\s\-]\d{3}\b",
    score=0.4  # Low score - same format as TFN
)
```

**Context Words:** 
- ABN: `abn`, `australian business number`, `business number`, `gst`
- ACN: `acn`, `australian company number`, `company number`, `asic`

**Implementation Notes:**
- Consider validation functions for both ABN and ACN
- ACN without context has high false positive risk (same format as TFN)

---

## Phase 2: NBN/Telecom IDs (Priority 4-6)

### 4. NBN Location ID (LOC ID)

**Entity Name:** `AU_NBN_LOC_ID`

**Format:**
- `LOC` prefix + 12 alphanumeric characters
- Examples: `LOC000012345678`, `LOC-000012345678`

**Regex Patterns:**
```python
Pattern(
    name="nbn_loc_id_standard",
    regex=r"(?i)\bLOC[-\s]?([A-Z0-9]{10,12})\b",
    score=0.9
),
Pattern(
    name="nbn_loc_id_with_context",
    regex=r"(?i)(?:location\s*id|loc\s*id|nbn\s*location)[:\s#]*(LOC)?[-\s]?([A-Z0-9]{10,12})",
    score=0.95
)
```

**Context Words:** `location id`, `loc id`, `nbn location`, `premises`, `nbn address`

---

### 5. 1300/1800 Special Numbers

**Entity Name:** `AU_SPECIAL_PHONE`

**Formats:**
- 1300 numbers: `1300 XXX XXX` (local rate)
- 1800 numbers: `1800 XXX XXX` (toll-free)
- 13 numbers: `13 XX XX` (local rate, 6 digits)

**Regex Patterns:**
```python
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
```

**Context Words:** `phone`, `call`, `contact`, `helpline`, `support`

**Implementation Notes:**
- Add to existing `_create_australian_phone_recognizer()` method

---

### 6. AVC/CVC Service IDs

**Entity Name:** `AU_NBN_SERVICE_ID`

**Format:**
- AVC: `AVC` + 10-12 alphanumeric characters
- CVC: `CVC` + 6-12 alphanumeric characters

**Regex Patterns:**
```python
Pattern(
    name="nbn_avc_id",
    regex=r"(?i)\bAVC[-\s]?([A-Z0-9]{10,12})\b",
    score=0.9
),
Pattern(
    name="nbn_cvc_id",
    regex=r"(?i)\bCVC[-\s]?([A-Z0-9]{6,12})\b",
    score=0.9
)
```

**Context Words:** `avc`, `cvc`, `virtual circuit`, `nbn service`, `access circuit`

---

## Phase 3: Address & Network IDs (Priority 7-8)

### 7. PO Box Addresses

**Entity Name:** `AU_PO_BOX`

**Formats:**
- `PO Box 123`
- `P.O. Box 123`
- `GPO Box 123`
- `Locked Bag 123`
- `Private Bag 123`

**Regex Patterns:**
```python
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
    regex=r"(?i)\b(?:Locked|Private)\s+Bag\s+\d{1,6}\b",
    score=0.85
),
Pattern(
    name="po_box_full_address",
    regex=r"(?i)\b(?:P\.?\s*O\.?\s*Box|GPO\s*Box)\s+\d{1,6}\s*,?\s*[A-Za-z][A-Za-z\s]{2,25}\s+(?:NSW|VIC|QLD|WA|SA|TAS|ACT|NT)\s+\d{4}\b",
    score=0.95
)
```

**Context Words:** `postal`, `mail`, `correspondence`, `send to`, `address`

**Implementation Notes:**
- Add to existing `_create_enhanced_address_recognizer()` or create new recognizer

---

### 8. MAC Addresses

**Entity Name:** `MAC_ADDRESS`

**Formats:**
- Colon-separated: `AA:BB:CC:DD:EE:FF`
- Dash-separated: `AA-BB-CC-DD-EE-FF`
- Dot-separated: `AABB.CCDD.EEFF`
- Plain: `AABBCCDDEEFF`

**Regex Patterns:**
```python
Pattern(
    name="mac_colon",
    regex=r"(?i)\b([0-9A-F]{2}:){5}[0-9A-F]{2}\b",
    score=0.9
),
Pattern(
    name="mac_dash",
    regex=r"(?i)\b([0-9A-F]{2}-){5}[0-9A-F]{2}\b",
    score=0.9
),
Pattern(
    name="mac_dot",
    regex=r"(?i)\b([0-9A-F]{4}\.){2}[0-9A-F]{4}\b",
    score=0.85
),
Pattern(
    name="mac_plain",
    regex=r"(?i)\b[0-9A-F]{12}\b",
    score=0.5  # Lower score - could be other hex string
)
```

**Context Words:** `mac`, `mac address`, `hardware address`, `ethernet`, `modem`, `router`

---

## Phase 4: Device Identifiers (Priority 9-10)

### 9. IMEI and ICCID

**Entity Name:** `IMEI`, `ICCID`

**IMEI Format:**
- 15-17 digits
- Can validate with Luhn algorithm

**ICCID Format:**
- 19-20 digits
- Starts with `89` (telecom industry) and `61` for Australia

**Regex Patterns:**
```python
# IMEI
Pattern(
    name="imei_with_context",
    regex=r"(?i)(?:imei|device\s*id)[:\s#]*(\d{15,17})",
    score=0.9
),
Pattern(
    name="imei_plain",
    regex=r"\b\d{15}\b",
    score=0.4  # Low without context
),

# ICCID
Pattern(
    name="iccid_australian",
    regex=r"\b89(?:61|64)\d{15,17}\b",
    score=0.9
),
Pattern(
    name="iccid_with_context",
    regex=r"(?i)(?:iccid|sim|sim\s*card)[:\s#]*(89\d{17,19})",
    score=0.95
)
```

**Context Words:**
- IMEI: `imei`, `device id`, `handset`, `phone serial`, `mobile device`
- ICCID: `iccid`, `sim`, `sim card`, `sim number`

---

### 10. NTD Serial Numbers

**Entity Name:** `AU_NTD_SERIAL`

**Format:**
- Varies by manufacturer
- Common prefixes: `NTD`, `NOKA`, `ALCL`, `2M`, `3M`
- Length: 10-16 alphanumeric characters

**Regex Patterns:**
```python
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
)
```

**Context Words:** `ntd`, `network termination`, `connection box`, `nbn device`, `nbn equipment`

---

## Implementation Steps

### Step 1: Create New Recognizer Methods

Add the following new methods to `FileProcessor` class:

```python
def _create_tfn_recognizer(self) -> PatternRecognizer:
def _create_medicare_recognizer(self) -> PatternRecognizer:
def _create_abn_recognizer(self) -> PatternRecognizer:
def _create_acn_recognizer(self) -> PatternRecognizer:
def _create_nbn_location_recognizer(self) -> PatternRecognizer:
def _create_nbn_service_recognizer(self) -> PatternRecognizer:
def _create_po_box_recognizer(self) -> PatternRecognizer:
def _create_mac_address_recognizer(self) -> PatternRecognizer:
def _create_imei_recognizer(self) -> PatternRecognizer:
def _create_iccid_recognizer(self) -> PatternRecognizer:
def _create_ntd_serial_recognizer(self) -> PatternRecognizer:
```

### Step 2: Update `_init_presidio()` Method

Register all new recognizers:

```python
# Add new recognizers
tfn_recognizer = self._create_tfn_recognizer()
medicare_recognizer = self._create_medicare_recognizer()
abn_recognizer = self._create_abn_recognizer()
acn_recognizer = self._create_acn_recognizer()
nbn_loc_recognizer = self._create_nbn_location_recognizer()
nbn_service_recognizer = self._create_nbn_service_recognizer()
po_box_recognizer = self._create_po_box_recognizer()
mac_recognizer = self._create_mac_address_recognizer()
imei_recognizer = self._create_imei_recognizer()
iccid_recognizer = self._create_iccid_recognizer()
ntd_recognizer = self._create_ntd_serial_recognizer()

registry.add_recognizer(tfn_recognizer)
registry.add_recognizer(medicare_recognizer)
# ... etc
```

### Step 3: Update Existing Phone Recognizer

Add 1300/1800/13 patterns to `_create_australian_phone_recognizer()`.

### Step 4: Update Existing Address Recognizer

Add PO Box patterns to `_create_enhanced_address_recognizer()` or create separate recognizer.

### Step 5: Add Validation Functions (Optional Enhancement)

```python
def _validate_tfn(self, tfn: str) -> bool:
    """Validate TFN using modulus 11 algorithm."""
    
def _validate_abn(self, abn: str) -> bool:
    """Validate ABN using modulus 89 algorithm."""
    
def _validate_acn(self, acn: str) -> bool:
    """Validate ACN using check digit algorithm."""
    
def _validate_imei(self, imei: str) -> bool:
    """Validate IMEI using Luhn algorithm."""
```

### Step 6: Update Tests

Create test cases in `tests/test_anonymizers.py`:
- Test each recognizer with valid formats
- Test with various spacing/formatting variations
- Test with context keywords
- Test false positive scenarios

### Step 7: Update Configuration

Add new entity types to `config/default_config.yaml`:

```yaml
detection:
  enabled_entities:
    # Existing
    - PERSON
    - EMAIL_ADDRESS
    # New Australian entities
    - AU_TFN
    - AU_MEDICARE
    - AU_ABN
    - AU_ACN
    - AU_NBN_LOC_ID
    - AU_NBN_SERVICE_ID
    - AU_SPECIAL_PHONE
    - AU_PO_BOX
    - MAC_ADDRESS
    - IMEI
    - ICCID
    - AU_NTD_SERIAL
```

---

## Testing Strategy

### Unit Tests

1. **Pattern matching tests** - Verify regex patterns match expected formats
2. **Score validation tests** - Verify confidence scores are appropriate
3. **Context boost tests** - Verify context words increase confidence
4. **Validation tests** - Verify check digit algorithms work correctly

### Integration Tests

1. **Full document processing** - Process sample CRM notes with mixed PII
2. **False positive tests** - Ensure regular text isn't flagged
3. **Edge case tests** - Malformed/partial entries

### Sample Test Data

Create `tests/fixtures/australian_pii_samples.txt` with:
- Valid examples of each PII type
- Invalid/edge case examples
- Mixed PII in realistic CRM note format

---

## Rollout Plan

1. **Phase 1** - Implement TFN, Medicare, ABN/ACN (Critical IDs)
2. **Phase 2** - Implement NBN LOC ID, 1300/1800, AVC/CVC (Telecom IDs)
3. **Phase 3** - Implement PO Box, MAC Address (Address/Network)
4. **Phase 4** - Implement IMEI, ICCID, NTD Serial (Device IDs)

Each phase should include:
- Implementation
- Unit tests
- Integration testing
- Documentation update

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| False positives on generic numbers | Use context keywords, lower base scores |
| TFN/ACN format collision | Require context for ACN without formatting |
| Performance impact | Profile after adding recognizers |
| Over-anonymization | Implement whitelist for known safe values |

---

## Future Enhancements

1. **Validation-boosted scoring** - Use check digit validation to increase confidence
2. **Machine learning enhancement** - Train NER model on Australian entities
3. **Configurable sensitivity** - Allow per-entity confidence thresholds
4. **Audit reporting** - Track which entity types are most frequently detected
