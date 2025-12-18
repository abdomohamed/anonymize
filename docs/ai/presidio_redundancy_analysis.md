# Presidio Built-in Recognizers - Redundancy Analysis

## Summary

This document analyzes the overlap between our custom PII recognizers and Microsoft Presidio's built-in predefined recognizers to identify redundancies that can be removed.

## Presidio Built-in Recognizers Found

### Australian-Specific (Country-Specific)
Located in: `presidio_analyzer/predefined_recognizers/country_specific/australia/`

| Recognizer | Entity Type | Features |
|------------|-------------|----------|
| `AuTfnRecognizer` | `AU_TFN` | ✅ Regex patterns, context words, **checksum validation** |
| `AuMedicareRecognizer` | `AU_MEDICARE` | ✅ Regex patterns, context words, **modulus-10 checksum** |
| `AuAbnRecognizer` | `AU_ABN` | ✅ Regex patterns, context words, **checksum validation (mod 89)** |
| `AuAcnRecognizer` | `AU_ACN` | ✅ Regex patterns, context words, **checksum validation** |

### Generic (Universal)
Located in: `presidio_analyzer/predefined_recognizers/generic/`

| Recognizer | Entity Type | Features |
|------------|-------------|----------|
| `CreditCardRecognizer` | `CREDIT_CARD` | ✅ Regex patterns, context, **Luhn checksum** |
| `EmailRecognizer` | `EMAIL_ADDRESS` | ✅ Regex patterns, context, tldextract |
| `IpRecognizer` | `IP_ADDRESS` | ✅ IPv4/IPv6 patterns, context, **ipaddress validation** |
| `PhoneRecognizer` | `PHONE_NUMBER` | ✅ Uses `phonenumbers` library |
| `UrlRecognizer` | `URL` | ✅ Regex patterns |
| `IbanRecognizer` | `IBAN_CODE` | ✅ IBAN detection with validation |
| `CryptoRecognizer` | `CRYPTO` | ✅ Crypto wallet addresses |
| `DateRecognizer` | `DATE_TIME` | ✅ Date patterns |

## Our Custom Recognizers vs Presidio Built-ins

### ❌ REDUNDANT - Can Be Removed

| Our Custom Recognizer | Presidio Equivalent | Recommendation |
|----------------------|---------------------|----------------|
| `_create_tfn_recognizer()` | `AuTfnRecognizer` | **REMOVE** - Presidio has checksum validation |
| `_create_medicare_recognizer()` | `AuMedicareRecognizer` | **REMOVE** - Presidio has checksum validation |
| `_create_abn_recognizer()` | `AuAbnRecognizer` | **REMOVE** - Presidio has checksum validation |
| `_create_acn_recognizer()` | `AuAcnRecognizer` | **REMOVE** - Presidio has checksum validation |

### ✅ KEEP - No Presidio Equivalent

| Our Custom Recognizer | Entity Type | Reason to Keep |
|----------------------|-------------|----------------|
| `_create_nbn_location_recognizer()` | `AU_NBN_LOC_ID` | **UNIQUE** - AU NBN Location ID (LOC######) |
| `_create_nbn_service_recognizer()` | `AU_NBN_SERVICE_ID` | **UNIQUE** - AU NBN Service ID (AVC######) |
| `_create_special_phone_recognizer()` | `AU_SPECIAL_PHONE` | **UNIQUE** - 13/1300/1800 numbers |
| `_create_po_box_recognizer()` | `AU_PO_BOX` | **UNIQUE** - Australian PO Box patterns |
| `_create_mac_address_recognizer()` | `MAC_ADDRESS` | **KEEP** - Not in Presidio defaults |
| `_create_imei_recognizer()` | `IMEI` | **UNIQUE** - Mobile device identifiers |
| `_create_iccid_recognizer()` | `ICCID` | **UNIQUE** - SIM card identifiers |
| `_create_ntd_serial_recognizer()` | `AU_NTD_SERIAL` | **UNIQUE** - Network Termination Device serials |
| `_create_australian_phone_recognizer()` | `AU_PHONE_NUMBER` | **ENHANCE** - More AU-specific patterns than generic |
| `_dob_recognizer()` | `DATE_OF_BIRTH` | **ENHANCE** - Has context keywords for DOB |

### ⚠️ VERIFY - May Have Overlap

| Our Custom | Presidio | Notes |
|------------|----------|-------|
| `AU_PHONE_NUMBER` | `PHONE_NUMBER` (PhoneRecognizer) | Presidio uses `phonenumbers` library which handles AU. Consider if our custom patterns add value (partial numbers, specific formats) |

## Recommended Actions

### 1. Remove Redundant Custom Recognizers
Remove from `file_processor.py`:
- `_create_tfn_recognizer()` 
- `_create_medicare_recognizer()`
- `_create_abn_recognizer()`
- `_create_acn_recognizer()`

### 2. Use Presidio Built-in Recognizers Instead
Update `_initialize_analyzer()` to rely on Presidio's default registry:
```python
# Presidio loads these automatically:
# - AuTfnRecognizer
# - AuMedicareRecognizer  
# - AuAbnRecognizer
# - AuAcnRecognizer
# - CreditCardRecognizer
# - EmailRecognizer
# - IpRecognizer
# - PhoneRecognizer
# - UrlRecognizer
```

### 3. Keep Unique Custom Recognizers
Keep and maintain:
- NBN Location ID (`AU_NBN_LOC_ID`)
- NBN Service ID (`AU_NBN_SERVICE_ID`)
- Special Phone Numbers (`AU_SPECIAL_PHONE`)
- PO Box (`AU_PO_BOX`)
- MAC Address (`MAC_ADDRESS`)
- IMEI (`IMEI`)
- ICCID (`ICCID`)
- NTD Serial (`AU_NTD_SERIAL`)

### 4. Evaluate Phone Number Handling
Consider whether:
- Presidio's `PhoneRecognizer` (using `phonenumbers` library) sufficiently handles AU formats
- Our enhanced patterns for partial numbers, parenthetical formats add value
- Keep both if they complement each other

## Code Impact

### Before (Current Implementation)
```python
# Registering custom AU recognizers (redundant)
registry.add_recognizer(self._create_tfn_recognizer())      # ❌ Remove
registry.add_recognizer(self._create_medicare_recognizer()) # ❌ Remove
registry.add_recognizer(self._create_abn_recognizer())      # ❌ Remove
registry.add_recognizer(self._create_acn_recognizer())      # ❌ Remove
```

### After (Recommended)
```python
# Presidio automatically loads AU recognizers when using:
# registry.load_predefined_recognizers()

# Only register our unique custom recognizers:
registry.add_recognizer(self._create_nbn_location_recognizer())
registry.add_recognizer(self._create_nbn_service_recognizer())
registry.add_recognizer(self._create_special_phone_recognizer())
registry.add_recognizer(self._create_po_box_recognizer())
registry.add_recognizer(self._create_mac_address_recognizer())
registry.add_recognizer(self._create_imei_recognizer())
registry.add_recognizer(self._create_iccid_recognizer())
registry.add_recognizer(self._create_ntd_serial_recognizer())
```

## Entity Type Mapping

Ensure config uses Presidio's entity type names:

| Our Entity Type | Presidio Entity Type | Action |
|-----------------|---------------------|--------|
| `AU_TFN` | `AU_TFN` | ✅ Same |
| `AU_MEDICARE` | `AU_MEDICARE` | ✅ Same |
| `AU_ABN` | `AU_ABN` | ✅ Same |
| `AU_ACN` | `AU_ACN` | ✅ Same |
| `CREDIT_CARD` | `CREDIT_CARD` | ✅ Same |
| `EMAIL` | `EMAIL_ADDRESS` | ⚠️ Update to `EMAIL_ADDRESS` |
| `PHONE` | `PHONE_NUMBER` | ⚠️ Update to `PHONE_NUMBER` |
| `IP` | `IP_ADDRESS` | ⚠️ Update to `IP_ADDRESS` |

## Benefits of Using Presidio Built-ins

1. **Checksum Validation**: All Presidio AU recognizers include official checksum algorithms
2. **Maintained**: Updates come from Microsoft Presidio project
3. **Tested**: Extensive test coverage in Presidio
4. **Performance**: Optimized implementations
5. **Less Code**: Reduced maintenance burden

## Next Steps

1. [x] Review current `file_processor.py` implementation
2. [x] Remove 4 redundant recognizer methods (TFN, Medicare, ABN, ACN)
3. [x] Remove MAC_ADDRESS recognizer (per user request)
4. [x] Update entity type names in config
5. [ ] Verify Presidio predefined recognizers are loading
6. [ ] Run tests to ensure no regression
7. [ ] Update documentation

---
*Generated: Analysis of Presidio built-in recognizers vs custom implementation*
