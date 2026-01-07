# Quick Start Usage Guide

## Installation

**With UV (recommended):**
```bash
uv sync
```

**With pip:**
```bash
pip install -e .
```

## Basic Usage Examples

### 1. Simple Anonymization (Redaction)

**Input file** (`input.txt`):
```
Customer Information
====================

Name: John Smith
Email: john.smith@company.com
Phone: (555) 123-4567
SSN: 123-45-6789
Credit Card: 4532-1488-0343-6467

Notes: Customer called from IP 203.0.113.45
Alternative contact: jane.doe@email.com
```

**Command**:
```bash
python -m src.cli input.txt -o output.txt
```

**Output** (`output.txt`):
```
Customer Information
====================

Name: [PERSON_REDACTED]
Email: [EMAIL_ADDRESS_REDACTED]
Phone: [PHONE_NUMBER_REDACTED]
SSN: [US_SSN_REDACTED]
Credit Card: [CREDIT_CARD_REDACTED]

Notes: Customer called from IP [IP_ADDRESS_REDACTED]
Alternative contact: [EMAIL_ADDRESS_REDACTED]
```

---

### 2. Masking Strategy (Partial Visibility)

**Command**:
```bash
python -m src.cli input.txt -o output.txt --strategy mask
```

**Output**:
```
Customer Information
====================

Name: John Smith
Email: j***@company.com
Phone: 555-***-****
SSN: ***-**-6789
Credit Card: ****-****-****-6467

Notes: Customer called from IP 203.***.***.**
Alternative contact: j***@email.com
```

---

### 3. Fake Data Replacement

**Command**:
```bash
python -m src.cli input.txt -o output.txt --strategy replace
```

**Output**:
```
Customer Information
====================

Name: Jane Wilson
Email: michael.brown@example.org
Phone: (555) 789-4561
SSN: 987-65-4321
Credit Card: 5105-1051-0510-5100

Notes: Customer called from IP 198.51.100.42
Alternative contact: sarah.jones@example.net
```

---

### 4. Consistent Hashing

**Command**:
```bash
python -m src.cli input.txt -o output.txt --strategy hash
```

**Output**:
```
Customer Information
====================

Name: PERSON_a3f5d9e1
Email: EMAIL_ADDRESS_b7c2e4f6
Phone: PHONE_NUMBER_c8d3f5a2
SSN: US_SSN_d9e4g6b3
Credit Card: CREDIT_CARD_e1f7h8c4

Notes: Customer called from IP IP_ADDRESS_f2g8i9d5
Alternative contact: EMAIL_ADDRESS_g3h9j1e6
```

*Note: Same values get same hash (e.g., same email appears twice → same hash)*

---

## Advanced Usage

### Select Specific Entity Types

Only anonymize emails and phones:
```bash
python -m src.cli input.txt --entities EMAIL_ADDRESS PHONE_NUMBER
```

### Adjust Confidence Threshold

Increase accuracy (fewer false positives):
```bash
python -m src.cli input.txt --confidence 0.85
```

Lower threshold (catch more potential PII):
```bash
python -m src.cli input.txt --confidence 0.6
```

### Process Entire Directory

```bash
# Process all .txt files in a directory
python -m src.cli input_dir/ -o output_dir/ --dir

# Process recursively
python -m src.cli input_dir/ -o output_dir/ --dir --recursive
```

### Custom Configuration

Create `my_config.yaml`:
```yaml
detection:
  language: "en"
  confidence_threshold: 0.8
  enabled_entities:
    - EMAIL_ADDRESS
    - PHONE_NUMBER
    - US_SSN

anonymization:
  strategy: "mask"
  mask:
    mask_char: "*"
    email_visible_chars: 2
    phone_visible_chars: 3

whitelist:
  emails:
    - "support@company.com"
```

Use it:
```bash
python -m src.cli input.txt -c my_config.yaml
```

---

## Available Entity Types

The tool uses Microsoft Presidio, which detects:

| Entity Type | Description | Example |
|------------|-------------|---------|
| `EMAIL_ADDRESS` | Email addresses | john@example.com |
| `PHONE_NUMBER` | Phone numbers | +1-555-123-4567 |
| `CREDIT_CARD` | Credit card numbers | 4532-1234-5678-9010 |
| `US_SSN` | US Social Security | 123-45-6789 |
| `US_PASSPORT` | US Passport | 123456789 |
| `US_DRIVER_LICENSE` | Driver's License | D1234567 |
| `IP_ADDRESS` | IP addresses | 192.168.1.1 |
| `IBAN_CODE` | Bank accounts | DE89370400440532013000 |
| `CRYPTO` | Crypto wallets | 1A1zP1eP5QGefi2DMPTfTL... |
| `PERSON` | Person names | John Smith |
| `LOCATION` | Locations | New York |
| `DATE_TIME` | Dates/times | 01/01/2024 |

[See full list](https://microsoft.github.io/presidio/supported_entities/)

---

## Command Reference

```
Usage: python -m src.cli INPUT [OPTIONS]

Positional arguments:
  INPUT                 Input file or directory path

Optional arguments:
  -o, --output OUTPUT   Output file/directory (auto-generated if not specified)
  --dir                 Process directory mode
  -r, --recursive       Process directories recursively
  -c, --config CONFIG   Custom YAML configuration file
  --strategy STRATEGY   Anonymization strategy: redact/mask/replace/hash
  --entities ENTITIES   Specific entity types to detect
  --confidence FLOAT    Detection confidence threshold (0.0-1.0)
  --no-audit           Disable audit log generation
  --backup             Create backup of original file
  -v, --verbose        Verbose output
```

---

## Tips & Best Practices

### 1. **Test First**
Always test on a sample file first:
```bash
python -m src.cli sample.txt -v
```

### 2. **Review Output**
Check the anonymized file before using it:
```bash
cat output.txt
```

### 3. **Check Audit Logs**
Review what was anonymized:
```bash
cat output_anonymized_audit.json
```

### 4. **Use Whitelist for Known Safe Values**
Add to `config/default_config.yaml`:
```yaml
whitelist:
  emails:
    - "noreply@company.com"
  domains:
    - "example.com"
```

### 5. **Adjust for Your Needs**
- High security: Use `redact` strategy with `confidence: 0.85`
- Testing: Use `replace` strategy with fake data
- Analytics: Use `hash` strategy to preserve relationships

---

## Troubleshooting

**Issue**: "presidio-analyzer not installed"
```bash
Solution: pip install presidio-analyzer
```

**Issue**: "spaCy model not found"
```bash
Solution: uv sync  # or: pip install -e .
```

**Issue**: No PII detected
```bash
Solution: Lower confidence threshold
python -m src.cli input.txt --confidence 0.6
```

**Issue**: Too many false positives
```bash
Solution: Increase confidence threshold
python -m src.cli input.txt --confidence 0.85
```

---

## Example Workflow

```bash
# 1. Create test file
echo "Contact john@email.com or call 555-1234" > test.txt

# 2. Test with verbose output
python -m src.cli test.txt -v

# 3. Try different strategies
python -m src.cli test.txt --strategy redact -o test_redacted.txt
python -m src.cli test.txt --strategy mask -o test_masked.txt
python -m src.cli test.txt --strategy replace -o test_replaced.txt

# 4. Compare results
cat test_redacted.txt
cat test_masked.txt
cat test_replaced.txt

# 5. Process production files
python -m src.cli data/customer_info.txt -o data/customer_info_anonymized.txt
```

---

For more details, see [README.md](README.md) and [design documentation](docs/ai/design_pii_anonymization.md).
