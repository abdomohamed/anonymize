# PII Anonymization Tool

Detect and anonymize Personally Identifiable Information (PII) in text files using **Microsoft Presidio**.

## Features

- 🔍 **30+ PII types detected**: emails, phones, SSNs, credit cards, IPs, names, and more
- 🎭 **4 anonymization strategies**: redact, mask, replace, hash
- ⚙️ **Configurable**: YAML config, confidence thresholds, whitelists
- 📦 **Batch processing**: single files or entire directories
- 📝 **Audit logs**: JSON audit trails for compliance

## Distribution Options

### Option 1: Standalone Executable (Recommended for Restricted Environments)

If you need to distribute this tool to users who cannot install Python or download packages, you can build a standalone executable. See **[BUILD_DISTRIBUTION.md](BUILD_DISTRIBUTION.md)** for detailed instructions.

**Quick build:**
```bash
./build.sh           # Linux/macOS
# or
.\build.ps1          # Windows
```

This creates a single executable file in `dist/` that can be shared and run without any installation!

### Option 2: Standard Installation

### Quick Setup (Recommended)

**Requirements:** Python 3.9+

```bash
# Clone the repository
git clone https://github.com/abdomohamed/anonymize.git
cd anonymize

# Run setup script (installs UV, dependencies, and spaCy model)
./setup.sh
```

The setup script automatically:
- ✅ Checks Python installation
- ✅ Installs [UV](https://github.com/astral-sh/uv) if not present (10-100x faster than pip)
- ✅ Installs all dependencies via `uv sync`
- ✅ Downloads spaCy English language model

### Manual Installation

**With UV (recommended):**
```bash
uv sync
```

**With pip:**
```bash
pip install -e .
```

### Run the Tool

```bash
# Using UV (recommended)
uv run anonymize input.txt -o output.txt

# Or with pip installation
python -m src.cli input.txt -o output.txt
```

## Usage Examples

### Different Strategies

```bash
# Masking (partial visibility)
uv run anonymize input.txt --strategy mask
# Output: j***@company.com, 555-***-****

# Fake data replacement
uv run anonymize input.txt --strategy replace
# Output: jane.smith@example.org, 555-987-6543

# Consistent hashing
uv run anonymize input.txt --strategy hash
# Output: EMAIL_a3f5d9e1, PHONE_b7c2e4f6
```

### Batch Processing

```bash
# Process directory
uv run anonymize input_dir/ -o output_dir/ --dir --recursive
```

### Selective Detection

```bash
# Specific entity types only
uv run anonymize input.txt --entities EMAIL_ADDRESS PHONE_NUMBER

# Adjust confidence threshold
uv run anonymize input.txt --confidence 0.8
```

## Configuration

Create `my_config.yaml`:

```yaml
detection:
  confidence_threshold: 0.8
  enabled_entities:
    - EMAIL_ADDRESS
    - PHONE_NUMBER
    - US_SSN

anonymization:
  strategy: "mask"

whitelist:
  emails:
    - "noreply@company.com"
```

Use it:
```bash
uv run anonymize input.txt -c my_config.yaml
```

## Example Output

**Input:**
```
Contact: john.doe@company.com
Phone: 555-123-4567
```

**Redacted:**
```
Contact: [EMAIL_ADDRESS_REDACTED]
Phone: [PHONE_NUMBER_REDACTED]
His SSN is [SSN_REDACTED].
```

### Example 2: Masking

**Command:**
```bash
python -m src.cli input.txt --strategy mask
```

**Output:**
```
Contact John Doe at j***@company.com or call 555-***-****.
His SSN is ***-**-6789.
```

### Example 3: With Whitelist

**Config:**
```yaml
whitelist:
  emails:
    - "support@company.com"
```

**Input:**
```
Contact john@company.com or support@company.com
```

**Output:**
```
Contact [EMAIL_REDACTED] or support@company.com
```

## Command-Line Reference

```
usage: cli.py [-h] [-o OUTPUT] [--dir] [-r] [-c CONFIG]
              [--strategy {redact,mask,replace,hash}]
              [--detectors {email,phone,ssn,credit_card,ip_address,name} ...]
              [--confidence CONFIDENCE] [--no-audit] [--backup] [-v]
              [--version]
              input

PII Anonymization Tool

positional arguments:
  input                 Input file or directory path

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file or directory path
  --dir                 Process directory instead of single file
  -r, --recursive       Process directories recursively
  -c CONFIG, --config CONFIG
                        Path to custom configuration file (YAML)
  --strategy {redact,mask,replace,hash}
                        Anonymization strategy to use
  --detectors DETECTORS [DETECTORS ...]
                        Specific detectors to enable
  --confidence CONFIDENCE
                        Confidence threshold for detection (0.0-1.0)
  --no-audit            Disable audit log generation
  --backup              Create backup of original file
  -v, --verbose         Enable verbose output
  --version             show program's version number and exit
```

## Testing

Run the test suite:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_detectors.py -v
```

**Masked:**
```
Contact: j*********************
Phone: 555-***-****
```

## Detected PII Types

Presidio detects 30+ entity types including:
- EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD
- US_SSN, US_PASSPORT, US_DRIVER_LICENSE
- IP_ADDRESS, CRYPTO, IBAN_CODE
- PERSON names, LOCATION, DATE_TIME
- [Full list](https://microsoft.github.io/presidio/supported_entities/)

## UV Commands

```bash
# Install with dev dependencies
uv sync --all-extras

# Add new dependency
uv add <package-name>

# Update dependencies
uv lock --upgrade

# Run tests
uv run pytest

# Format/lint code
uv run black src/
uv run ruff check src/
```

## Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Comprehensive usage examples
- **[docs/ai/design_pii_anonymization.md](docs/ai/design_pii_anonymization.md)** - Technical design

## Troubleshooting

**No PII detected?** Lower confidence threshold:
```bash
uv run anonymize input.txt --confidence 0.6
```

**Too many false positives?** Increase confidence or use whitelist:
```bash
uv run anonymize input.txt --confidence 0.85
```

**Setup issues?** Run the setup script again:
```bash
./setup.sh
```

This will:
- Install UV if missing
- Sync all dependencies
- Download spaCy model

**Import errors?**
```bash
uv sync --reinstall
```

## License

MIT License

---

Built with [Microsoft Presidio](https://microsoft.github.io/presidio/) • Python 3.9+ • Fast installation with [UV](https://github.com/astral-sh/uv)
