# PII Anonymization Tool

Detect and anonymize Personally Identifiable Information (PII) in text files using **Microsoft Presidio**.

## Features

- 🔍 **30+ PII types detected**: emails, phones, SSNs, credit cards, IPs, names, and more
- 🎭 **4 anonymization strategies**: redact, mask, replace, hash
- ⚙️ **Configurable**: YAML config, confidence thresholds, whitelists
- 📦 **Batch processing**: single files or entire directories
- 📝 **Audit logs**: JSON audit trails for compliance

## Distribution Options

### Option 1: Dev Container (Recommended for Development)

The fastest way to get started is using the included **Dev Container**, which provides a fully configured development environment with all dependencies pre-installed.

**Requirements:** [VS Code](https://code.visualstudio.com/) + [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) + Docker

```bash
# Clone and open in VS Code
git clone https://github.com/abdomohamed/anonymize.git
code anonymize
```

When prompted, click **"Reopen in Container"** (or use Command Palette → "Dev Containers: Reopen in Container").

The dev container automatically:
- ✅ Installs Python, UV, Git, GitHub CLI, Azure CLI, Docker
- ✅ Installs all dependencies on startup (`uv sync --all-extras`)
- ✅ Configures VS Code extensions (Python, Pylance, Copilot, etc.)
- ✅ Sets up testing integration

You're ready to go immediately after the container builds!

### Option 2: Standalone Executable (Recommended for Restricted Environments)

If you need to distribute this tool to users who cannot install Python or download packages, you can build a standalone executable. See **[BUILD_DISTRIBUTION.md](BUILD_DISTRIBUTION.md)** for detailed instructions.

**Quick build:**
```bash
./build.sh           # Linux/macOS
# or
.\build.ps1          # Windows
```

This creates a single executable file in `dist/` that can be shared and run without any installation!

### Option 3: Standard Installation

### Quick Setup

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

### CSV Processing

Process CSV files with specific columns containing PII:

```bash
# Process specific columns in a CSV
uv run anonymize data.csv --csv --columns notes email_body -o anonymized.csv

# Process all text columns
uv run anonymize data.csv --csv -o anonymized.csv

# Use multiple workers for large files (parallel processing)
uv run anonymize large_data.csv --csv --columns CommentBody --workers 4

# Single-threaded processing (useful for debugging)
uv run anonymize data.csv --csv --single-threaded
```

**CSV Features:**
- 🚀 **Parallel processing**: Use `--workers N` to process large files faster
- 📊 **Selective columns**: Only anonymize columns you specify with `--columns`
- 📈 **Progress bar**: Visual progress for large datasets (disable with `--no-progress`)
- ✅ **Preserves structure**: All other columns remain unchanged

**Example:**

Input CSV (`customers.csv`):
```csv
id,name,notes,created_at
1,John,Call from john@email.com about billing,2024-01-15
2,Jane,Customer phone: 555-123-4567,2024-01-16
```

Command:
```bash
uv run anonymize customers.csv --csv --columns notes -o customers_safe.csv
```

Output CSV (`customers_safe.csv`):
```csv
id,name,notes,created_at
1,John,Call from [EMAIL_ADDRESS_REDACTED] about billing,2024-01-15
2,Jane,Customer phone: [PHONE_NUMBER_REDACTED],2024-01-16
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

## LLM Second Pass (Optional)

The tool supports an optional LLM-powered second pass that catches PII missed by Presidio/spaCy. This is especially useful for:
- Context-dependent PII (partial addresses, names in unusual formats)
- Domain-specific identifiers (NBN service IDs, telecom codes)
- Edge cases that rule-based detection misses

### Enabling LLM Detection

Add `--llm` flag to enable the second pass:

```bash
# Enable LLM second pass
uv run anonymize data.csv --csv --columns notes --llm -o output.csv
```

### Configuration

#### Option 1: Environment Variables (Recommended)

Create a `.env` file in your project root:

```bash
# For Azure OpenAI with Managed Identity (recommended for Azure)
OPENAI_ENDPOINT=https://your-resource.openai.azure.com/openai/v1

# For Azure OpenAI with API Key (fallback if managed identity fails)
OPENAI_ENDPOINT=https://your-resource.openai.azure.com/openai/v1
OPENAI_API_KEY=your-api-key

# For OpenAI API directly
OPENAI_API_KEY=sk-your-api-key

# For local models (Ollama, etc.)
OPENAI_ENDPOINT=http://localhost:11434/v1
```

#### Option 2: Configuration File

Edit `config/default_config.yaml`:

```yaml
llm_detection:
  enabled: true

  # Azure OpenAI (managed identity auto-detected from 'azure' in URL)
  base_url: "${OPENAI_ENDPOINT}"
  model: "gpt-4o-mini"

  # API key (used as fallback if managed identity fails)
  api_key: "${OPENAI_API_KEY}"

  settings:
    max_concurrent: 750    # Concurrent requests for batch processing
    max_retries: 3
    timeout: 30
```

### Authentication Methods

| Provider | Configuration | Notes |
|----------|--------------|-------|
| **Azure OpenAI (Managed Identity)** | Set `base_url` containing "azure" | Auto-detected, no API key needed |
| **Azure OpenAI (API Key)** | Set `base_url` + `api_key` | Fallback if MI fails |
| **OpenAI** | Set `api_key` only | Uses default OpenAI endpoint |
| **Local (Ollama)** | Set `base_url` to local endpoint | No API key required |

### Azure Managed Identity Setup

For Azure deployments, managed identity is the most secure option:

1. **Enable managed identity** on your compute (VM, Container App, etc.)
2. **Grant access** to your Azure OpenAI resource:
   - Go to Azure OpenAI resource → Access Control (IAM)
   - Add role assignment: "Cognitive Services OpenAI User"
   - Assign to your managed identity
3. **Configure endpoint** in `.env`:
   ```bash
   OPENAI_ENDPOINT=https://your-resource.openai.azure.com/openai/v1
   ```

The tool will automatically use managed identity when it detects "azure" in the URL.

### Local Development with Azure

When developing locally (including in the dev container), you need to authenticate with Azure CLI for managed identity to work:

```bash
# Login to Azure (opens browser for authentication)
az login

# Verify you're logged in
az account show
```

The `DefaultAzureCredential` used by the tool will automatically pick up your Azure CLI credentials when running locally. In production (Azure VMs, Container Apps, etc.), it uses the actual managed identity instead.

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
usage: anonymize [-h] [-o OUTPUT] [--dir] [-r] [--csv] [--columns COLUMNS ...]
                 [--workers WORKERS] [--single-threaded] [--no-progress]
                 [--llm] [-c CONFIG] [--strategy {redact,mask,replace,hash}]
                 [--entities ENTITIES ...] [--confidence CONFIDENCE]
                 [--no-audit] [--backup] [-v] [--version]
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
  --csv                 Process input as CSV file
  --columns COLUMNS ... CSV columns to process (default: all columns)
  --workers WORKERS     Number of parallel workers for CSV (default: CPU cores)
  --single-threaded     Disable multiprocessing, use single thread
  --no-progress         Disable progress bar
  --llm                 Enable LLM second pass for additional PII detection
  -c CONFIG, --config CONFIG
                        Path to custom configuration file (YAML)
  --strategy {redact,mask,replace,hash}
                        Anonymization strategy to use
  --entities ENTITIES ...
                        Specific entity types to detect
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
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_llm.py -v
```

You can also use VS Code's Test Explorer - tests are configured to use the `.venv` created by `uv sync`.

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
