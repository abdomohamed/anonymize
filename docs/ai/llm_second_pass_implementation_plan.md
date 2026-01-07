# LLM Second-Pass PII Detection - Implementation Plan

## Overview

This document outlines the plan to implement LLM-based second-pass PII detection as validated in `test_azure_pipeline.py`. The feature will provide an optional secondary detection pass using LLM models to catch PII that the primary spaCy/Presidio pass may have missed.

**Status**: Implemented  
**Date**: January 7, 2026  
**Validated by**: `test_azure_pipeline.py` proof of concept

---

## Goals

1. **Catch missed PII**: LLM second pass detects PII that spaCy/regex patterns miss
2. **Flexible providers**: Support Azure OpenAI, OpenAI, and OpenAI-compatible APIs (Ollama, etc.)
3. **Zero config for Azure**: Auto-detect managed identity from URL
4. **Simple**: One file, three functions, no classes

---

## Architecture

### Component Structure

```
src/
├── llm.py                        # NEW: Single file - client creation + PII detection
├── processors/
│   ├── pii_detection.py          # MODIFY: Add LLM second pass integration
│   └── ...
└── config/
    └── config_manager.py         # MODIFY: Add LLM config loading
```

One file. Two main functions. No class hierarchy for calling an API.

### Data Flow

```
text → spaCy → redact → LLM → redact → done
```

---

## Configuration Schema

Add to `config/default_config.yaml`:

```yaml
# LLM Second-Pass Detection (Optional)
llm_detection:
  # Enable/disable LLM second pass
  enabled: false
  
  # Base URL for API (determines provider)
  # Azure:    https://your-resource.openai.azure.com/openai/v1
  # OpenAI:   https://api.openai.com/v1  (or omit for default)
  # Ollama:   http://localhost:11434/v1
  # Note: If URL contains 'azure', managed identity is tried first automatically
  base_url: "${AZURE_OPENAI_ENDPOINT}/openai/v1"
  
  # Model or deployment name
  model: "gpt-4o-mini"
  
  # API key (for Azure: falls back to this if managed identity fails)
  api_key: "${OPENAI_API_KEY}"
  
  # Detection Settings
  settings:
    # Delay between API calls (seconds) - additional rate limiting
    request_delay: 0.1
    
    # Maximum retries on failure (built into openai client)
    max_retries: 3
    
    # Timeout per request (seconds)
    timeout: 30

  # System prompt for PII detection
  system_prompt: |
    Find PII in text. Return JSON array only.
    
    DETECT: names, addresses, partial addresses, phones, emails, australian gov IDs, NBN codes (AVC/LOC)
    
    IGNORE: dates (unless DOB), account/case numbers, [BRACKETS_REDACTED] content
    
    Return ONLY sensitive value, not context. Example: "medicare 2123456701" → v="2123456701"
    
    Format: [{"t":"TYPE","v":"value"}]
    Empty: []
```

---

## Implementation Details

### The Entire LLM Module (`src/llm.py`)

```python
"""LLM integration for second-pass PII detection. One file. Three functions."""

import json
import logging
import os
import re
import time
from typing import Dict, Any, List, Optional, Tuple

from openai import OpenAI
from src.models import PIIMatch

logger = logging.getLogger(__name__)


# Default system prompt
DEFAULT_SYSTEM_PROMPT = """Find PII in text. Return JSON array only.

DETECT: names, addresses, partial addresses, phones, emails, australian gov IDs, NBN codes (AVC/LOC)

IGNORE: dates (unless DOB), account/case numbers, [BRACKETS_REDACTED] content

Return ONLY sensitive value, not context. Example: "medicare 2123456701" → v="2123456701"

Format: [{"t":"TYPE","v":"value"}]
Empty: []"""


def _resolve_env(value: str) -> str:
    """Resolve $VAR and ${VAR} references in config values."""
    return os.path.expandvars(value) if value else value


def create_llm_client(config: Dict[str, Any]) -> Optional[OpenAI]:
    """
    Create OpenAI client based on config. Works for Azure, OpenAI, and compatible APIs.
    Create ONCE and reuse for all texts - enables connection pooling and prompt caching.
    
    Built-in retry with exponential backoff for rate limits (429) and server errors (5xx).
    """
    if not config.get('enabled', False):
        return None
    
    settings = config.get('settings', {})
    max_retries = settings.get('max_retries', 3)
    timeout = settings.get('timeout', 30.0)
    
    base_url = _resolve_env(config.get('base_url', '')) or None
    api_key = _resolve_env(config.get('api_key', ''))
    
    # Auto-detect Azure and try managed identity first
    if base_url and 'azure' in base_url.lower():
        try:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            api_key = get_bearer_token_provider(
                DefaultAzureCredential(), 
                "https://cognitiveservices.azure.com/.default"
            )
        except Exception as e:
            if not api_key:
                raise ValueError(f"Managed identity failed and no api_key configured: {e}")
            logger.warning(f"Managed identity failed, falling back to api_key: {e}")
    
    return OpenAI(
        base_url=base_url,
        api_key=api_key,
        max_retries=max_retries,
        timeout=timeout,
    )


def detect_pii_with_llm(
    client: OpenAI,
    text: str,
    model: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> List[PIIMatch]:
    """
    Detect PII in a single text using LLM.
    
    Args:
        client: OpenAI client (works for Azure, OpenAI, Ollama, etc.)
        text: Text to analyze
        model: Model/deployment name
        system_prompt: System instructions
        
    Returns:
        List of PIIMatch objects
    """
    CONFIDENCE = 0.85  # LLM detections - not tunable, it's a made-up number
    # Call LLM
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text}
        ]
    )
    
    content = response.choices[0].message.content.strip()
    
    # Parse JSON from response
    try:
        # Handle markdown code blocks
        if content.startswith("```"):
            match = re.search(r'\[.*?\]', content, re.DOTALL)
            if match:
                content = match.group(0)
        
        # Find JSON array
        match = re.search(r'\[.*\]', content, re.DOTALL)
        results = json.loads(match.group(0)) if match else []
    except (json.JSONDecodeError, AttributeError):
        results = []
    
    # Convert to PIIMatch objects
    matches = []
    for result in results:
        value = result.get("v") or result.get("value")
        pii_type = result.get("t") or result.get("type")
        
        if not value or not pii_type:
            continue
        
        # Find position in text (returns actual span for flexible matches)
        start, end = _find_position(value, text)
        if start == -1:
            continue
        
        matches.append(PIIMatch(
            pii_type=pii_type.upper().replace(" ", "_").replace("-", "_"),
            value=text[start:end],
            start=start,
            end=end,
            confidence=CONFIDENCE,
            context=text[max(0, start-20):end+20],
            detector_name="LLM"
        ))
    
    return matches


def _find_position(value: str, text: str) -> Tuple[int, int]:
    """Find position of value in text. Returns (start, end) or (-1, -1)."""
    # Exact match
    start = text.find(value)
    if start != -1:
        return start, start + len(value)
    
    # Case-insensitive
    start = text.lower().find(value.lower())
    if start != -1:
        return start, start + len(value)
    
    # Flexible whitespace (e.g., "0412345678" matches "0412 345 678")
    pattern = r'\s*'.join(re.escape(c) for c in value if not c.isspace())
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.start(), match.end()  # Actual span, not assumed length
    
    return -1, -1


def detect_pii_batch(
    client: OpenAI,
    texts: List[str],
    model: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    request_delay: float = 0.0
) -> List[List[PIIMatch]]:
    """
    Process multiple texts. Reuses client for connection pooling and prompt caching.
    
    Args:
        client: OpenAI client (create ONCE, reuse for all texts)
        texts: List of texts to analyze
        model: Model/deployment name
        system_prompt: System instructions (cached server-side by Azure)
        request_delay: Seconds between requests (rate limiting)
        
    Returns:
        List of PIIMatch lists, one per input text
    """
    results = []
    
    for i, text in enumerate(texts):
        # Skip empty or fully-redacted texts (don't waste API calls)
        if not text.strip() or re.fullmatch(r'[\s\[\]A-Z_]*', text):
            results.append([])
            continue
        
        try:
            matches = detect_pii_with_llm(client, text, model, system_prompt)
            results.append(matches)
        except Exception as e:
            # Client already retried - log and continue (don't crash the batch)
            logger.error(f"Record {i} failed after retries: {e}")
            results.append([])
        
        # Additional rate limiting between requests (not after last one)
        if request_delay and i < len(texts) - 1:
            time.sleep(request_delay)
    
    return results
```

That's it. ~170 lines. Three functions. No classes.

**Built-in from openai library:**
- Retry on 429 (rate limited) with exponential backoff
- Retry on 5xx (server errors)
- Parses `Retry-After` header automatically
- Configurable `max_retries` and `timeout`

### Integration with Existing Processors

The key is to create the client ONCE and process all texts through it:

```python
# In FileProcessor or CSVProcessor - process all records with one client

from src.llm import create_llm_client, detect_pii_batch

def process_with_llm_pass(self, texts: List[str], llm_config: Dict[str, Any]) -> List[str]:
    """
    Process multiple texts with spaCy + LLM second pass.
    Creates client ONCE for optimal caching and connection reuse.
    """
    from src.anonymizers.redactor import Redactor
    
    redactor = Redactor(config={})
    
    # Pass 1: spaCy/Presidio on all texts
    pass1_results = []
    for text in texts:
        matches = analyze_text_for_pii(self.analyzer, text, 'en')
        redacted = redactor.anonymize_batch(matches, text)
        pass1_results.append(redacted)
    
    # Pass 2: LLM on all partially-redacted texts (if enabled)
    client = create_llm_client(llm_config)
    if not client:
        return pass1_results
    
    # Get config
    model = llm_config.get('model', 'gpt-4o-mini')
    system_prompt = llm_config.get('system_prompt')
    delay = llm_config.get('settings', {}).get('request_delay', 0.0)
    
    # Single client, all texts - prompt caching kicks in
    all_llm_matches = detect_pii_batch(
        client=client,
        texts=pass1_results,
        model=model,
        system_prompt=system_prompt,
        request_delay=delay
    )
    
    # Apply pass 2 redactions
    final_results = []
    for text, matches in zip(pass1_results, all_llm_matches):
        final_results.append(redactor.anonymize_batch(matches, text))
    
    return final_results
```

**Why this works for prompt caching:**
1. Client created once → connection pooling
2. Same system prompt every call → Azure caches it server-side after first request
3. Sequential calls hit the cache → faster responses, lower cost

---

## CLI Integration

Add CLI options for LLM second pass:

```python
# In src/cli.py

@app.command()
def anonymize(
    # ... existing options ...
    llm_enabled: bool = typer.Option(False, "--llm", help="Enable LLM second-pass detection"),
):
    """Anonymize PII in text files."""
    # Apply CLI overrides to config
    if llm_enabled:
        cli_overrides['llm_detection'] = {'enabled': True}
```

---

## Dependencies

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
llm = [
    "openai>=1.0.0",
    "azure-identity>=1.15.0",
]
```

---

## Implementation Tasks

### Phase 1: Core LLM Module
- [x] Create `src/llm.py` (~170 lines)
- [x] Add unit tests for `create_llm_client()`
- [x] Add unit tests for `detect_pii_with_llm()`

### Phase 2: PII Detection Integration
- [x] Add `apply_llm_second_pass()` to `pii_detection.py`
- [x] Update `FileProcessor` to use LLM second pass
- [x] Update `CSVProcessor` to use LLM second pass
- [ ] Add integration tests

### Phase 3: Configuration
- [x] Add LLM config schema to `default_config.yaml`
- [x] Update `ConfigManager` to handle LLM config (uses existing deep merge)
- [x] Add config validation

### Phase 4: CLI & Documentation
- [x] Add CLI options for LLM second pass (`--llm` flag)
- [ ] Update README with LLM configuration
- [ ] Add usage examples

---

## Testing Strategy

### Unit Tests
```python
# tests/test_llm.py
def test_create_azure_client_managed_identity():
    """Test Azure OpenAI client creation with managed identity."""
    
def test_create_azure_client_api_key_fallback():
    """Test Azure OpenAI falls back to API key."""
    
def test_create_openai_client():
    """Test standard OpenAI client creation."""

def test_create_compatible_client():
    """Test OpenAI-compatible client (Ollama)."""

def test_detect_pii_parses_json():
    """Test JSON parsing from LLM response."""

def test_detect_pii_flexible_whitespace():
    """Test phone number matching with spaces."""
```

### Integration Tests
```python
# tests/test_llm_integration.py
def test_full_pipeline_with_llm():
    """Test spaCy + LLM second pass pipeline."""
    
def test_llm_catches_missed_pii():
    """Test that LLM catches PII missed by spaCy."""
```

---

## Performance Considerations

| Metric | spaCy Only | spaCy + Azure LLM |
|--------|------------|-------------------|
| Per request | ~50ms | ~200ms |
| 13K records | ~3-5 min | ~45 min (sequential) |
| Cost | Free | ~$1-3 |
| Accuracy | Good | Better |

*Tested with gpt-4o-mini on Azure at 1,000 TPM*

---

## Security Considerations

1. **Managed Identity preferred**: No API keys in config files
2. **Environment variables**: API keys should use `${VAR}` syntax
3. **Data in transit**: All providers use HTTPS
4. **Already redacted**: LLM receives partially redacted text (privacy-first)
