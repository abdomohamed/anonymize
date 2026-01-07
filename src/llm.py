"""
LLM integration for second-pass PII detection.

This module provides functions to create LLM clients and detect PII using
Azure OpenAI, OpenAI, or any OpenAI-compatible API (Ollama, etc.).

Usage:
    client = create_llm_client(config)
    if client:
        matches = detect_pii_with_llm(client, text, model)
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Optional

from src.models import PIIMatch
from src.processors.pii_detection import FALSE_POSITIVE_WORDS

logger = logging.getLogger(__name__)


# Default system prompt for PII detection
DEFAULT_SYSTEM_PROMPT = """Find PII in text. Return JSON array only.

DETECT: names, addresses, partial addresses, phones, emails, australian gov IDs, NBN codes (AVC/LOC)

IGNORE: dates (unless DOB), account/case numbers, [BRACKETS_REDACTED] content

Return ONLY sensitive value, not context. Example: "medicare 2123456701" → v="2123456701"

Format: [{"t":"TYPE","v":"value"}]
Empty: []"""


def _resolve_env(value: str) -> str:
    """Resolve $VAR and ${VAR} references in config values."""
    if not value:
        return value
    return os.path.expandvars(value)


def create_llm_client(config: dict[str, Any]) -> Optional[Any]:
    """
    Create OpenAI client based on config. Works for Azure, OpenAI, and compatible APIs.
    
    Create ONCE and reuse for all texts - enables connection pooling and prompt caching.
    Built-in retry with exponential backoff for rate limits (429) and server errors (5xx).
    
    Args:
        config: LLM configuration dictionary with keys:
            - enabled: bool - Whether LLM detection is enabled
            - base_url: str - API base URL (Azure, OpenAI, or compatible)
            - api_key: str - API key (can use ${ENV_VAR} syntax)
            - settings.max_retries: int - Max retry attempts (default: 3)
            - settings.timeout: float - Request timeout in seconds (default: 30)
    
    Returns:
        OpenAI client instance or None if disabled/unavailable
    """
    if not config.get('enabled', False):
        return None
    
    try:
        from openai import OpenAI
    except ImportError:
        logger.warning("openai package not installed. Install with: pip install 'anonymize[llm]'")
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
            credential = DefaultAzureCredential()
            token_provider = get_bearer_token_provider(
                credential,
                "https://cognitiveservices.azure.com/.default"
            )
            logger.debug("Using Azure managed identity for LLM authentication")
            return OpenAI(
                base_url=base_url,
                api_key=token_provider,
                max_retries=max_retries,
                timeout=timeout,
            )
        except Exception as e:
            if not api_key:
                logger.error(f"Managed identity failed and no api_key configured: {e}")
                return None
            logger.warning(f"Managed identity failed, falling back to api_key: {e}")
    
    # Standard OpenAI or compatible API with API key
    if not api_key and not base_url:
        logger.warning("No api_key or base_url configured for LLM")
        return None
    
    return OpenAI(
        base_url=base_url,
        api_key=api_key or "not-needed",  # Some local APIs don't require a key
        max_retries=max_retries,
        timeout=timeout,
    )


def detect_pii_with_llm(
    client: Any,
    text: str,
    model: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> list[PIIMatch]:
    """
    Detect PII in a single text using LLM.
    
    Args:
        client: OpenAI client (works for Azure, OpenAI, Ollama, etc.)
        text: Text to analyze
        model: Model/deployment name
        system_prompt: System instructions for PII detection
        
    Returns:
        List of PIIMatch objects with detected PII
    """
    CONFIDENCE = 0.85  # LLM detections - consistent confidence score
    
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
        logger.debug(f"Failed to parse LLM response as JSON: {content[:100]}")
        results = []
    
    # Entity types that should be filtered for false positives
    FILTERABLE_TYPES = {'PERSON', 'ORGANIZATION', 'LOCATION', 'ORG', 'NRP', 'GPE'}
    
    # Convert to PIIMatch objects
    matches = []
    for result in results:
        value = result.get("v") or result.get("value")
        pii_type = result.get("t") or result.get("type")
        
        if not value or not pii_type:
            continue
        
        # Normalize type for comparison
        normalized_type = pii_type.upper().replace(" ", "_").replace("-", "_")
        
        # Filter false positives for name/org/location types
        if normalized_type in FILTERABLE_TYPES:
            value_lower = value.lower()
            words = value_lower.split()
            # Skip if any word is a known false positive
            if any(word in FALSE_POSITIVE_WORDS for word in words):
                logger.debug(f"LLM false positive filtered: '{value}' ({pii_type})")
                continue
        
        # Find position in text (returns actual span for flexible matches)
        start, end = _find_position(value, text)
        if start == -1:
            logger.debug(f"LLM detected '{value}' but couldn't find position in text")
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


def _find_position(value: str, text: str) -> tuple[int, int]:
    """
    Find position of value in text with flexible matching.
    
    Tries exact match first, then case-insensitive, then flexible whitespace.
    
    Args:
        value: The value to find
        text: The text to search in
        
    Returns:
        Tuple of (start, end) positions or (-1, -1) if not found
    """
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
    client: Any,
    texts: list[str],
    model: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    request_delay: float = 0.0
) -> list[list[PIIMatch]]:
    """
    Process multiple texts for PII detection using LLM.
    
    Reuses client for connection pooling and prompt caching benefits.
    
    Args:
        client: OpenAI client (create ONCE, reuse for all texts)
        texts: List of texts to analyze
        model: Model/deployment name
        system_prompt: System instructions (cached server-side by Azure)
        request_delay: Seconds between requests for rate limiting
        
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

def create_async_llm_client(config: dict[str, Any]) -> Optional[Any]:
    """
    Create async OpenAI client for concurrent requests.

    Args:
        config: LLM configuration dictionary

    Returns:
        AsyncOpenAI client instance or None if disabled/unavailable
    """
    if not config.get('enabled', False):
        return None

    try:
        from openai import AsyncOpenAI
    except ImportError:
        logger.warning("openai package not installed. Install with: pip install 'anonymize[llm]'")
        return None

    settings = config.get('settings', {})
    max_retries = settings.get('max_retries', 3)
    timeout = settings.get('timeout', 30.0)

    base_url = _resolve_env(config.get('base_url', '')) or None
    api_key = _resolve_env(config.get('api_key', ''))

    # Auto-detect Azure and get token (async client needs actual token, not provider)
    if base_url and 'azure' in base_url.lower():
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            # Get actual token for async client (token provider doesn't work with async)
            token = credential.get_token("https://cognitiveservices.azure.com/.default")
            api_key = token.token
            logger.debug("Using Azure managed identity token for async LLM client")
        except Exception as e:
            if not api_key:
                logger.error(f"Managed identity failed and no api_key configured: {e}")
                return None
            logger.warning(f"Managed identity failed, falling back to api_key: {e}")

    if not api_key and not base_url:
        logger.warning("No api_key or base_url configured for LLM")
        return None

    return AsyncOpenAI(
        base_url=base_url,
        api_key=api_key or "not-needed",
        max_retries=max_retries,
        timeout=timeout,
    )


async def _detect_pii_async(
    client: Any,
    text: str,
    index: int,
    model: str,
    system_prompt: str,
    semaphore: asyncio.Semaphore,
    on_start: callable = None,
) -> tuple[int, list[PIIMatch]]:
    """
    Async PII detection for a single text with semaphore rate limiting.

    Args:
        client: AsyncOpenAI client
        text: Text to analyze
        index: Original index in the batch
        model: Model/deployment name
        system_prompt: System instructions
        semaphore: Semaphore for concurrency control
        on_start: Callback when request starts (after acquiring semaphore)

    Returns:
        Tuple of (index, matches)
    """
    CONFIDENCE = 0.85

    # Skip empty or fully-redacted texts
    if not text.strip() or re.fullmatch(r'[\s\[\]A-Z_]*', text):
        return index, []

    async with semaphore:
        # Signal request is now active (acquired semaphore)
        if on_start:
            on_start()
            
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text}
                ]
            )

            content = response.choices[0].message.content.strip()

            # Parse JSON from response
            try:
                if content.startswith("```"):
                    match = re.search(r'\[.*?\]', content, re.DOTALL)
                    if match:
                        content = match.group(0)

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

            return index, matches

        except Exception as e:
            logger.error(f"Record {index} failed: {e}")
            return index, []


async def _detect_pii_batch_async(
    client: Any,
    texts: list[str],
    model: str,
    system_prompt: str,
    max_concurrent: int,
    show_progress: bool = True,
) -> list[list[PIIMatch]]:
    """
    Async batch processing with concurrency control and progress bar.

    Args:
        client: AsyncOpenAI client
        texts: List of texts to analyze
        model: Model/deployment name
        system_prompt: System instructions
        max_concurrent: Maximum concurrent requests
        show_progress: Show progress bar

    Returns:
        List of PIIMatch lists, one per input text
    """
    from tqdm import tqdm

    semaphore = asyncio.Semaphore(max_concurrent)
    
    # Track sent/received for dual progress
    sent_count = [0]  # Use list to allow mutation in closure
    
    def on_request_start():
        sent_count[0] += 1

    tasks = [
        _detect_pii_async(client, text, i, model, system_prompt, semaphore, on_request_start)
        for i, text in enumerate(texts)
    ]

    # Use as_completed for progress tracking
    results_dict = {}

    if show_progress:
        # Suppress verbose HTTP/Azure logging during progress bar
        noisy_loggers = ['httpx', 'azure', 'openai', 'httpcore']
        saved_levels = {}
        for name in noisy_loggers:
            log = logging.getLogger(name)
            saved_levels[name] = log.level
            log.setLevel(logging.WARNING)

        try:
            with tqdm(total=len(tasks), desc="LLM Pass 2", unit="texts",
                      dynamic_ncols=True, leave=True,
                      bar_format='{l_bar}{bar:40}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}') as pbar:
                pbar.set_postfix_str("⬆0 ⬇0")
                for coro in asyncio.as_completed(tasks):
                    index, matches = await coro
                    results_dict[index] = matches
                    pbar.update(1)
                    in_flight = sent_count[0] - pbar.n
                    pbar.set_postfix_str(f"⬆{sent_count[0]} ⬇{pbar.n} ({in_flight} in-flight)")
        finally:
            # Restore logging levels
            for name, level in saved_levels.items():
                logging.getLogger(name).setLevel(level)
    else:
        for coro in asyncio.as_completed(tasks):
            index, matches = await coro
            results_dict[index] = matches

    # Return in original order
    return [results_dict[i] for i in range(len(texts))]


def detect_pii_batch_concurrent(
    config: dict[str, Any],
    texts: list[str],
    max_concurrent: int = 50,
    show_progress: bool = True,
) -> list[list[PIIMatch]]:
    """
    Process multiple texts concurrently for PII detection using LLM.

    With 1000 RPM limit, max_concurrent=50 gives ~20 req/sec throughput.

    Args:
        config: LLM configuration dictionary
        texts: List of texts to analyze
        max_concurrent: Maximum concurrent requests (default: 50)
        show_progress: Show progress information

    Returns:
        List of PIIMatch lists, one per input text
    """
    import asyncio

    # Suppress verbose Azure/HTTP logging during LLM client creation
    noisy_loggers = ['azure', 'azure.identity', 'azure.core', 'httpx', 'httpcore']
    saved_levels = {}
    for name in noisy_loggers:
        log = logging.getLogger(name)
        saved_levels[name] = log.level
        log.setLevel(logging.ERROR)

    try:
        client = create_async_llm_client(config)
    finally:
        # Restore logging levels
        for name, level in saved_levels.items():
            logging.getLogger(name).setLevel(level)

    if not client:
        return [[] for _ in texts]

    model = config.get('model', 'gpt-4o-mini')
    system_prompt = config.get('system_prompt') or DEFAULT_SYSTEM_PROMPT

    # Filter out empty texts but keep track of indices
    non_empty_indices = []
    non_empty_texts = []
    for i, text in enumerate(texts):
        if text.strip() and not re.fullmatch(r'[\s\[\]A-Z_]*', text):
            non_empty_indices.append(i)
            non_empty_texts.append(text)

    if show_progress:
        print(f"Pass 2: LLM ({len(non_empty_texts)} texts, {max_concurrent} concurrent)...")

    if not non_empty_texts:
        return [[] for _ in texts]

    # Run async batch
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    async_results = loop.run_until_complete(
        _detect_pii_batch_async(client, non_empty_texts, model, system_prompt, max_concurrent, show_progress)
    )

    # Map results back to original indices
    results = [[] for _ in texts]
    for orig_idx, matches in zip(non_empty_indices, async_results):
        results[orig_idx] = matches

    return results
