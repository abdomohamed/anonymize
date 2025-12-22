"""
CSV processor for batch PII detection and anonymization.

This module provides high-performance CSV processing with optional
multiprocessing support for large datasets.
"""

import csv
import os
import re
import time
from dataclasses import dataclass, field
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Optional

from tqdm import tqdm

from src.models import PIIMatch
from src.utils import deduplicate_matches, merge_overlapping_matches


def _normalize_caps_for_ner(text: str) -> str:
    """
    Convert ALL CAPS word sequences to Title Case for better NER detection.

    Handles: JOHN SMITH, MARY O'BRIEN, MICHAEL SMITH-JONES
    """
    def title_case_match(match):
        return match.group(0).title()

    # Each word: 2+ letters OR apostrophe pattern (O'BRIEN) OR hyphenated (SMITH-JONES)
    pattern = r"\b(?:[A-Z]{2,}|[A-Z]'[A-Z]+|[A-Z]+-[A-Z]+)(?:\s+(?:[A-Z]{2,}|[A-Z]'[A-Z]+|[A-Z]+-[A-Z]+)){1,2}\b"
    return re.sub(pattern, title_case_match, text)


@dataclass
class CSVProcessResult:
    """Result of CSV processing operation."""
    success: bool
    input_path: str
    output_path: Optional[str] = None
    rows_processed: int = 0
    rows_failed: int = 0
    total_pii_found: int = 0
    processing_time: float = 0.0
    workers_used: int = 1
    errors: list = field(default_factory=list)


# Global processor for multiprocessing (initialized per worker)
_worker_processor = None


def _init_worker(config: dict):
    """Initialize processor in worker process."""
    global _worker_processor
    # Import here to avoid circular imports and ensure fresh instance per worker
    from src.processors.file_processor import FileProcessor
    _worker_processor = FileProcessor(config)


def _process_row_worker(args: tuple) -> tuple:
    """
    Process a single row in a worker process.

    Args:
        args: Tuple of (row_idx, row_dict, text_columns)

    Returns:
        Tuple of (row_idx, processed_row, pii_count, error)
    """
    global _worker_processor
    row_idx, row, text_columns = args

    try:
        pii_count = 0
        processed_row = row.copy()

        for col in text_columns:
            if col not in row or not row[col]:
                continue

            text = str(row[col])

            # Normalize ALL CAPS for better NER detection
            normalized_text = _normalize_caps_for_ner(text)

            # Analyze on normalized text (positions map 1:1)
            results = _worker_processor.analyzer.analyze(
                text=normalized_text,
                language='en'
            )

            if not results:
                continue

            # Convert to PIIMatch
            matches = [
                PIIMatch(
                    pii_type=r.entity_type,
                    value=text[r.start:r.end],
                    start=r.start,
                    end=r.end,
                    confidence=r.score,
                    context="",
                    detector_name="Presidio"
                )
                for r in results
            ]

            # Dedupe and merge
            matches = deduplicate_matches(matches)
            matches = merge_overlapping_matches(matches)

            pii_count += len(matches)

            # Anonymize
            processed_row[col] = _worker_processor.anonymizer.anonymize_batch(matches, text)

        return (row_idx, processed_row, pii_count, None)

    except Exception as e:
        return (row_idx, row, 0, str(e))


class CSVProcessor:
    """
    Processor for CSV files with multiprocessing support.

    Features:
    - Column-aware processing (only process specified columns)
    - Multiprocessing for large files
    - Progress bar with ETA
    - Streaming output for memory efficiency
    """

    def __init__(self, config: dict):
        """
        Initialize CSV processor.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self._processor = None  # Lazy init for single-process mode

    @property
    def processor(self):
        """Lazy-load the file processor."""
        if self._processor is None:
            from src.processors.file_processor import FileProcessor
            self._processor = FileProcessor(self.config)
        return self._processor

    def process_csv(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        text_columns: Optional[list] = None,
        workers: int = 1,
        batch_size: int = 100,
        show_progress: bool = True
    ) -> CSVProcessResult:
        """
        Process a CSV file for PII anonymization.

        Args:
            input_path: Path to input CSV file
            output_path: Path to output CSV file (auto-generated if None)
            text_columns: List of column names to process (all if None)
            workers: Number of worker processes (1 = single-threaded)
            batch_size: Rows per batch for multiprocessing
            show_progress: Show progress bar

        Returns:
            CSVProcessResult with processing statistics
        """
        start_time = time.time()
        result = CSVProcessResult(success=False, input_path=input_path)

        # Validate input
        if not os.path.exists(input_path):
            result.errors.append(f"Input file not found: {input_path}")
            return result

        # Generate output path
        if output_path is None:
            input_p = Path(input_path)
            output_path = str(input_p.parent / f"{input_p.stem}_anonymized{input_p.suffix}")
        result.output_path = output_path

        try:
            # Read CSV
            with open(input_path, encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                rows = list(reader)

            if not rows:
                result.errors.append("CSV file is empty")
                return result

            # Determine columns to process
            if text_columns is None:
                text_columns = list(fieldnames)
            else:
                # Validate columns exist
                missing = [c for c in text_columns if c not in fieldnames]
                if missing:
                    result.errors.append(f"Columns not found: {missing}")
                    return result

            total_rows = len(rows)
            total_pii = 0
            failed_rows = 0
            processed_rows = []
            workers_used = workers

            if workers > 1:
                # Multiprocessing mode
                processed_rows, total_pii, failed_rows = self._process_multiprocessing(
                    rows, text_columns, workers, batch_size, show_progress
                )
            else:
                # Single-threaded mode
                processed_rows, total_pii, failed_rows = self._process_single(
                    rows, text_columns, show_progress
                )

            # Write output
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(processed_rows)

            result.success = True
            result.rows_processed = total_rows
            result.rows_failed = failed_rows
            result.total_pii_found = total_pii
            result.processing_time = time.time() - start_time
            result.workers_used = workers_used

        except Exception as e:
            result.errors.append(str(e))
            result.processing_time = time.time() - start_time

        return result

    def _process_single(
        self,
        rows: list,
        text_columns: list,
        show_progress: bool
    ) -> tuple:
        """Process rows in single-threaded mode."""
        processed_rows = []
        total_pii = 0
        failed_rows = 0

        iterator = tqdm(rows, desc="Processing", unit="rows") if show_progress else rows

        for row in iterator:
            try:
                processed_row = row.copy()
                row_pii = 0

                for col in text_columns:
                    if col not in row or not row[col]:
                        continue

                    text = str(row[col])

                    # Analyze
                    results = self.processor.analyzer.analyze(
                        text=text,
                        language='en'
                    )

                    if not results:
                        continue

                    # Convert to PIIMatch
                    matches = [
                        PIIMatch(
                            pii_type=r.entity_type,
                            value=text[r.start:r.end],
                            start=r.start,
                            end=r.end,
                            confidence=r.score,
                            context="",
                            detector_name="Presidio"
                        )
                        for r in results
                    ]

                    matches = deduplicate_matches(matches)
                    matches = merge_overlapping_matches(matches)
                    row_pii += len(matches)

                    # Anonymize
                    processed_row[col] = self.processor.anonymizer.anonymize_batch(matches, text)

                processed_rows.append(processed_row)
                total_pii += row_pii

            except Exception:
                processed_rows.append(row)  # Keep original on error
                failed_rows += 1

        return processed_rows, total_pii, failed_rows

    def _process_multiprocessing(
        self,
        rows: list,
        text_columns: list,
        workers: int,
        batch_size: int,
        show_progress: bool
    ) -> tuple:
        """Process rows using multiprocessing."""
        # Prepare work items
        work_items = [(i, row, text_columns) for i, row in enumerate(rows)]

        # Process with pool
        processed_results = [None] * len(rows)
        total_pii = 0
        failed_rows = 0

        # Cap workers at CPU count
        workers = min(workers, cpu_count())

        with Pool(processes=workers, initializer=_init_worker, initargs=(self.config,)) as pool:
            # Use imap for ordered results with progress
            if show_progress:
                iterator = tqdm(
                    pool.imap(_process_row_worker, work_items, chunksize=batch_size),
                    total=len(rows),
                    desc=f"Processing ({workers} workers)",
                    unit="rows"
                )
            else:
                iterator = pool.imap(_process_row_worker, work_items, chunksize=batch_size)

            for row_idx, processed_row, pii_count, error in iterator:
                processed_results[row_idx] = processed_row
                total_pii += pii_count
                if error:
                    failed_rows += 1

        return processed_results, total_pii, failed_rows
