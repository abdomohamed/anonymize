"""
Command-line interface for PII Anonymization Tool.

This module provides the CLI for detecting and anonymizing PII in text files.
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# Load .env file if present (before any config is read)
from dotenv import load_dotenv
load_dotenv()

from src.config.config_manager import ConfigManager
from src.processors.file_processor import FileProcessor
from src.processors.csv_processor import CSVProcessor, CSVProcessResult


def setup_logging(config: dict) -> None:
    """
    Setup logging configuration.

    Args:
        config: Logging configuration dictionary
    """
    log_level = config.get('level', 'INFO')
    log_format = config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_file = config.get('file', None)

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=log_format,
        filename=log_file
    )

    # Suppress verbose library logging for cleaner output
    for name in ['presidio-analyzer', 'spacy', 'azure', 'azure.identity', 'azure.core', 'httpx', 'httpcore']:
        logging.getLogger(name).setLevel(logging.ERROR)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='PII Anonymization Tool - Detect and anonymize personally identifiable information in text files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Anonymize a single file
  anonymize input.txt -o output.txt

  # Use specific anonymization strategy
  anonymize input.txt --strategy mask

  # Process all files in a directory
  anonymize input_dir/ -o output_dir/ --dir

  # Process CSV file (single-threaded)
  anonymize data.csv --csv -o anonymized.csv

  # Process CSV with specific columns
  anonymize data.csv --csv --columns notes email phone

  # Process large CSV with 4 parallel workers
  anonymize large.csv --csv --workers 4

  # Use custom configuration
  anonymize input.txt -c my_config.yaml
        '''
    )

    # Input/output arguments
    parser.add_argument(
        'input',
        help='Input file or directory path'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output file or directory path (auto-generated if not specified)',
        default=None
    )

    # Processing mode
    parser.add_argument(
        '--dir',
        action='store_true',
        help='Process directory instead of single file'
    )

    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Process directories recursively (only with --dir)'
    )

    # CSV mode
    parser.add_argument(
        '--csv',
        action='store_true',
        help='Process input as CSV file'
    )

    parser.add_argument(
        '--columns',
        nargs='+',
        help='CSV columns to process (default: all columns)',
        default=None
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=None,
        help='Number of parallel workers for CSV processing (default: auto-detect CPU cores)'
    )

    parser.add_argument(
        '--single-threaded',
        action='store_true',
        help='Disable multiprocessing, use single thread'
    )

    parser.add_argument(
        '--no-progress',
        action='store_true',
        help='Disable progress bar'
    )

    # Configuration
    parser.add_argument(
        '-c', '--config',
        help='Path to custom configuration file (YAML)',
        default=None
    )

    # Anonymization strategy
    parser.add_argument(
        '--strategy',
        choices=['redact', 'mask', 'replace', 'hash'],
        help='Anonymization strategy to use (overrides config)',
        default=None
    )

    # Detector options
    parser.add_argument(
        '--entities',
        nargs='+',
        help='Specific Presidio entity types to detect (e.g., EMAIL_ADDRESS PHONE_NUMBER)',
        default=None
    )

    parser.add_argument(
        '--confidence',
        type=float,
        help='Confidence threshold for detection (0.0-1.0)',
        default=None
    )

    # LLM second pass
    parser.add_argument(
        '--llm',
        action='store_true',
        help='Enable LLM second-pass detection (requires openai package)'
    )

    # Output options
    parser.add_argument(
        '--no-audit',
        action='store_true',
        help='Disable audit log generation'
    )

    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create backup of original file before anonymization'
    )

    # Verbosity
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='PII Anonymization Tool v1.0.0'
    )

    return parser.parse_args()


def build_cli_overrides(args: argparse.Namespace) -> dict:
    """
    Build configuration overrides from CLI arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Dictionary of configuration overrides
    """
    overrides = {}

    # Anonymization strategy
    if args.strategy:
        overrides['anonymization'] = {'strategy': args.strategy}

    # Entity types
    if args.entities:
        if 'detection' not in overrides:
            overrides['detection'] = {}
        overrides['detection']['enabled_entities'] = args.entities

    # Confidence threshold
    if args.confidence is not None:
        if 'detection' not in overrides:
            overrides['detection'] = {}
        overrides['detection']['confidence_threshold'] = args.confidence

    # Processing options
    processing_overrides = {}

    if args.no_audit:
        processing_overrides['create_audit_log'] = False

    if args.backup:
        processing_overrides['backup_original'] = True

    if processing_overrides:
        overrides['processing'] = processing_overrides

    # LLM second pass
    if args.llm:
        overrides['llm_detection'] = {'enabled': True}

    # Logging
    if args.verbose:
        overrides['logging'] = {'level': 'DEBUG', 'verbose': True}

    return overrides


def validate_input(args: argparse.Namespace) -> bool:
    """
    Validate input arguments.

    Args:
        args: Parsed arguments

    Returns:
        True if valid, False otherwise
    """
    # Check if input exists
    if not os.path.exists(args.input):
        print(f"Error: Input path does not exist: {args.input}", file=sys.stderr)
        return False

    # CSV mode validation
    if args.csv:
        if not os.path.isfile(args.input):
            print(f"Error: --csv specified but input is not a file: {args.input}", file=sys.stderr)
            return False
        if not args.input.lower().endswith('.csv'):
            print("Warning: Input file does not have .csv extension")
        return True

    # Validate directory mode
    if args.dir:
        if not os.path.isdir(args.input):
            print(f"Error: --dir specified but input is not a directory: {args.input}", file=sys.stderr)
            return False
    else:
        if not os.path.isfile(args.input):
            print(f"Error: Input is not a file: {args.input}", file=sys.stderr)
            return False

    # Recursive only makes sense with directory mode
    if args.recursive and not args.dir:
        print("Warning: --recursive ignored (only applies to --dir mode)")

    return True


def print_results(results) -> None:
    """
    Print processing results summary.

    Args:
        results: ProcessResult, CSVProcessResult, or list of ProcessResult objects
    """
    # Handle CSV results
    if isinstance(results, CSVProcessResult):
        print("\n" + "=" * 70)
        print("CSV PROCESSING RESULT")
        print("=" * 70)
        print(f"Input: {results.input_path}")
        print(f"Output: {results.output_path}")
        print(f"Status: {'SUCCESS' if results.success else 'FAILED'}")
        print(f"Workers: {results.workers_used}")
        print(f"Rows processed: {results.rows_processed:,}")
        if results.rows_failed > 0:
            print(f"Rows failed: {results.rows_failed:,}")
        print(f"PII found: {results.total_pii_found:,}")
        if results.llm_pii_found > 0:
            print(f"  └─ LLM second pass: {results.llm_pii_found:,}")
        if results.rows_processed > 0:
            print(f"Avg PII/row: {results.total_pii_found / results.rows_processed:.1f}")
        print(f"Processing time: {results.processing_time:.2f}s")
        if results.rows_processed > 0 and results.processing_time > 0:
            print(f"Rate: {results.rows_processed / results.processing_time:.0f} rows/sec")

        if results.errors:
            print(f"\nErrors:")
            for error in results.errors:
                print(f"  - {error}")

        print("=" * 70)
        return

    if isinstance(results, list):
        # Multiple files
        print("\n" + "=" * 70)
        print("PROCESSING SUMMARY")
        print("=" * 70)

        total = len(results)
        successful = sum(1 for r in results if r.success)
        total_pii = sum(r.pii_anonymized for r in results)
        total_time = sum(r.processing_time for r in results)

        print(f"Files processed: {successful}/{total}")
        print(f"Total PII anonymized: {total_pii}")
        print(f"Total processing time: {total_time:.2f}s")

        # Show errors
        errors = [r for r in results if not r.success]
        if errors:
            print(f"\nErrors ({len(errors)} files):")
            for result in errors[:5]:  # Show first 5 errors
                print(f"  - {result.input_path}: {result.errors[0] if result.errors else 'Unknown error'}")
            if len(errors) > 5:
                print(f"  ... and {len(errors) - 5} more errors")

        print("=" * 70)
    else:
        # Single file
        result = results
        print("\n" + "=" * 70)
        print("PROCESSING RESULT")
        print("=" * 70)
        print(f"Input: {result.input_path}")
        print(f"Output: {result.output_path}")
        print(f"Status: {'SUCCESS' if result.success else 'FAILED'}")
        print(f"PII found: {result.pii_found}")
        if result.llm_pii_found > 0:
            print(f"  └─ LLM second pass: {result.llm_pii_found}")
        print(f"PII anonymized: {result.pii_anonymized}")
        print(f"Processing time: {result.processing_time:.2f}s")

        if result.errors:
            print(f"\nErrors:")
            for error in result.errors:
                print(f"  - {error}")

        if result.warnings:
            print(f"\nWarnings:")
            for warning in result.warnings:
                print(f"  - {warning}")

        print("=" * 70)


def main():
    """Main entry point for CLI."""
    # Parse arguments
    args = parse_args()

    # Validate input
    if not validate_input(args):
        sys.exit(1)

    try:
        # Determine default config path
        # Look for config in: 1) Current directory, 2) Script directory
        script_dir = Path(__file__).parent
        default_config_paths = [
            'config/default_config.yaml',
            script_dir / 'config' / 'default_config.yaml',
            script_dir.parent / 'config' / 'default_config.yaml',
        ]

        default_config_path = None
        for path in default_config_paths:
            if os.path.exists(path):
                default_config_path = str(path)
                break

        if default_config_path is None:
            print("Error: Default configuration file not found", file=sys.stderr)
            sys.exit(1)

        # Build configuration overrides
        cli_overrides = build_cli_overrides(args)

        # Load configuration
        print("Loading configuration...")
        config_manager = ConfigManager.load(
            default_path=default_config_path,
            user_path=args.config,
            cli_overrides=cli_overrides
        )

        # Setup logging
        setup_logging(config_manager.config_data.get('logging', {}))

        # Process based on mode
        if args.csv:
            # CSV mode
            from multiprocessing import cpu_count

            # Determine workers: None=auto-detect, explicit number, or --single-threaded
            if args.single_threaded:
                workers = 1
            elif args.workers is not None:
                workers = args.workers
            else:
                # Auto-detect: use all CPUs
                workers = cpu_count()

            # Cap at available CPUs
            max_workers = cpu_count()
            if workers > max_workers:
                print(f"Warning: Requested {workers} workers, but only {max_workers} CPUs available")
                workers = max_workers

            print(f"Initializing CSV processor ({workers} workers)...")
            processor = CSVProcessor(config_manager.config_data)

            results = processor.process_csv(
                input_path=args.input,
                output_path=args.output,
                text_columns=args.columns,
                workers=workers,
                show_progress=not args.no_progress
            )
        elif args.dir:
            # Directory mode
            print("Initializing processor...")
            processor = FileProcessor(config_manager.config_data)
            results = processor.process_directory(
                input_dir=args.input,
                output_dir=args.output,
                recursive=args.recursive
            )
        else:
            # Single file mode
            print("Initializing processor...")
            processor = FileProcessor(config_manager.config_data)
            results = processor.process_file(
                input_path=args.input,
                output_path=args.output
            )

        # Print results
        print_results(results)

        # Exit with appropriate code
        if isinstance(results, CSVProcessResult):
            if not results.success:
                sys.exit(1)
        elif isinstance(results, list):
            # Exit with error if any file failed
            if any(not r.success for r in results):
                sys.exit(1)
        else:
            if not results.success:
                sys.exit(1)

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"\nFatal error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
