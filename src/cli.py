"""
Command-line interface for PII Anonymization Tool.

This module provides the CLI for detecting and anonymizing PII in text files.
"""

import argparse
import sys
import os
import logging
from pathlib import Path

from src.config.config_manager import ConfigManager
from src.processors.file_processor import FileProcessor


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
  python -m cli input.txt -o output.txt
  
  # Use specific anonymization strategy
  python -m cli input.txt --strategy mask
  
  # Process all files in a directory
  python -m cli input_dir/ -o output_dir/ --dir
  
  # Use custom configuration
  python -m cli input.txt -c my_config.yaml
  
  # Enable verbose output
  python -m cli input.txt -v
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
        results: ProcessResult or list of ProcessResult objects
    """
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
        
        # Create processor
        print("Initializing processor...")
        processor = FileProcessor(config_manager.config_data)
        
        # Process files
        if args.dir:
            # Directory mode
            results = processor.process_directory(
                input_dir=args.input,
                output_dir=args.output,
                recursive=args.recursive
            )
        else:
            # Single file mode
            results = processor.process_file(
                input_path=args.input,
                output_path=args.output
            )
        
        # Print results
        print_results(results)
        
        # Exit with appropriate code
        if isinstance(results, list):
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
