#!/usr/bin/env python3
"""
Converts Sigma rules to Splunk savedsearches.conf format.
Supports Windows and cross-platform rules.
"""

import os
import sys
import subprocess
import yaml
import json
import argparse
from pathlib import Path
from datetime import datetime


RULES_DIR = "SCYTHE_Rules"
OUTPUT_DIR = "splunk_output"

# Rules compatible with Splunk (Windows-based logsources)
SPLUNK_COMPATIBLE_PREFIXES = [
    "proc_creation_win_",
    "file_event_win_",
    "reg_set_win_",
    "net_connection_win_",
    "security_",
]

# Pipeline mapping based on logsource
PIPELINE_MAP = {
    "proc_creation": "splunk_windows",
    "file_event": "splunk_windows",
    "reg_set": "splunk_windows",
    "net_connection": "splunk_windows",
    "security": "splunk_windows",
}


def get_rule_metadata(rule_path):
    """Extract metadata from a Sigma rule."""
    try:
        with open(rule_path, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
        return {
            'id': rule.get('id', ''),
            'title': rule.get('title', ''),
            'description': rule.get('description', ''),
            'level': rule.get('level', 'medium'),
            'status': rule.get('status', 'experimental'),
            'tags': rule.get('tags', []),
            'logsource': rule.get('logsource', {}),
        }
    except Exception as e:
        print(f"Warning: Could not parse {rule_path}: {e}")
        return None


def is_splunk_compatible(rule_path):
    """Check if a rule is compatible with Splunk conversion."""
    filename = os.path.basename(rule_path)

    # Check by filename prefix
    for prefix in SPLUNK_COMPATIBLE_PREFIXES:
        if filename.startswith(prefix):
            return True

    # Check logsource for Windows product
    metadata = get_rule_metadata(rule_path)
    if metadata:
        logsource = metadata.get('logsource', {})
        product = logsource.get('product', '')
        if product == 'windows':
            return True

    return False


def get_pipeline_for_rule(rule_path):
    """Determine the appropriate pySigma pipeline for a rule."""
    filename = os.path.basename(rule_path)

    for prefix, pipeline in PIPELINE_MAP.items():
        if prefix in filename:
            return pipeline

    return "splunk_windows"


def convert_rule(rule_path, output_format="savedsearches"):
    """Convert a single Sigma rule to Splunk format."""
    pipeline = get_pipeline_for_rule(rule_path)

    cmd = [
        "sigma", "convert",
        "-t", "splunk",
        "-p", pipeline,
        "-f", output_format,
        str(rule_path)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            return {
                'success': True,
                'output': result.stdout,
                'rule_path': str(rule_path)
            }
        else:
            return {
                'success': False,
                'error': result.stderr,
                'rule_path': str(rule_path)
            }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Conversion timed out',
            'rule_path': str(rule_path)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'rule_path': str(rule_path)
        }


def convert_all_rules(rules_dir, output_dir, output_format="savedsearches"):
    """Convert all compatible Sigma rules to Splunk format."""
    rules_path = Path(rules_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    rule_files = list(rules_path.glob("*.yml"))
    compatible_rules = [r for r in rule_files if is_splunk_compatible(r)]

    print(f"Found {len(rule_files)} total rules")
    print(f"Found {len(compatible_rules)} Splunk-compatible rules")
    print()

    results = {
        'successful': [],
        'failed': [],
        'skipped': []
    }

    # Combine all savedsearches into one file
    combined_output = []
    combined_output.append("[default]")
    combined_output.append("dispatch.earliest_time = -30d")
    combined_output.append("dispatch.latest_time = now")
    combined_output.append("")

    for rule_path in compatible_rules:
        print(f"Converting: {rule_path.name}...", end=" ")

        result = convert_rule(rule_path, output_format)

        if result['success']:
            print("OK")
            results['successful'].append(rule_path.name)

            # Extract the rule content (skip the [default] header)
            lines = result['output'].strip().split('\n')
            rule_lines = []
            skip_header = True
            for line in lines:
                if skip_header:
                    if line.startswith('[') and not line.startswith('[default]'):
                        skip_header = False
                        rule_lines.append(line)
                else:
                    rule_lines.append(line)

            if rule_lines:
                combined_output.append('\n'.join(rule_lines))
                combined_output.append("")
        else:
            print(f"FAILED: {result['error']}")
            results['failed'].append({
                'rule': rule_path.name,
                'error': result['error']
            })

    # Track skipped rules
    for rule_path in rule_files:
        if rule_path not in compatible_rules:
            results['skipped'].append(rule_path.name)

    # Write combined savedsearches.conf
    output_file = output_path / "savedsearches.conf"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(combined_output))

    # Write conversion report
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_rules': len(rule_files),
        'compatible_rules': len(compatible_rules),
        'successful_conversions': len(results['successful']),
        'failed_conversions': len(results['failed']),
        'skipped_rules': len(results['skipped']),
        'details': results
    }

    report_file = output_path / "conversion_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    return results, output_file


def main():
    parser = argparse.ArgumentParser(
        description='Convert Sigma rules to Splunk savedsearches.conf format'
    )
    parser.add_argument(
        '-i', '--input',
        default=RULES_DIR,
        help=f'Input directory containing Sigma rules (default: {RULES_DIR})'
    )
    parser.add_argument(
        '-o', '--output',
        default=OUTPUT_DIR,
        help=f'Output directory for Splunk files (default: {OUTPUT_DIR})'
    )
    parser.add_argument(
        '-f', '--format',
        default='savedsearches',
        choices=['savedsearches', 'default', 'data_model'],
        help='Output format (default: savedsearches)'
    )
    parser.add_argument(
        '--list-compatible',
        action='store_true',
        help='List compatible rules without converting'
    )

    args = parser.parse_args()

    if args.list_compatible:
        rules_path = Path(args.input)
        rule_files = list(rules_path.glob("*.yml"))
        compatible = [r for r in rule_files if is_splunk_compatible(r)]

        print("Splunk-compatible rules:")
        for r in sorted(compatible):
            print(f"  - {r.name}")
        print(f"\nTotal: {len(compatible)} / {len(rule_files)} rules")
        return 0

    print("=" * 60)
    print("Sigma to Splunk Conversion")
    print("=" * 60)
    print()

    results, output_file = convert_all_rules(
        args.input,
        args.output,
        args.format
    )

    print()
    print("=" * 60)
    print("Conversion Summary")
    print("=" * 60)
    print(f"Successful: {len(results['successful'])}")
    print(f"Failed:     {len(results['failed'])}")
    print(f"Skipped:    {len(results['skipped'])} (non-Windows rules)")
    print()
    print(f"Output file: {output_file}")
    print(f"Report file: {output_file.parent / 'conversion_report.json'}")

    if results['failed']:
        print()
        print("Failed conversions:")
        for fail in results['failed']:
            print(f"  - {fail['rule']}: {fail['error'][:50]}...")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
