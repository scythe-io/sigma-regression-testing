#!/usr/bin/env python3
"""
Sigma Rule Regression Testing Framework

Integrates with SCYTHE atomic actions to validate that Sigma rules
properly trigger in Splunk when expected activity occurs.

Usage:
    python regression-test.py --splunk-host splunk.local --test-config tests/test_mapping.yaml
"""

import argparse
import json
import time
import yaml
import requests
import urllib3
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestCase:
    """A single test case mapping a SCYTHE action to expected Sigma rule(s)."""
    name: str
    description: str
    scythe_action: str
    scythe_params: Dict[str, Any]
    expected_rules: List[str]
    timeout_seconds: int = 300
    mitre_technique: Optional[str] = None


@dataclass
class TestResult:
    """Result of a single test case execution."""
    test_name: str
    passed: bool
    expected_rules: List[str]
    triggered_rules: List[str]
    missing_rules: List[str]
    execution_time: float
    error: Optional[str] = None


class SplunkClient:
    """Client for querying Splunk via REST API."""

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = False):
        self.base_url = f"https://{host}:{port}"
        self.auth = (username, password)
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def search(self, query: str, earliest: str = "-15m", latest: str = "now") -> List[Dict]:
        """Execute a Splunk search and return results."""
        # Create search job
        create_url = f"{self.base_url}/services/search/jobs"
        data = {
            "search": f"search {query}",
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json"
        }

        response = self.session.post(create_url, data=data, auth=self.auth)
        response.raise_for_status()

        sid = response.json()["sid"]

        # Wait for search to complete
        status_url = f"{self.base_url}/services/search/jobs/{sid}"
        while True:
            status_response = self.session.get(
                status_url,
                params={"output_mode": "json"},
                auth=self.auth
            )
            status_response.raise_for_status()

            dispatch_state = status_response.json()["entry"][0]["content"]["dispatchState"]
            if dispatch_state == "DONE":
                break
            elif dispatch_state == "FAILED":
                raise Exception("Search job failed")
            time.sleep(1)

        # Get results
        results_url = f"{self.base_url}/services/search/jobs/{sid}/results"
        results_response = self.session.get(
            results_url,
            params={"output_mode": "json", "count": 0},
            auth=self.auth
        )
        results_response.raise_for_status()

        return results_response.json().get("results", [])

    def get_triggered_alerts(self, earliest: str = "-15m") -> List[str]:
        """Get list of triggered alert names in the given time window."""
        query = "index=_audit action=alert_fired | stats count by savedsearch_name"
        results = self.search(query, earliest=earliest)
        return [r["savedsearch_name"] for r in results]

    def get_matching_events(self, search_query: str, earliest: str = "-15m") -> int:
        """Run a saved search query and return event count."""
        results = self.search(search_query, earliest=earliest)
        return len(results)


class SCYTHEClient:
    """Client for triggering SCYTHE atomic actions via API."""

    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = False):
        self.api_url = api_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.verify_ssl = verify_ssl

    def execute_action(self, action: str, params: Dict[str, Any], target: str) -> Dict:
        """
        Execute a SCYTHE atomic action on a target.

        Note: This is a placeholder implementation. The actual API calls
        will depend on your SCYTHE deployment and API version.
        """
        endpoint = f"{self.api_url}/api/v1/operations/execute"
        payload = {
            "action": action,
            "parameters": params,
            "target": target
        }

        response = requests.post(
            endpoint,
            headers=self.headers,
            json=payload,
            verify=self.verify_ssl
        )
        response.raise_for_status()
        return response.json()

    def get_operation_status(self, operation_id: str) -> Dict:
        """Get the status of a running operation."""
        endpoint = f"{self.api_url}/api/v1/operations/{operation_id}/status"
        response = requests.get(
            endpoint,
            headers=self.headers,
            verify=self.verify_ssl
        )
        response.raise_for_status()
        return response.json()


class MockSCYTHEClient:
    """Mock SCYTHE client for testing without actual SCYTHE deployment."""

    def __init__(self):
        self.executed_actions = []

    def execute_action(self, action: str, params: Dict[str, Any], target: str) -> Dict:
        """Simulate action execution."""
        self.executed_actions.append({
            "action": action,
            "params": params,
            "target": target,
            "timestamp": datetime.now().isoformat()
        })
        return {"operation_id": "mock-123", "status": "completed"}

    def get_operation_status(self, operation_id: str) -> Dict:
        return {"status": "completed"}


def load_test_config(config_path: str) -> List[TestCase]:
    """Load test cases from YAML configuration."""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    test_cases = []
    for test in config.get('tests', []):
        test_cases.append(TestCase(
            name=test['name'],
            description=test.get('description', ''),
            scythe_action=test['scythe_action'],
            scythe_params=test.get('scythe_params', {}),
            expected_rules=test['expected_rules'],
            timeout_seconds=test.get('timeout_seconds', 300),
            mitre_technique=test.get('mitre_technique')
        ))

    return test_cases


def run_test(
    test: TestCase,
    splunk: SplunkClient,
    scythe: SCYTHEClient,
    target: str,
    wait_time: int = 60
) -> TestResult:
    """Execute a single test case."""
    print(f"\n{'='*60}")
    print(f"Running: {test.name}")
    print(f"Description: {test.description}")
    print(f"SCYTHE Action: {test.scythe_action}")
    print(f"Expected Rules: {', '.join(test.expected_rules)}")
    print('='*60)

    start_time = time.time()
    error = None
    triggered_rules = []

    try:
        # Record the current time for Splunk queries
        test_start = datetime.now()

        # Execute SCYTHE action
        print(f"[+] Executing SCYTHE action: {test.scythe_action}")
        result = scythe.execute_action(
            test.scythe_action,
            test.scythe_params,
            target
        )
        print(f"[+] Action executed: {result.get('operation_id', 'N/A')}")

        # Wait for logs to propagate to Splunk
        print(f"[*] Waiting {wait_time}s for log ingestion...")
        time.sleep(wait_time)

        # Check for triggered alerts
        print("[*] Querying Splunk for triggered rules...")
        earliest = test_start.strftime("-%Mm")  # Relative time from test start

        # Get all triggered alerts
        all_alerts = splunk.get_triggered_alerts(earliest=f"-{wait_time + 60}s")
        triggered_rules = [r for r in all_alerts if r in test.expected_rules]

        # Also check by running the searches directly
        # (in case alerts aren't configured but searches exist)
        # This requires the search queries to be available

        print(f"[+] Triggered rules: {triggered_rules if triggered_rules else 'None'}")

    except Exception as e:
        error = str(e)
        print(f"[-] Error: {error}")

    execution_time = time.time() - start_time
    missing_rules = [r for r in test.expected_rules if r not in triggered_rules]

    passed = len(missing_rules) == 0 and error is None

    return TestResult(
        test_name=test.name,
        passed=passed,
        expected_rules=test.expected_rules,
        triggered_rules=triggered_rules,
        missing_rules=missing_rules,
        execution_time=execution_time,
        error=error
    )


def generate_report(results: List[TestResult], output_path: str):
    """Generate test results report."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": len(results),
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{(passed/len(results)*100):.1f}%" if results else "N/A"
        },
        "results": []
    }

    for r in results:
        report["results"].append({
            "test_name": r.test_name,
            "passed": r.passed,
            "expected_rules": r.expected_rules,
            "triggered_rules": r.triggered_rules,
            "missing_rules": r.missing_rules,
            "execution_time_seconds": round(r.execution_time, 2),
            "error": r.error
        })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Also print summary
    print("\n" + "="*60)
    print("REGRESSION TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {len(results)}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")
    print(f"Pass Rate:   {report['summary']['pass_rate']}")
    print()

    if failed > 0:
        print("Failed Tests:")
        for r in results:
            if not r.passed:
                print(f"  - {r.test_name}")
                if r.missing_rules:
                    print(f"    Missing rules: {', '.join(r.missing_rules)}")
                if r.error:
                    print(f"    Error: {r.error}")

    print()
    print(f"Full report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Sigma Rule Regression Testing with SCYTHE'
    )
    parser.add_argument(
        '--splunk-host',
        required=True,
        help='Splunk server hostname'
    )
    parser.add_argument(
        '--splunk-port',
        type=int,
        default=8089,
        help='Splunk management port (default: 8089)'
    )
    parser.add_argument(
        '--splunk-user',
        default='admin',
        help='Splunk username'
    )
    parser.add_argument(
        '--splunk-pass',
        help='Splunk password (or set SPLUNK_PASSWORD env var)'
    )
    parser.add_argument(
        '--scythe-url',
        help='SCYTHE API URL'
    )
    parser.add_argument(
        '--scythe-key',
        help='SCYTHE API key (or set SCYTHE_API_KEY env var)'
    )
    parser.add_argument(
        '--target',
        default='test-endpoint',
        help='Target endpoint for SCYTHE actions'
    )
    parser.add_argument(
        '--test-config',
        default='tests/test_mapping.yaml',
        help='Path to test configuration YAML'
    )
    parser.add_argument(
        '--output',
        default='test_results.json',
        help='Output path for test results'
    )
    parser.add_argument(
        '--wait-time',
        type=int,
        default=60,
        help='Seconds to wait for log ingestion (default: 60)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Parse config and show tests without executing'
    )
    parser.add_argument(
        '--mock-scythe',
        action='store_true',
        help='Use mock SCYTHE client (for testing without SCYTHE)'
    )

    args = parser.parse_args()

    # Load test configuration
    if not Path(args.test_config).exists():
        print(f"Test configuration not found: {args.test_config}")
        print("Creating example configuration...")
        create_example_config(args.test_config)
        print(f"Example config created at: {args.test_config}")
        print("Please edit the configuration and run again.")
        return 1

    test_cases = load_test_config(args.test_config)
    print(f"Loaded {len(test_cases)} test cases from {args.test_config}")

    if args.dry_run:
        print("\n[DRY RUN] Test cases to execute:")
        for test in test_cases:
            print(f"\n  {test.name}")
            print(f"    SCYTHE Action: {test.scythe_action}")
            print(f"    Expected Rules: {', '.join(test.expected_rules)}")
        return 0

    # Initialize clients
    import os

    splunk_pass = args.splunk_pass or os.environ.get('SPLUNK_PASSWORD')
    if not splunk_pass:
        import getpass
        splunk_pass = getpass.getpass("Splunk password: ")

    splunk = SplunkClient(
        host=args.splunk_host,
        port=args.splunk_port,
        username=args.splunk_user,
        password=splunk_pass
    )

    if args.mock_scythe:
        scythe = MockSCYTHEClient()
        print("[!] Using mock SCYTHE client - no actual actions will be executed")
    else:
        scythe_key = args.scythe_key or os.environ.get('SCYTHE_API_KEY')
        if not args.scythe_url or not scythe_key:
            print("Error: SCYTHE URL and API key required (use --mock-scythe for testing)")
            return 1

        scythe = SCYTHEClient(
            api_url=args.scythe_url,
            api_key=scythe_key
        )

    # Run tests
    results = []
    for test in test_cases:
        result = run_test(
            test=test,
            splunk=splunk,
            scythe=scythe,
            target=args.target,
            wait_time=args.wait_time
        )
        results.append(result)

    # Generate report
    generate_report(results, args.output)

    # Return non-zero if any tests failed
    return 0 if all(r.passed for r in results) else 1


def create_example_config(path: str):
    """Create an example test configuration file."""
    example_config = {
        "tests": [
            {
                "name": "Conti Ransomware Discovery",
                "description": "Test detection of Conti-style reconnaissance commands",
                "scythe_action": "run",
                "scythe_params": {
                    "command": "ipconfig /all && systeminfo && whoami"
                },
                "expected_rules": [
                    "Conti Ransomware Discovery Commands"
                ],
                "mitre_technique": "T1082",
                "timeout_seconds": 300
            },
            {
                "name": "Scheduled Task Creation",
                "description": "Test detection of suspicious scheduled task creation",
                "scythe_action": "schtasks",
                "scythe_params": {
                    "name": "TestTask",
                    "command": "C:\\Windows\\System32\\cmd.exe",
                    "trigger": "onlogon"
                },
                "expected_rules": [
                    "Suspicious Scheduled Task Creation"
                ],
                "mitre_technique": "T1053.005",
                "timeout_seconds": 300
            },
            {
                "name": "Registry Run Key Persistence",
                "description": "Test detection of Run key modification",
                "scythe_action": "registry",
                "scythe_params": {
                    "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value": "TestPersistence",
                    "data": "C:\\temp\\test.exe"
                },
                "expected_rules": [
                    "Suspicious Run Key Modification"
                ],
                "mitre_technique": "T1547.001",
                "timeout_seconds": 300
            },
            {
                "name": "Event Log Clearing",
                "description": "Test detection of Windows event log clearing",
                "scythe_action": "run",
                "scythe_params": {
                    "command": "wevtutil cl Security"
                },
                "expected_rules": [
                    "Windows Event Log Cleared"
                ],
                "mitre_technique": "T1070.001",
                "timeout_seconds": 300
            }
        ]
    }

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(example_config, f, default_flow_style=False, sort_keys=False)


if __name__ == "__main__":
    import sys
    sys.exit(main())
