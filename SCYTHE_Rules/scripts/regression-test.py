#!/usr/bin/env python3
"""
Sigma Rule Regression Testing with Atomic Red Team

Executes Atomic Red Team tests and validates that corresponding
Sigma rules trigger in Splunk.

Usage:
    python regression-test.py --splunk-host splunk.local --test-config tests/art_mapping.yaml

Requirements:
    - Atomic Red Team installed on target (Install-AtomicRedTeam)
    - Invoke-AtomicTest PowerShell module
    - WinRM or SSH access to test endpoint
    - Splunk with deployed Sigma rules
"""

import argparse
import json
import time
import yaml
import requests
import urllib3
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AtomicTest:
    """An Atomic Red Team test mapped to expected Sigma rules."""
    name: str
    description: str
    technique_id: str           # MITRE ATT&CK technique (e.g., T1070.001)
    atomic_test_guid: str       # Atomic Red Team test GUID
    expected_rules: List[str]   # Sigma rule titles that should fire
    cleanup: bool = True        # Run cleanup after test
    timeout_seconds: int = 300
    input_arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result of a single test execution."""
    test_name: str
    technique_id: str
    atomic_guid: str
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
        """Get list of triggered alert/saved search names."""
        query = 'index=_audit action=alert_fired | stats count by savedsearch_name'
        results = self.search(query, earliest=earliest)
        return [r["savedsearch_name"] for r in results]

    def search_saved_search(self, search_name: str, earliest: str = "-15m") -> int:
        """Run a saved search and return result count."""
        query = f'| savedsearch "{search_name}"'
        try:
            results = self.search(query, earliest=earliest)
            return len(results)
        except Exception:
            return 0


class AtomicRunner:
    """Executes Atomic Red Team tests on local or remote systems."""

    def __init__(self, target: str = "localhost", use_winrm: bool = False,
                 winrm_user: str = None, winrm_pass: str = None):
        self.target = target
        self.use_winrm = use_winrm
        self.winrm_user = winrm_user
        self.winrm_pass = winrm_pass

    def run_atomic(self, technique_id: str, test_guid: str,
                   input_args: Dict[str, Any] = None, cleanup: bool = True) -> Dict:
        """
        Execute an Atomic Red Team test.

        Returns dict with 'success' bool and 'output' or 'error'.
        """
        # Build the PowerShell command
        ps_cmd = f'Invoke-AtomicTest {technique_id} -TestGuids {test_guid}'

        if input_args:
            args_str = ','.join(f'{k}="{v}"' for k, v in input_args.items())
            ps_cmd += f' -InputArguments @{{{args_str}}}'

        if not cleanup:
            ps_cmd += ' -NoCleanup'

        ps_cmd += ' -Confirm:$false'

        if self.target == "localhost" and not self.use_winrm:
            return self._run_local(ps_cmd)
        else:
            return self._run_remote(ps_cmd)

    def _run_local(self, ps_cmd: str) -> Dict:
        """Run PowerShell command locally."""
        full_cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd]

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_remote(self, ps_cmd: str) -> Dict:
        """Run PowerShell command via WinRM."""
        try:
            import winrm
            session = winrm.Session(
                self.target,
                auth=(self.winrm_user, self.winrm_pass),
                transport='ntlm'
            )
            result = session.run_ps(ps_cmd)
            return {
                "success": result.status_code == 0,
                "output": result.std_out.decode('utf-8'),
                "error": result.std_err.decode('utf-8') if result.status_code != 0 else None
            }
        except ImportError:
            return {"success": False, "error": "pywinrm not installed. Run: pip install pywinrm"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def check_atomic_installed(self) -> bool:
        """Verify Atomic Red Team is installed."""
        check_cmd = "Get-Module -ListAvailable -Name Invoke-AtomicRedTeam"
        result = self._run_local(check_cmd) if self.target == "localhost" else self._run_remote(check_cmd)
        return result["success"] and "Invoke-AtomicRedTeam" in result.get("output", "")


def load_test_config(config_path: str) -> List[AtomicTest]:
    """Load test mappings from YAML configuration."""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    tests = []
    for test in config.get('tests', []):
        tests.append(AtomicTest(
            name=test['name'],
            description=test.get('description', ''),
            technique_id=test['technique_id'],
            atomic_test_guid=test['atomic_test_guid'],
            expected_rules=test['expected_rules'],
            cleanup=test.get('cleanup', True),
            timeout_seconds=test.get('timeout_seconds', 300),
            input_arguments=test.get('input_arguments', {})
        ))
    return tests


def run_test(test: AtomicTest, splunk: SplunkClient, runner: AtomicRunner,
             wait_time: int = 60) -> TestResult:
    """Execute a single test case."""
    print(f"\n{'='*60}")
    print(f"Test: {test.name}")
    print(f"Technique: {test.technique_id}")
    print(f"Atomic GUID: {test.atomic_test_guid}")
    print(f"Expected Rules: {', '.join(test.expected_rules)}")
    print('='*60)

    start_time = time.time()
    error = None
    triggered_rules = []

    try:
        # Execute atomic test
        print(f"[+] Executing Atomic Test: {test.technique_id} / {test.atomic_test_guid}")
        result = runner.run_atomic(
            test.technique_id,
            test.atomic_test_guid,
            test.input_arguments,
            test.cleanup
        )

        if not result["success"]:
            print(f"[-] Atomic test failed: {result.get('error', 'Unknown error')}")
            error = result.get('error')
        else:
            print(f"[+] Atomic test executed successfully")
            if result.get("output"):
                # Show first few lines of output
                lines = result["output"].strip().split('\n')[:5]
                for line in lines:
                    print(f"    {line}")

        # Wait for logs to propagate
        print(f"[*] Waiting {wait_time}s for log ingestion...")
        time.sleep(wait_time)

        # Check for triggered rules
        print("[*] Checking Splunk for triggered rules...")

        # Method 1: Check triggered alerts
        all_alerts = splunk.get_triggered_alerts(earliest=f"-{wait_time + 60}s")
        triggered_rules = [r for r in all_alerts if r in test.expected_rules]

        # Method 2: Also run each expected saved search directly
        for rule_name in test.expected_rules:
            if rule_name not in triggered_rules:
                count = splunk.search_saved_search(rule_name, earliest=f"-{wait_time + 60}s")
                if count > 0:
                    triggered_rules.append(rule_name)
                    print(f"    [+] {rule_name}: {count} matches")
                else:
                    print(f"    [-] {rule_name}: no matches")

    except Exception as e:
        error = str(e)
        print(f"[-] Error: {error}")

    execution_time = time.time() - start_time
    missing_rules = [r for r in test.expected_rules if r not in triggered_rules]
    passed = len(missing_rules) == 0 and error is None

    status = "PASS" if passed else "FAIL"
    print(f"\n[{'+'if passed else '-'}] Result: {status}")

    return TestResult(
        test_name=test.name,
        technique_id=test.technique_id,
        atomic_guid=test.atomic_test_guid,
        passed=passed,
        expected_rules=test.expected_rules,
        triggered_rules=triggered_rules,
        missing_rules=missing_rules,
        execution_time=execution_time,
        error=error
    )


def generate_report(results: List[TestResult], output_path: str):
    """Generate JSON test report."""
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
            "technique_id": r.technique_id,
            "atomic_guid": r.atomic_guid,
            "passed": r.passed,
            "expected_rules": r.expected_rules,
            "triggered_rules": r.triggered_rules,
            "missing_rules": r.missing_rules,
            "execution_time_seconds": round(r.execution_time, 2),
            "error": r.error
        })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Print summary
    print("\n" + "="*60)
    print("REGRESSION TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {len(results)}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")
    print(f"Pass Rate:   {report['summary']['pass_rate']}")

    if failed > 0:
        print("\nFailed Tests:")
        for r in results:
            if not r.passed:
                print(f"  - {r.test_name} ({r.technique_id})")
                if r.missing_rules:
                    print(f"    Missing: {', '.join(r.missing_rules)}")
                if r.error:
                    print(f"    Error: {r.error}")

    print(f"\nReport saved to: {output_path}")
    return report


def create_example_config(path: str):
    """Create example test mapping configuration."""
    example = {
        "tests": [
            {
                "name": "Clear Windows Event Logs",
                "description": "Clears Security event log using wevtutil",
                "technique_id": "T1070.001",
                "atomic_test_guid": "e6abb60e-26b8-41da-8aae-0c35174b0967",
                "expected_rules": ["Windows Event Log Cleared"],
                "cleanup": True,
                "timeout_seconds": 300
            },
            {
                "name": "System Information Discovery",
                "description": "Runs systeminfo command",
                "technique_id": "T1082",
                "atomic_test_guid": "66571c33-5533-4b71-8d3f-02626c89c5dc",
                "expected_rules": ["Conti Ransomware Discovery Commands"],
                "cleanup": True
            },
            {
                "name": "Create Local Admin User",
                "description": "Creates a new local administrator account",
                "technique_id": "T1136.001",
                "atomic_test_guid": "a524ce99-86de-4f6c-88f5-8c3439e21ed5",
                "expected_rules": ["New Local User Created"],
                "input_arguments": {
                    "username": "AtomicTestUser",
                    "password": "AtomicP@ss123!"
                },
                "cleanup": True
            }
        ]
    }

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(example, f, default_flow_style=False, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(
        description='Sigma Rule Regression Testing with Atomic Red Team'
    )
    parser.add_argument('--splunk-host', required=True, help='Splunk server hostname')
    parser.add_argument('--splunk-port', type=int, default=8089, help='Splunk management port')
    parser.add_argument('--splunk-user', default='admin', help='Splunk username')
    parser.add_argument('--splunk-pass', help='Splunk password (or SPLUNK_PASSWORD env var)')
    parser.add_argument('--target', default='localhost', help='Target for atomic tests')
    parser.add_argument('--winrm-user', help='WinRM username for remote targets')
    parser.add_argument('--winrm-pass', help='WinRM password for remote targets')
    parser.add_argument('--test-config', default='tests/art_mapping.yaml', help='Test mapping file')
    parser.add_argument('--output', default='test_results.json', help='Output report path')
    parser.add_argument('--wait-time', type=int, default=60, help='Seconds to wait for log ingestion')
    parser.add_argument('--dry-run', action='store_true', help='Show tests without executing')
    parser.add_argument('--skip-atomic-check', action='store_true', help='Skip Atomic RT install check')

    args = parser.parse_args()

    # Load or create test config
    if not Path(args.test_config).exists():
        print(f"Creating example config at: {args.test_config}")
        create_example_config(args.test_config)
        print("Edit the configuration and run again.")
        return 0

    tests = load_test_config(args.test_config)
    print(f"Loaded {len(tests)} test cases from {args.test_config}")

    if args.dry_run:
        print("\n[DRY RUN] Tests to execute:")
        for test in tests:
            print(f"\n  {test.name}")
            print(f"    Technique: {test.technique_id}")
            print(f"    Atomic GUID: {test.atomic_test_guid}")
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

    runner = AtomicRunner(
        target=args.target,
        use_winrm=args.target != "localhost",
        winrm_user=args.winrm_user,
        winrm_pass=args.winrm_pass
    )

    # Check Atomic RT installation
    if not args.skip_atomic_check:
        print("Checking Atomic Red Team installation...")
        if not runner.check_atomic_installed():
            print("WARNING: Atomic Red Team not detected. Install with:")
            print("  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)")
            print("  Install-AtomicRedTeam -getAtomics")
            print("\nUse --skip-atomic-check to proceed anyway.")
            return 1
        print("Atomic Red Team is installed.")

    # Run tests
    results = []
    for test in tests:
        result = run_test(test, splunk, runner, args.wait_time)
        results.append(result)

    # Generate report
    generate_report(results, args.output)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
