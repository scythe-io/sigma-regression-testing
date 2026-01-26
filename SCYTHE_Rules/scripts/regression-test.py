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
    search_queries: Dict[str, str] = field(default_factory=dict)  # rule_name -> query
    search_results: Dict[str, List[Dict]] = field(default_factory=dict)  # rule_name -> results
    lookback_seconds: int = 0


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
        # Don't add 'search' prefix if query already starts with a pipe command
        search_query = query if query.strip().startswith('|') else f"search {query}"
        data = {
            "search": search_query,
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

    def search_saved_search(self, search_name: str, earliest: str = "-15m") -> tuple:
        """Run a saved search and return (count, query, results)."""
        query = f'| savedsearch "{search_name}"'
        try:
            results = self.search(query, earliest=earliest)
            return len(results), query, results
        except Exception as e:
            print(f"      [DEBUG] Error running saved search: {e}")
            return 0, query, []


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
        # Build the PowerShell command (import module first for remote sessions)
        ps_cmd = 'Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1" -Force; '
        ps_cmd += f'Invoke-AtomicTest {technique_id} -TestGuids {test_guid}'

        if input_args:
            # PowerShell hashtables use semicolons as separators
            args_str = ';'.join(f'{k}="{v}"' for k, v in input_args.items())
            ps_cmd += f' -InputArgs @{{{args_str}}}'

        # -Cleanup runs cleanup commands after the test
        # -Force bypasses confirmation prompts
        if cleanup:
            ps_cmd += ' -Cleanup'

        ps_cmd += ' -Force'

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
        check_cmd = 'Import-Module "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1" -Force; Get-Command Invoke-AtomicTest'
        result = self._run_local(check_cmd) if self.target == "localhost" else self._run_remote(check_cmd)
        return result["success"] and "Invoke-AtomicTest" in result.get("output", "")


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
        lookback = wait_time + 60
        print(f"[*] Checking Splunk for triggered rules (lookback: {lookback}s)...")

        # Method 1: Check triggered alerts
        all_alerts = splunk.get_triggered_alerts(earliest=f"-{lookback}s")
        triggered_rules = [r for r in all_alerts if r in test.expected_rules]

        # Method 2: Also run each expected saved search directly
        search_queries = {}
        search_results = {}
        for rule_name in test.expected_rules:
            if rule_name not in triggered_rules:
                count, query, results = splunk.search_saved_search(rule_name, earliest=f"-{lookback}s")
                search_queries[rule_name] = query
                search_results[rule_name] = results
                if count > 0:
                    triggered_rules.append(rule_name)
                    print(f"    [+] {rule_name}: {count} matches")
                else:
                    print(f"    [-] {rule_name}: no matches")

    except Exception as e:
        error = str(e)
        print(f"[-] Error: {error}")
        search_queries = {}
        search_results = {}
        lookback = wait_time + 60

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
        error=error,
        search_queries=search_queries,
        search_results=search_results,
        lookback_seconds=lookback
    )


def generate_html_report(results: List[TestResult], output_path: str, timestamp: str):
    """Generate interactive HTML report with filtering."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    pass_rate = (passed / len(results) * 100) if results else 0

    # Build table rows
    table_rows = []
    for r in results:
        status_class = "passed" if r.passed else "failed"
        status_text = "PASS" if r.passed else "FAIL"
        expected = ", ".join(r.expected_rules)
        triggered = ", ".join(r.triggered_rules) if r.triggered_rules else "-"
        missing = ", ".join(r.missing_rules) if r.missing_rules else "-"
        error_text = r.error[:100] + "..." if r.error and len(r.error) > 100 else (r.error or "-")

        table_rows.append(f'''
            <tr class="{status_class}" data-status="{status_text}" data-technique="{r.technique_id}">
                <td><span class="status-badge {status_class}">{status_text}</span></td>
                <td>{r.test_name}</td>
                <td><code>{r.technique_id}</code></td>
                <td>{expected}</td>
                <td>{triggered}</td>
                <td>{missing}</td>
                <td class="error-cell" title="{r.error or ''}">{error_text}</td>
            </tr>
        ''')

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sigma Regression Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        header h1 {{
            font-size: 28px;
            margin-bottom: 5px;
        }}
        header .timestamp {{
            opacity: 0.7;
            font-size: 14px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .card h3 {{
            font-size: 14px;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 8px;
        }}
        .card .value {{
            font-size: 36px;
            font-weight: 700;
        }}
        .card.passed .value {{ color: #22c55e; }}
        .card.failed .value {{ color: #ef4444; }}
        .card.total .value {{ color: #3b82f6; }}
        .card.rate .value {{ color: #8b5cf6; }}
        .progress-section {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .progress-bar {{
            height: 24px;
            background: #fee2e2;
            border-radius: 12px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #22c55e, #16a34a);
            border-radius: 12px;
            transition: width 0.5s ease;
        }}
        .filters {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filters label {{
            font-weight: 500;
            color: #555;
        }}
        .filters select, .filters input {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }}
        .filters input {{
            width: 250px;
        }}
        .table-container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #f8fafc;
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            color: #475569;
            border-bottom: 2px solid #e2e8f0;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
        }}
        tr:hover {{
            background: #f8fafc;
        }}
        tr.hidden {{
            display: none;
        }}
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .status-badge.passed {{
            background: #dcfce7;
            color: #166534;
        }}
        .status-badge.failed {{
            background: #fee2e2;
            color: #991b1b;
        }}
        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }}
        .error-cell {{
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #991b1b;
            font-size: 13px;
        }}
        .legend {{
            display: flex;
            gap: 20px;
            margin-top: 10px;
            font-size: 14px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
        }}
        .legend-color.pass {{ background: #22c55e; }}
        .legend-color.fail {{ background: #ef4444; }}
        footer {{
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Sigma Regression Test Report</h1>
            <div class="timestamp">Generated: {timestamp}</div>
        </header>

        <div class="summary-cards">
            <div class="card total">
                <h3>Total Tests</h3>
                <div class="value">{len(results)}</div>
            </div>
            <div class="card passed">
                <h3>Passed</h3>
                <div class="value">{passed}</div>
            </div>
            <div class="card failed">
                <h3>Failed</h3>
                <div class="value">{failed}</div>
            </div>
            <div class="card rate">
                <h3>Pass Rate</h3>
                <div class="value">{pass_rate:.1f}%</div>
            </div>
        </div>

        <div class="progress-section">
            <strong>Overall Progress</strong>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {pass_rate}%"></div>
            </div>
            <div class="legend">
                <div class="legend-item"><div class="legend-color pass"></div> Passed ({passed})</div>
                <div class="legend-item"><div class="legend-color fail"></div> Failed ({failed})</div>
            </div>
        </div>

        <div class="filters">
            <label>Filter by Status:</label>
            <select id="statusFilter" onchange="filterTable()">
                <option value="all">All</option>
                <option value="PASS">Passed Only</option>
                <option value="FAIL">Failed Only</option>
            </select>
            <label>Search:</label>
            <input type="text" id="searchInput" placeholder="Search test name or technique..." onkeyup="filterTable()">
        </div>

        <div class="table-container">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Test Name</th>
                        <th>Technique</th>
                        <th>Expected Rules</th>
                        <th>Triggered Rules</th>
                        <th>Missing Rules</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(table_rows)}
                </tbody>
            </table>
        </div>

        <footer>
            <p>Generated by Sigma Regression Test Framework</p>
        </footer>
    </div>

    <script>
        function filterTable() {{
            const statusFilter = document.getElementById('statusFilter').value;
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#resultsTable tbody tr');

            rows.forEach(row => {{
                const status = row.getAttribute('data-status');
                const technique = row.getAttribute('data-technique').toLowerCase();
                const testName = row.cells[1].textContent.toLowerCase();

                const matchesStatus = statusFilter === 'all' || status === statusFilter;
                const matchesSearch = testName.includes(searchText) || technique.includes(searchText);

                if (matchesStatus && matchesSearch) {{
                    row.classList.remove('hidden');
                }} else {{
                    row.classList.add('hidden');
                }}
            }});
        }}
    </script>
</body>
</html>
'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def generate_report(results: List[TestResult], output_path: str):
    """Generate JSON and HTML test reports."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    timestamp = datetime.now().isoformat()

    report = {
        "timestamp": timestamp,
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
            "lookback_seconds": r.lookback_seconds,
            "search_queries": r.search_queries,
            "search_results": r.search_results,
            "error": r.error
        })

    # Write JSON report
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Write HTML report
    html_path = output_path.replace('.json', '.html')
    if html_path == output_path:
        html_path = output_path + '.html'
    generate_html_report(results, html_path, timestamp)

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

    print(f"\nReports saved to:")
    print(f"  JSON: {output_path}")
    print(f"  HTML: {html_path}")
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
    parser.add_argument('--batch', action='store_true', help='Run all atomics first, then check rules (faster)')

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

    if args.batch:
        # Batch mode: run all atomics first, then check all rules
        print("\n" + "="*60)
        print("BATCH MODE: Running all atomic tests first...")
        print("="*60)

        execution_results = {}
        for test in tests:
            print(f"\n[+] Executing: {test.name} ({test.technique_id})")
            result = runner.run_atomic(
                test.technique_id,
                test.atomic_test_guid,
                test.input_arguments,
                test.cleanup
            )
            execution_results[test.name] = result
            if result["success"]:
                print(f"    OK")
            else:
                print(f"    FAILED: {result.get('error', 'Unknown')[:50]}")

        print(f"\n[*] All atomics executed. Waiting {args.wait_time}s for log ingestion...")
        time.sleep(args.wait_time)

        print("\n" + "="*60)
        print("Checking Splunk for triggered rules...")
        print("="*60)

        lookback = args.wait_time + 120  # Extra buffer for batch mode

        for test in tests:
            start_time = time.time()
            exec_result = execution_results[test.name]
            error = exec_result.get('error') if not exec_result['success'] else None

            triggered_rules = []
            search_queries = {}
            search_results = {}

            print(f"\n[*] {test.name}")
            for rule_name in test.expected_rules:
                count, query, rule_results = splunk.search_saved_search(rule_name, earliest=f"-{lookback}s")
                search_queries[rule_name] = query
                search_results[rule_name] = rule_results
                if count > 0:
                    triggered_rules.append(rule_name)
                    print(f"    [+] {rule_name}: {count} matches")
                else:
                    print(f"    [-] {rule_name}: no matches")

            missing_rules = [r for r in test.expected_rules if r not in triggered_rules]
            passed = len(missing_rules) == 0 and error is None

            results.append(TestResult(
                test_name=test.name,
                technique_id=test.technique_id,
                atomic_guid=test.atomic_test_guid,
                passed=passed,
                expected_rules=test.expected_rules,
                triggered_rules=triggered_rules,
                missing_rules=missing_rules,
                execution_time=time.time() - start_time,
                error=error,
                search_queries=search_queries,
                search_results=search_results,
                lookback_seconds=lookback
            ))
    else:
        # Sequential mode: run each test and wait
        for test in tests:
            result = run_test(test, splunk, runner, args.wait_time)
            results.append(result)

    # Generate report
    generate_report(results, args.output)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
