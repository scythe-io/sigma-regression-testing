#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
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

Tab Completion:
    pip install argcomplete
    # Bash: eval "$(register-python-argcomplete regression-test.py)"
    # PowerShell: Register-ArgumentCompleter -Native -CommandName regression-test.py -ScriptBlock {
    #     param($wordToComplete, $commandAst, $cursorPosition)
    #     $env:_ARGCOMPLETE = 1
    #     $env:_ARGCOMPLETE_IFS = "`n"
    #     $env:COMP_LINE = $commandAst.ToString()
    #     $env:COMP_POINT = $cursorPosition
    #     python $commandAst.CommandElements[0].Value 2>$null | ForEach-Object { $_ }
    # }
"""

import argparse
import json
import time
import yaml
import requests
import urllib3
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# Optional tab completion support
try:
    import argcomplete
    HAS_ARGCOMPLETE = True
except ImportError:
    HAS_ARGCOMPLETE = False

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


@dataclass
class UntestedRule:
    """A rule that was not tested, with reason."""
    rule_name: str
    reason: str  # 'no_mapping', 'skipped_non_windows', 'error', 'excluded'
    details: Optional[str] = None


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
        # Don't prepend 'search' if query starts with a generating command (|)
        if query.strip().startswith('|'):
            search_query = query
        else:
            search_query = f"search {query}"
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
            # PowerShell hashtables use semicolons as separators, not commas
            # Newer ART versions use -InputArgs instead of -InputArguments
            args_str = ';'.join(f'{k}="{v}"' for k, v in input_args.items())
            ps_cmd += f' -InputArgs @{{{args_str}}}'

        # Note: Newer ART versions don't have -NoCleanup; cleanup is run separately
        ps_cmd += ' -Confirm:$false'

        if self.target == "localhost" and not self.use_winrm:
            result = self._run_local(ps_cmd)
        else:
            result = self._run_remote(ps_cmd)

        # Run cleanup if requested and test succeeded
        if cleanup and result.get("success"):
            cleanup_cmd = f'Invoke-AtomicTest {technique_id} -TestGuids {test_guid} -Cleanup -Confirm:$false'
            if self.target == "localhost" and not self.use_winrm:
                self._run_local(cleanup_cmd)
            else:
                self._run_remote(cleanup_cmd)

        return result

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
            # Import Atomic Red Team module before running command
            # The module may be in different locations depending on installation
            full_cmd = '''
$ErrorActionPreference = "SilentlyContinue"
# Try common ART installation paths
$artPaths = @(
    "C:\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1",
    "$env:USERPROFILE\\AtomicRedTeam\\invoke-atomicredteam\\Invoke-AtomicRedTeam.psd1"
)
foreach ($path in $artPaths) {
    if (Test-Path $path) {
        Import-Module $path -Force
        break
    }
}
$ErrorActionPreference = "Continue"
''' + ps_cmd
            result = session.run_ps(full_cmd)
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


def load_all_rules(conversion_report_path: str = None, savedsearches_path: str = None) -> Dict[str, List[str]]:
    """
    Load all available rules and categorize them.

    Returns dict with:
        - 'converted': List of rule names that were converted to Splunk
        - 'skipped': List of rules skipped (non-Windows)
        - 'failed': List of rules that failed conversion
    """
    rules = {'converted': [], 'skipped': [], 'failed': []}

    # Try conversion report first
    if conversion_report_path and Path(conversion_report_path).exists():
        with open(conversion_report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)

        # Get rule names from the report
        rules['skipped'] = report.get('details', {}).get('skipped', [])
        rules['failed'] = report.get('details', {}).get('failed', [])

        # For converted rules, we need to get actual names from savedsearches.conf
        # since the report only has filenames

    # Parse savedsearches.conf to get actual rule names
    if savedsearches_path and Path(savedsearches_path).exists():
        with open(savedsearches_path, 'r', encoding='utf-8') as f:
            content = f.read()

        import re
        # Match stanza names like [Rule Name Here]
        rule_names = re.findall(r'^\[([^\]]+)\]', content, re.MULTILINE)
        # Filter out 'default' stanza
        rules['converted'] = [name for name in rule_names if name.lower() != 'default']

    return rules


def get_tested_rules(tests: List['AtomicTest']) -> set:
    """Extract all rule names that are mapped to tests."""
    tested = set()
    for test in tests:
        tested.update(test.expected_rules)
    return tested


def categorize_untested_rules(
    all_rules: Dict[str, List[str]],
    tested_rules: set,
    test_results: List['TestResult'] = None
) -> List[UntestedRule]:
    """
    Categorize rules that were not tested.

    Returns list of UntestedRule with reasons:
        - no_mapping: Rule exists but no atomic test is mapped
        - skipped_non_windows: Rule was skipped (Linux, M365, etc.)
        - conversion_failed: Rule failed to convert to Splunk
        - test_error: Rule was mapped but test had an error
    """
    untested = []

    # Rules with test errors
    error_rules = set()
    if test_results:
        for result in test_results:
            if result.error:
                for rule in result.expected_rules:
                    error_rules.add(rule)
                    untested.append(UntestedRule(
                        rule_name=rule,
                        reason='test_error',
                        details=f"Test '{result.test_name}' error: {result.error[:100]}"
                    ))

    # Converted rules with no mapping
    for rule_name in all_rules.get('converted', []):
        if rule_name not in tested_rules and rule_name not in error_rules:
            untested.append(UntestedRule(
                rule_name=rule_name,
                reason='no_mapping',
                details='No Atomic Red Team test mapped to this rule'
            ))

    # Skipped rules (non-Windows)
    for filename in all_rules.get('skipped', []):
        # Extract a readable name from filename
        rule_name = filename.replace('.yml', '').replace('_', ' ').title()
        untested.append(UntestedRule(
            rule_name=rule_name,
            reason='skipped_non_windows',
            details=f'Rule file: {filename} (Linux/M365/non-Windows)'
        ))

    # Failed conversions
    for filename in all_rules.get('failed', []):
        rule_name = filename.replace('.yml', '').replace('_', ' ').title()
        untested.append(UntestedRule(
            rule_name=rule_name,
            reason='conversion_failed',
            details=f'Rule file: {filename} failed Splunk conversion'
        ))

    return untested


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


def load_inputs_file(inputs_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Load input arguments from a YAML file.

    Format:
        # By atomic GUID
        f1bf6c8f-9016-4edf-aff9-80b65f5d711f:
            username: "TestUser"
            password: "TestPass123!"

        # Or by test name
        "Create Local User Account":
            username: "MyUser"
    """
    with open(inputs_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def prompt_for_inputs(test: AtomicTest) -> Dict[str, Any]:
    """Prompt user for input arguments for a test."""
    if not test.input_arguments:
        return {}

    print(f"\n  Input arguments for: {test.name}")
    print(f"  (Press Enter to use default value shown in brackets)")

    inputs = {}
    for key, default_value in test.input_arguments.items():
        prompt = f"    {key} [{default_value}]: "
        user_input = input(prompt).strip()
        inputs[key] = user_input if user_input else default_value

    return inputs


def apply_inputs_from_file(tests: List[AtomicTest], inputs: Dict[str, Dict[str, Any]]) -> None:
    """Apply input arguments from file to tests (modifies tests in place)."""
    for test in tests:
        # Check by GUID first
        if test.atomic_test_guid in inputs:
            test.input_arguments.update(inputs[test.atomic_test_guid])
        # Then check by test name
        elif test.name in inputs:
            test.input_arguments.update(inputs[test.name])


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


def generate_html_report(results: List[TestResult], report: dict, output_path: str,
                         splunk_host: str = None, splunk_web_port: int = 8000, splunk_app: str = "search",
                         untested_rules: List[UntestedRule] = None):
    """Generate interactive HTML test report."""
    passed = report['summary']['passed']
    failed = report['summary']['failed']
    total = report['summary']['total_tests']
    pass_rate = report['summary']['pass_rate']
    untested_count = len(untested_rules) if untested_rules else 0

    # Calculate progress bar width
    pass_pct = (passed / total * 100) if total > 0 else 0

    # Build Splunk URL base for saved search links
    splunk_base_url = None
    if splunk_host:
        from urllib.parse import quote
        splunk_base_url = f"https://{splunk_host}:{splunk_web_port}/en-US/app/{splunk_app}"

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sigma Regression Test Results</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #333; margin-bottom: 20px; }}
        .timestamp {{ color: #666; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }}
        .card h3 {{ color: #666; font-size: 14px; margin-bottom: 8px; }}
        .card .value {{ font-size: 32px; font-weight: bold; }}
        .card.passed .value {{ color: #22c55e; }}
        .card.failed .value {{ color: #ef4444; }}
        .card.total .value {{ color: #3b82f6; }}
        .card.rate .value {{ color: #8b5cf6; }}
        .card.untested .value {{ color: #f59e0b; }}
        .progress-bar {{ background: #e5e7eb; height: 24px; border-radius: 12px; overflow: hidden; margin-bottom: 30px; }}
        .progress-fill {{ height: 100%; background: linear-gradient(90deg, #22c55e, #16a34a); width: {pass_pct}%; transition: width 0.3s; }}
        .filters {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
        .filters button {{ padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; }}
        .filters button.active {{ background: #3b82f6; color: white; border-color: #3b82f6; }}
        .filters input {{ padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; width: 250px; }}
        table {{ width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #f8fafc; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
        td {{ padding: 12px; border-bottom: 1px solid #e5e7eb; }}
        tr:hover {{ background: #f8fafc; }}
        .status {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .status.pass {{ background: #dcfce7; color: #166534; }}
        .status.fail {{ background: #fee2e2; color: #991b1b; }}
        .rules {{ font-size: 12px; color: #666; }}
        .rules a {{ color: #3b82f6; text-decoration: none; }}
        .rules a:hover {{ text-decoration: underline; }}
        .rules .missing {{ color: #ef4444; }}
        .rules .triggered {{ color: #22c55e; }}
        .hidden {{ display: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Sigma Regression Test Results</h1>
        <p class="timestamp">Generated: {report['timestamp']}</p>

        <div class="summary">
            <div class="card total"><h3>Total Tests</h3><div class="value">{total}</div></div>
            <div class="card passed"><h3>Passed</h3><div class="value">{passed}</div></div>
            <div class="card failed"><h3>Failed</h3><div class="value">{failed}</div></div>
            <div class="card rate"><h3>Pass Rate</h3><div class="value">{pass_rate}</div></div>
            <div class="card untested"><h3>Untested Rules</h3><div class="value">{untested_count}</div></div>
        </div>

        <div class="progress-bar"><div class="progress-fill"></div></div>

        <div class="filters">
            <button class="active" onclick="filterTests('all')">All</button>
            <button onclick="filterTests('pass')">Passed</button>
            <button onclick="filterTests('fail')">Failed</button>
            <input type="text" placeholder="Search tests..." onkeyup="searchTests(this.value)">
        </div>

        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Test Name</th>
                    <th>Technique</th>
                    <th>Expected Rules</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody>
'''

    for r in report['results']:
        status_class = 'pass' if r['passed'] else 'fail'
        status_text = 'PASS' if r['passed'] else 'FAIL'

        # Generate expected rules with Splunk links if available
        if splunk_base_url:
            expected_links = []
            for rule in r['expected_rules']:
                encoded_rule = quote(rule, safe='')
                # Link to run the saved search directly with last 15 minutes time range
                search_url = f"{splunk_base_url}/search?s=%2FservicesNS%2Fnobody%2F{splunk_app}%2Fsaved%2Fsearches%2F{encoded_rule}&earliest=-15m&latest=now"
                expected_links.append(f'<a href="{search_url}" target="_blank" title="Run in Splunk (last 15 min)">{rule}</a>')
            expected = ', '.join(expected_links)
        else:
            expected = ', '.join(r['expected_rules'])

        triggered = ', '.join(r['triggered_rules']) if r['triggered_rules'] else 'None'
        missing = ', '.join(r['missing_rules']) if r['missing_rules'] else ''

        result_html = f'<span class="triggered">Triggered: {triggered}</span>'
        if missing:
            result_html += f'<br><span class="missing">Missing: {missing}</span>'
        if r['error']:
            result_html += f'<br><span class="missing">Error: {r["error"]}</span>'

        # Build Atomic Red Team test link
        technique_id = r['technique_id']
        atomic_guid = r.get('atomic_guid', '')
        art_url = f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{technique_id}/{technique_id}.md"
        test_name_link = f'<a href="{art_url}" target="_blank" title="View Atomic Test: {atomic_guid}">{r["test_name"]}</a>'

        html += f'''                <tr data-status="{status_class}">
                    <td><span class="status {status_class}">{status_text}</span></td>
                    <td>{test_name_link}</td>
                    <td>{r['technique_id']}</td>
                    <td class="rules">{expected}</td>
                    <td class="rules">{result_html}</td>
                </tr>
'''

    html += '''            </tbody>
        </table>
'''

    # Add untested rules section if there are any
    if untested_rules:
        # Group by reason
        by_reason = {}
        for rule in untested_rules:
            if rule.reason not in by_reason:
                by_reason[rule.reason] = []
            by_reason[rule.reason].append(rule)

        reason_labels = {
            'no_mapping': ('No Test Mapping', 'Rules converted to Splunk but no Atomic Red Team test is mapped'),
            'skipped_non_windows': ('Non-Windows (Skipped)', 'Linux, M365, or other non-Windows rules not converted'),
            'conversion_failed': ('Conversion Failed', 'Rules that failed to convert to Splunk format'),
            'test_error': ('Test Error', 'Rules mapped to tests that encountered errors during execution'),
            'excluded': ('Excluded', 'Rules explicitly excluded from testing')
        }

        html += '''
        <h2 style="margin-top: 40px; color: #333;">Untested Rules</h2>
        <p style="color: #666; margin-bottom: 20px;">Rules that were not validated during this test run, grouped by reason.</p>
'''

        for reason, rules_list in by_reason.items():
            label, description = reason_labels.get(reason, (reason, ''))
            count = len(rules_list)

            # Determine color based on reason
            color_map = {
                'no_mapping': '#f59e0b',      # amber
                'skipped_non_windows': '#6b7280',  # gray
                'conversion_failed': '#ef4444',   # red
                'test_error': '#ef4444',          # red
                'excluded': '#6b7280'             # gray
            }
            color = color_map.get(reason, '#6b7280')

            html += f'''
        <div style="margin-bottom: 30px;">
            <h3 style="color: {color}; margin-bottom: 5px;">{label} ({count})</h3>
            <p style="color: #666; font-size: 14px; margin-bottom: 10px;">{description}</p>
            <table>
                <thead>
                    <tr>
                        <th>Rule Name</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
'''
            for rule in rules_list:
                details = rule.details or '-'
                html += f'''                    <tr>
                        <td>{rule.rule_name}</td>
                        <td style="font-size: 12px; color: #666;">{details}</td>
                    </tr>
'''
            html += '''                </tbody>
            </table>
        </div>
'''

    html += '''    </div>

    <script>
        function filterTests(status) {
            document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('tbody tr').forEach(row => {
                if (status === 'all' || row.dataset.status === status) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }

        function searchTests(query) {
            query = query.toLowerCase();
            document.querySelectorAll('tbody tr').forEach(row => {
                const text = row.textContent.toLowerCase();
                row.classList.toggle('hidden', !text.includes(query));
            });
        }
    </script>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_report(results: List[TestResult], output_path: str,
                    splunk_host: str = None, splunk_web_port: int = 8000, splunk_app: str = "search",
                    untested_rules: List[UntestedRule] = None):
    """Generate JSON and HTML test reports."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    # Count untested rules by reason
    untested_by_reason = {}
    if untested_rules:
        for rule in untested_rules:
            untested_by_reason[rule.reason] = untested_by_reason.get(rule.reason, 0) + 1

    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": len(results),
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{(passed/len(results)*100):.1f}%" if results else "N/A",
            "untested_rules_count": len(untested_rules) if untested_rules else 0,
            "untested_by_reason": untested_by_reason
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

    # Add untested rules to report
    if untested_rules:
        report["untested_rules"] = []
        for rule in untested_rules:
            report["untested_rules"].append({
                "rule_name": rule.rule_name,
                "reason": rule.reason,
                "details": rule.details
            })

    # Write JSON report
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Write HTML report
    html_path = output_path.replace('.json', '.html')
    generate_html_report(results, report, html_path, splunk_host, splunk_web_port, splunk_app, untested_rules)

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

    # Print untested rules summary
    if untested_rules:
        print(f"\nUntested Rules: {len(untested_rules)}")
        by_reason = {}
        for rule in untested_rules:
            by_reason[rule.reason] = by_reason.get(rule.reason, 0) + 1
        for reason, count in sorted(by_reason.items()):
            reason_label = {
                'no_mapping': 'No test mapping',
                'skipped_non_windows': 'Non-Windows (skipped)',
                'conversion_failed': 'Conversion failed',
                'test_error': 'Test error'
            }.get(reason, reason)
            print(f"  - {reason_label}: {count}")

    print(f"\nReports saved to:")
    print(f"  - {output_path}")
    print(f"  - {html_path}")
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


def list_tests(tests: List[AtomicTest], fields: List[str], output_format: str = 'table'):
    """Display tests in a formatted table or other format."""
    if not tests:
        print("No tests to display.")
        return

    # Define available fields and their display names
    field_map = {
        'name': ('Name', lambda t: t.name),
        'technique': ('Technique', lambda t: t.technique_id),
        'guid': ('Atomic GUID', lambda t: t.atomic_test_guid),
        'rules': ('Expected Rules', lambda t: ', '.join(t.expected_rules)),
        'description': ('Description', lambda t: t.description[:50] + '...' if len(t.description) > 50 else t.description),
        'cleanup': ('Cleanup', lambda t: 'Yes' if t.cleanup else 'No'),
        'inputs': ('Has Inputs', lambda t: 'Yes' if t.input_arguments else 'No'),
    }

    # Default fields if none specified
    if not fields:
        fields = ['name', 'technique', 'guid', 'rules']

    # Validate fields
    valid_fields = []
    for f in fields:
        f_lower = f.lower()
        if f_lower in field_map:
            valid_fields.append(f_lower)
        else:
            print(f"Warning: Unknown field '{f}'. Available: {', '.join(field_map.keys())}")

    if not valid_fields:
        valid_fields = ['name', 'technique', 'guid', 'rules']

    if output_format == 'csv':
        # CSV output
        headers = [field_map[f][0] for f in valid_fields]
        print(','.join(f'"{h}"' for h in headers))
        for test in tests:
            values = [field_map[f][1](test) for f in valid_fields]
            print(','.join(f'"{v}"' for v in values))
    else:
        # Table output - calculate column widths
        headers = [field_map[f][0] for f in valid_fields]
        rows = [[field_map[f][1](test) for f in valid_fields] for test in tests]

        # Calculate max width for each column
        widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                widths[i] = max(widths[i], len(str(val)))

        # Cap widths to prevent overly wide columns
        max_width = 60
        widths = [min(w, max_width) for w in widths]

        # Print header
        header_line = ' | '.join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(header_line)
        print('-' * len(header_line))

        # Print rows
        for row in rows:
            values = []
            for i, val in enumerate(row):
                val_str = str(val)
                if len(val_str) > widths[i]:
                    val_str = val_str[:widths[i]-3] + '...'
                values.append(val_str.ljust(widths[i]))
            print(' | '.join(values))

        print(f"\nTotal: {len(tests)} test(s)")


def main():
    parser = argparse.ArgumentParser(
        description='Sigma Rule Regression Testing with Atomic Red Team'
    )
    parser.add_argument('--splunk-host', help='Splunk server hostname (required unless using --list)')
    parser.add_argument('--splunk-port', type=int, default=8089, help='Splunk management port (REST API)')
    parser.add_argument('--splunk-web-port', type=int, default=8000, help='Splunk web UI port (for HTML report links)')
    parser.add_argument('--splunk-app', default='search', help='Splunk app context (default: search)')
    parser.add_argument('--splunk-user', default='admin', help='Splunk username')
    parser.add_argument('--splunk-pass', help='Splunk password (or SPLUNK_PASSWORD env var)')
    parser.add_argument('--target', default='localhost', help='Target for atomic tests')
    parser.add_argument('--winrm-user', help='WinRM username for remote targets')
    parser.add_argument('--winrm-pass', help='WinRM password for remote targets')
    parser.add_argument('--test-config', default='tests/art_mapping.yaml', help='Test mapping file')
    parser.add_argument('--output', default='test_results.json', help='Output report path')
    parser.add_argument('--wait-time', type=int, default=60, help='Seconds to wait after tests before querying Splunk')
    parser.add_argument('--lookback-window', type=int, default=None, help='Minutes to look back in Splunk when querying (overrides auto-calculated window)')
    parser.add_argument('--dry-run', action='store_true', help='Show tests without executing')
    parser.add_argument('--skip-atomic-check', action='store_true', help='Skip Atomic RT install check')
    parser.add_argument('--batch', action='store_true', help='Run all atomics first, then check rules (faster)')
    parser.add_argument('--parallel', action='store_true', help='Run atomic tests in parallel (implies --batch)')
    parser.add_argument('--test-id', action='append', help='Filter by atomic test GUID (can specify multiple)')
    parser.add_argument('--expected-rule', action='append', help='Filter by expected rule name (can specify multiple)')
    parser.add_argument('--technique', action='append', help='Filter by MITRE ATT&CK technique ID, e.g., T1018 (can specify multiple)')
    parser.add_argument('--list', action='store_true', help='List tests instead of running them (works with filters)')
    parser.add_argument('--fields', action='append', help='Fields to display with --list: name, technique, guid, rules, description, cleanup, inputs')
    parser.add_argument('--format', choices=['table', 'csv'], default='table', help='Output format for --list (default: table)')
    parser.add_argument('--prompt-inputs', action='store_true', help='Prompt for input arguments interactively')
    parser.add_argument('--inputs-file', help='YAML file with input arguments (overrides test config inputs)')
    parser.add_argument('--use-defaults', action='store_true', help='Use ART default values, ignore custom inputs')
    parser.add_argument('--conversion-report', default='splunk_output/conversion_report.json',
                        help='Path to Sigma conversion report JSON (for untested rules tracking)')
    parser.add_argument('--savedsearches', default='splunk_output/savedsearches.conf',
                        help='Path to Splunk savedsearches.conf (for untested rules tracking)')
    parser.add_argument('--skip-untested-report', action='store_true',
                        help='Skip generating the untested rules section in reports')

    # Enable tab completion if argcomplete is installed
    if HAS_ARGCOMPLETE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    # Load or create test config
    if not Path(args.test_config).exists():
        print(f"Creating example config at: {args.test_config}")
        create_example_config(args.test_config)
        print("Edit the configuration and run again.")
        return 0

    tests = load_test_config(args.test_config)
    total_tests = len(tests)

    # Filter tests by test ID (atomic GUID)
    if args.test_id:
        tests = [t for t in tests if t.atomic_test_guid in args.test_id]

    # Filter tests by technique ID (case-insensitive, supports partial match)
    if args.technique:
        filtered = []
        for t in tests:
            for tech in args.technique:
                if tech.lower() in t.technique_id.lower():
                    filtered.append(t)
                    break
        tests = filtered

    # Filter tests by expected rule name
    if args.expected_rule:
        filtered = []
        for t in tests:
            for rule in args.expected_rule:
                if any(rule.lower() in r.lower() for r in t.expected_rules):
                    filtered.append(t)
                    break
        tests = filtered

    if args.test_id or args.expected_rule or args.technique:
        print(f"Loaded {total_tests} test cases, filtered to {len(tests)} matching tests")
        if len(tests) == 0:
            print("\nNo tests matched the specified filters:")
            if args.test_id:
                print(f"  --test-id: {', '.join(args.test_id)}")
            if args.technique:
                print(f"  --technique: {', '.join(args.technique)}")
            if args.expected_rule:
                print(f"  --expected-rule: {', '.join(args.expected_rule)}")
            return 1
    else:
        print(f"Loaded {len(tests)} test cases from {args.test_config}")

    # List mode - display tests and exit
    if args.list:
        print()
        list_tests(tests, args.fields or [], args.format)
        return 0

    # Require splunk-host for non-list operations
    if not args.splunk_host:
        print("Error: --splunk-host is required (unless using --list)")
        return 1

    # Handle input arguments
    if args.use_defaults:
        # Clear all custom inputs, use ART defaults
        print("Using ART default input values (ignoring custom inputs)")
        for test in tests:
            test.input_arguments = {}
    elif args.inputs_file:
        # Load inputs from file
        if not Path(args.inputs_file).exists():
            print(f"Error: Inputs file not found: {args.inputs_file}")
            return 1
        print(f"Loading input arguments from: {args.inputs_file}")
        file_inputs = load_inputs_file(args.inputs_file)
        apply_inputs_from_file(tests, file_inputs)
    elif args.prompt_inputs:
        # Will prompt during test execution (handled later)
        print("Will prompt for input arguments during test execution")

    if args.dry_run:
        print("\n[DRY RUN] Tests to execute:")
        for test in tests:
            print(f"\n  {test.name}")
            print(f"    Technique: {test.technique_id}")
            print(f"    Atomic GUID: {test.atomic_test_guid}")
            print(f"    Expected Rules: {', '.join(test.expected_rules)}")
            if test.input_arguments:
                print(f"    Input Arguments:")
                for k, v in test.input_arguments.items():
                    print(f"      {k}: {v}")
            elif args.prompt_inputs:
                print(f"    Input Arguments: (will prompt)")
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

    # --parallel implies --batch
    if args.parallel:
        args.batch = True

    # If prompting for inputs, collect them upfront in batch mode
    if args.prompt_inputs and args.batch:
        print("\n[INPUT COLLECTION] Collecting input arguments for all tests...")
        print("="*60)
        for test in tests:
            if test.input_arguments:
                test.input_arguments = prompt_for_inputs(test)

    if args.batch:
        # Batch mode: run all atomics first, then check rules
        if args.parallel:
            print("\n[BATCH MODE] Executing all atomic tests in parallel...")
        else:
            print("\n[BATCH MODE] Executing all atomic tests first...")
        print("="*60)

        batch_start_time = time.time()
        print_lock = threading.Lock()

        def run_one(index_test):
            i, test = index_test
            result = runner.run_atomic(
                test.technique_id,
                test.atomic_test_guid,
                test.input_arguments,
                test.cleanup
            )
            status = "Executed successfully" if result["success"] else f"FAILED - {result.get('error', 'Unknown error')}"
            with print_lock:
                print(f"[{i}/{len(tests)}] {test.name}")
                print(f"    Technique: {test.technique_id}")
                print(f"    Atomic GUID: {test.atomic_test_guid}")
                print(f"    Status: {status}")
            return (test, result)

        atomic_results = []
        if args.parallel:
            print(f"Launching {len(tests)} tests concurrently (max 5 parallel WinRM sessions)...")
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(run_one, (i, test)): i for i, test in enumerate(tests, 1)}
                ordered = {}
                for future in as_completed(futures):
                    test, result = future.result()
                    ordered[futures[future]] = (test, result)
            # Preserve original test order
            atomic_results = [ordered[i] for i in sorted(ordered)]
        else:
            for i, test in enumerate(tests, 1):
                print(f"\n[{i}/{len(tests)}] {test.name}")
                print(f"    Technique: {test.technique_id}")
                print(f"    Atomic GUID: {test.atomic_test_guid}")
                result = runner.run_atomic(
                    test.technique_id,
                    test.atomic_test_guid,
                    test.input_arguments,
                    test.cleanup
                )
                if result["success"]:
                    print(f"    Status: Executed successfully")
                else:
                    print(f"    Status: FAILED - {result.get('error', 'Unknown error')}")
                atomic_results.append((test, result))

        # Wait for log ingestion
        print(f"\n{'='*60}")
        print(f"All atomics executed. Waiting {args.wait_time}s for log ingestion...")
        print("="*60)
        time.sleep(args.wait_time)

        # Calculate query lookback window
        if args.lookback_window:
            # User-specified lookback in minutes
            query_earliest = f"-{args.lookback_window}m"
            print(f"\nUsing lookback window: {args.lookback_window} minutes")
        else:
            # Auto-calculate: time since first test started + 120s buffer
            elapsed = int(time.time() - batch_start_time)
            query_earliest = f"-{elapsed + 120}s"
            print(f"\nAuto lookback window: {elapsed + 120}s (elapsed: {elapsed}s)")

        # Check rules for all tests
        print("\n[BATCH MODE] Checking Splunk for detections...")
        print("="*60)

        for i, (test, atomic_result) in enumerate(atomic_results, 1):
            print(f"\n[{i}/{len(tests)}] {test.name}")

            start_time = time.time()
            triggered_rules = []
            error = atomic_result.get('error') if not atomic_result['success'] else None

            # Check for triggered rules
            all_alerts = splunk.get_triggered_alerts(earliest=query_earliest)
            triggered_rules = [r for r in all_alerts if r in test.expected_rules]

            # Also run each expected saved search directly
            for rule_name in test.expected_rules:
                if rule_name not in triggered_rules:
                    count = splunk.search_saved_search(rule_name, earliest=query_earliest)
                    if count > 0:
                        triggered_rules.append(rule_name)
                        print(f"    [+] {rule_name}: {count} matches")
                    else:
                        print(f"    [-] {rule_name}: no matches")

            missing_rules = [r for r in test.expected_rules if r not in triggered_rules]
            passed = len(missing_rules) == 0 and error is None

            status = "PASS" if passed else "FAIL"
            print(f"    Result: {status}")

            results.append(TestResult(
                test_name=test.name,
                technique_id=test.technique_id,
                atomic_guid=test.atomic_test_guid,
                passed=passed,
                expected_rules=test.expected_rules,
                triggered_rules=triggered_rules,
                missing_rules=missing_rules,
                execution_time=time.time() - start_time,
                error=error
            ))
    else:
        # Sequential mode: run each test and check individually
        for test in tests:
            # Prompt for inputs if requested
            if args.prompt_inputs and test.input_arguments:
                test.input_arguments = prompt_for_inputs(test)
            result = run_test(test, splunk, runner, args.wait_time)
            results.append(result)

    # Collect untested rules information
    untested_rules = None
    if not args.skip_untested_report:
        all_rules = load_all_rules(args.conversion_report, args.savedsearches)
        tested_rules = get_tested_rules(tests)
        untested_rules = categorize_untested_rules(all_rules, tested_rules, results)

    # Generate report
    generate_report(results, args.output, args.splunk_host, args.splunk_web_port, args.splunk_app, untested_rules)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
