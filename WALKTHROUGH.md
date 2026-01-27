# Sigma Detection Engineering Pipeline - Walkthrough

This document provides a step-by-step guide for engineers to understand, set up, and use the Sigma detection engineering pipeline.

---

## Table of Contents

1. [What This Project Does](#what-this-project-does)
2. [Prerequisites](#prerequisites)
3. [Setup Instructions](#setup-instructions)
4. [Pipeline Walkthrough](#pipeline-walkthrough)
   - [Step 1: Validate Sigma Rules](#step-1-validate-sigma-rules)
   - [Step 2: Convert Rules to Splunk Format](#step-2-convert-rules-to-splunk-format)
   - [Step 3: Deploy to Splunk](#step-3-deploy-to-splunk)
   - [Step 4: Run Regression Tests](#step-4-run-regression-tests)
5. [Understanding the Output](#understanding-the-output)
6. [Troubleshooting](#troubleshooting)

---

## What This Project Does

This project provides an automated pipeline for:

1. **Writing detection rules** in Sigma format (vendor-agnostic YAML)
2. **Validating rules** automatically via CI/CD
3. **Converting rules** to Splunk saved searches
4. **Deploying rules** to a Splunk instance via REST API
5. **Testing rules** using Atomic Red Team attacks to verify detections work

```
┌─────────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  Write  │     │ Validate │     │ Convert │     │ Deploy  │     │  Test   │
│  Rules  │────►│  (CI)    │────►│   to    │────►│   to    │────►│  with   │
│ (.yml)  │     │          │     │ Splunk  │     │ Splunk  │     │ Atomics │
└─────────┘     └──────────┘     └─────────┘     └─────────┘     └─────────┘
```

---

## Prerequisites

### On Your Workstation

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.9+ | Run conversion and testing scripts |
| PowerShell | 5.1+ or 7+ | Deploy to Splunk |
| Git | Any | Clone repository |

### Python Packages

```bash
pip install sigma-cli pysigma pysigma-backend-splunk pysigma-pipeline-windows PyYAML pywinrm
```

### Infrastructure Requirements

| Component | Purpose | Notes |
|-----------|---------|-------|
| Splunk Server | Detection platform | Need admin credentials and REST API access (port 8089) |
| Windows Test Endpoint | Attack simulation | Must have Atomic Red Team installed, WinRM enabled |
| Sysmon | Log collection | Installed on test endpoint, forwarding to Splunk |

### Test Endpoint Setup (Windows)

1. **Install Atomic Red Team:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force -InstallPath "C:\AtomicRedTeam"
```

2. **Enable WinRM:**

```powershell
Enable-PSRemoting -Force
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

3. **Install and Configure Sysmon:**

```powershell
# Download Sysmon from Microsoft Sysinternals
# Apply a configuration (e.g., SwiftOnSecurity config)
sysmon64.exe -accepteula -i sysmonconfig.xml
```

4. **Configure Splunk Universal Forwarder** to send logs to your Splunk instance.

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/Sigma.git
cd Sigma
```

### 2. Install Python Dependencies

```bash
pip install sigma-cli pysigma pysigma-backend-splunk pysigma-pipeline-windows PyYAML pywinrm
```

### 3. Verify Installation

```bash
sigma version
```

**Expected output:**
```
sigma version 0.9.x or pySigma version 0.x.x
```

---

## Pipeline Walkthrough

### Step 1: Validate Sigma Rules

Validation ensures all rules are syntactically correct and follow Sigma specifications.

**Command:**
```bash
sigma check SCYTHE_Rules/*.yml
```

**Expected output (success):**
```
Checking 75 rules...

No issues found in 75 rules.
```

**Expected output (with errors):**
```
Checking 75 rules...

SCYTHE_Rules/proc_creation_win_bad_rule.yml:
  - error: Missing required field 'logsource'
  - warning: No 'falsepositives' field defined

1 rule with errors, 74 rules OK
```

### Step 2: Convert Rules to Splunk Format

The conversion script transforms Sigma YAML rules into Splunk's `savedsearches.conf` format.

**Command (list compatible rules first):**
```bash
python scripts/convert-to-splunk.py --list-compatible
```

**Expected output:**
```
Compatible Windows rules found: 55

Rules that will be converted:
  1. proc_creation_win_conti_discovery.yml
  2. proc_creation_win_domain_enumeration.yml
  3. proc_creation_win_encoded_ps_execution.yml
  ...
  55. reg_set_win_run_key_modification.yml

Run without --list-compatible to perform conversion.
```

**Command (perform conversion):**
```bash
python scripts/convert-to-splunk.py -i SCYTHE_Rules -o splunk_output
```

**Expected output:**
```
Sigma to Splunk Converter
=========================

Processing Windows rules from SCYTHE_Rules...
  ✓ proc_creation_win_conti_discovery.yml
  ✓ proc_creation_win_domain_enumeration.yml
  ✓ proc_creation_win_encoded_ps_execution.yml
  ...

Conversion Summary
==================
Total rules processed: 55
Successfully converted: 55
Failed conversions: 0

Output files:
  - splunk_output/savedsearches.conf (55 searches)
  - splunk_output/conversion_report.json
```

**Verify the output:**
```bash
head -30 splunk_output/savedsearches.conf
```

**Expected output:**
```conf
# Sigma Rules - Converted to Splunk Saved Searches
# Generated: 2026-01-27T10:30:00
# Total searches: 55

[Conti Ransomware Discovery Commands]
description = Detects commands commonly used by Conti ransomware for system discovery
search = index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 \
    (CommandLine="*systeminfo*" OR CommandLine="*whoami*" OR CommandLine="*ipconfig*" OR CommandLine="*hostname*")
dispatch.earliest_time = -24h
dispatch.latest_time = now
```

### Step 3: Deploy to Splunk

The PowerShell script deploys the converted saved searches to your Splunk instance.

**Command (dry run - validates without deploying):**
```powershell
.\scripts\deploy-to-splunk.ps1 -SplunkHost splunk.yourcompany.com -Username admin -DryRun
```

**Expected output:**
```
============================================================
Splunk Saved Search Deployment
============================================================

Parsing splunk_output/savedsearches.conf...
Found 55 saved searches

[DRY RUN] Would deploy the following searches:
  - Conti Ransomware Discovery Commands
    Search: index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/...
  - Domain Discovery via NET Command
    Search: index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/...
  - Encoded PowerShell Execution
    Search: index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/...
  ...

Run without -DryRun to deploy to Splunk
```

**Command (actual deployment):**
```powershell
.\scripts\deploy-to-splunk.ps1 -SplunkHost splunk.yourcompany.com -Username admin
```

You will be prompted for the Splunk admin password.

**Expected output:**
```
============================================================
Splunk Saved Search Deployment
============================================================

Parsing splunk_output/savedsearches.conf...
Found 55 saved searches

Authenticating with Splunk at splunk.yourcompany.com:8089...
Authentication successful

Deploying saved searches to app: search
----------------------------------------
Deploying: Conti Ransomware Discovery Commands... CREATED
Deploying: Domain Discovery via NET Command... CREATED
Deploying: Encoded PowerShell Execution... CREATED
Deploying: Windows Event Log Manipulation via PowerShell... CREATED
...

============================================================
Deployment Summary
============================================================
Created: 55
Updated: 0
Failed:  0

Deployment complete! Searches are available in Splunk under:
  Settings -> Searches, reports, and alerts
```

**If running again (updates existing):**
```
Deploying: Conti Ransomware Discovery Commands... UPDATED
Deploying: Domain Discovery via NET Command... UPDATED
...

============================================================
Deployment Summary
============================================================
Created: 0
Updated: 55
Failed:  0
```

### Step 4: Run Regression Tests

The regression test script executes Atomic Red Team attacks on a test endpoint and verifies the Splunk rules detect them.

**Command (dry run - shows test plan without executing):**
```bash
python scripts/regression-test.py \
  --splunk-host splunk.yourcompany.com \
  --test-config tests/art_mapping.yaml \
  --dry-run
```

**Expected output:**
```
Sigma Rule Regression Testing (DRY RUN)
=======================================

Test Configuration: tests/art_mapping.yaml
Total tests defined: 19

Test Plan:
----------
  1. Clear Security Event Log (wevtutil)
     Technique: T1070.001
     Atomic GUID: e6abb60e-26b8-41da-8aae-0c35174b0967
     Expected rules:
       - Windows Event Log Manipulation via PowerShell

  2. System Information Discovery
     Technique: T1082
     Atomic GUID: 66571c33-5533-4b71-8d3f-02626c89c5dc
     Expected rules:
       - Conti Ransomware Discovery Commands

  3. Hostname Discovery
     Technique: T1082
     Atomic GUID: 88f11004-d6a7-43b2-84ab-ebf7e3f8cb10
     Expected rules:
       - Conti Ransomware Discovery Commands
  ...

DRY RUN complete. No tests were executed.
```

**Command (full test execution):**
```bash
python scripts/regression-test.py \
  --splunk-host splunk.yourcompany.com \
  --splunk-user admin \
  --target 192.168.1.100 \
  --winrm-user "YOURDOM\Administrator" \
  --winrm-pass "YourPassword123!" \
  --test-config tests/art_mapping.yaml \
  --wait-time 60 \
  --skip-atomic-check
```

**Expected output:**
```
Sigma Rule Regression Testing
=============================

Configuration:
  Splunk Host: splunk.yourcompany.com
  Target Endpoint: 192.168.1.100
  Test Config: tests/art_mapping.yaml
  Wait Time: 60 seconds

Authenticating with Splunk...
Authentication successful

Running tests (sequential mode)...

[1/19] Clear Security Event Log (wevtutil)
  Executing atomic: T1070.001 (e6abb60e-26b8-41da-8aae-0c35174b0967)
  Waiting 60 seconds for log ingestion...
  Checking Splunk for detections...
  Expected: Windows Event Log Manipulation via PowerShell
  Triggered: (none)
  Result: FAIL

[2/19] System Information Discovery
  Executing atomic: T1082 (66571c33-5533-4b71-8d3f-02626c89c5dc)
  Waiting 60 seconds for log ingestion...
  Checking Splunk for detections...
  Expected: Conti Ransomware Discovery Commands
  Triggered: Conti Ransomware Discovery Commands
  Result: PASS

[3/19] Hostname Discovery
  Executing atomic: T1082 (88f11004-d6a7-43b2-84ab-ebf7e3f8cb10)
  Waiting 60 seconds for log ingestion...
  Checking Splunk for detections...
  Expected: Conti Ransomware Discovery Commands
  Triggered: Conti Ransomware Discovery Commands
  Result: PASS

...

============================================================
Test Results Summary
============================================================
Total Tests: 19
Passed: 7
Failed: 12
Pass Rate: 36.8%

Output files:
  - test_results.json
  - test_results.html
```

**Batch mode (faster for large test suites):**
```bash
python scripts/regression-test.py \
  --splunk-host splunk.yourcompany.com \
  --splunk-user admin \
  --target 192.168.1.100 \
  --winrm-user "YOURDOM\Administrator" \
  --winrm-pass "YourPassword123!" \
  --test-config tests/art_mapping.yaml \
  --wait-time 90 \
  --skip-atomic-check \
  --batch
```

**Expected output (batch mode):**
```
Sigma Rule Regression Testing (Batch Mode)
==========================================

Phase 1: Executing all atomic tests...
  [1/19] Clear Security Event Log (wevtutil)... executed
  [2/19] System Information Discovery... executed
  [3/19] Hostname Discovery... executed
  ...
  [19/19] UAC Bypass via ICacls... executed

All atomics executed. Waiting 90 seconds for log ingestion...

Phase 2: Checking Splunk for detections...
  [1/19] Clear Security Event Log (wevtutil)... FAIL
  [2/19] System Information Discovery... PASS
  [3/19] Hostname Discovery... PASS
  ...

============================================================
Test Results Summary
============================================================
Total Tests: 19
Passed: 7
Failed: 12
Pass Rate: 36.8%
```

---

## Understanding the Output

### test_results.json

Machine-readable results for automation/integration:

```json
{
  "summary": {
    "total": 19,
    "passed": 7,
    "failed": 12,
    "pass_rate": 36.84
  },
  "tests": [
    {
      "name": "System Information Discovery",
      "technique_id": "T1082",
      "atomic_guid": "66571c33-5533-4b71-8d3f-02626c89c5dc",
      "status": "passed",
      "expected_rules": ["Conti Ransomware Discovery Commands"],
      "triggered_rules": ["Conti Ransomware Discovery Commands"],
      "missing_rules": [],
      "execution_time": "2026-01-27T10:45:23Z"
    },
    ...
  ]
}
```

### test_results.html

Interactive HTML report with:

- **Summary cards** showing total tests, passed, failed, pass rate
- **Visual progress bar** for quick pass/fail overview
- **Filterable table** (filter by All/Passed/Failed or search text)
- **Clickable Splunk links** for each expected rule (opens saved search with last 15 minutes)

Open in any browser:
```bash
# Linux/macOS
open test_results.html

# Windows
start test_results.html
```

### savedsearches.conf

Standard Splunk configuration file. Can be:
- Deployed via REST API (as shown above)
- Copied directly to `$SPLUNK_HOME/etc/apps/search/local/`
- Imported via Splunk Web UI

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `sigma check` fails | Invalid YAML syntax | Check for missing colons, bad indentation |
| 401 Unauthorized on deploy | Wrong credentials | Verify Splunk username/password |
| WinRM connection failed | WinRM not enabled | Run `Enable-PSRemoting -Force` on target |
| Atomic test not found | ART not installed | Install Atomic Red Team to `C:\AtomicRedTeam` |
| Rule doesn't fire | Log not reaching Splunk | Check Splunk forwarder, verify Sysmon events |
| No events in Splunk | Wrong index/sourcetype | Verify `index` and `sourcetype` in search |

### Verify Logs Are Reaching Splunk

Run this search in Splunk to confirm Sysmon events are arriving:

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
| sort -count
```

You should see EventCode 1 (Process Create), EventCode 13 (Registry), etc.

### Test a Rule Manually

1. Run an atomic test manually on the endpoint:
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
Invoke-AtomicTest T1082 -TestGuids 66571c33-5533-4b71-8d3f-02626c89c5dc
```

2. Check Splunk for the detection:
```spl
| savedsearch "Conti Ransomware Discovery Commands"
```

### Debug WinRM Connectivity

```powershell
# From your workstation
Test-WSMan -ComputerName 192.168.1.100

# Should return XML response with ProductVersion, etc.
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Validate rules | `sigma check SCYTHE_Rules/*.yml` |
| Convert to Splunk | `python scripts/convert-to-splunk.py -i SCYTHE_Rules -o splunk_output` |
| Deploy (dry run) | `.\scripts\deploy-to-splunk.ps1 -SplunkHost HOST -Username USER -DryRun` |
| Deploy (actual) | `.\scripts\deploy-to-splunk.ps1 -SplunkHost HOST -Username USER` |
| Test (dry run) | `python scripts/regression-test.py --splunk-host HOST --test-config tests/art_mapping.yaml --dry-run` |
| Test (full) | `python scripts/regression-test.py --splunk-host HOST --splunk-user USER --target IP --winrm-user USER --winrm-pass PASS --test-config tests/art_mapping.yaml` |

---

## Next Steps

After completing this walkthrough:

1. **Add new detection rules** - Create `.yml` files in `SCYTHE_Rules/` following existing patterns
2. **Map tests** - Add entries to `tests/art_mapping.yaml` for new rules
3. **Tune rules** - Investigate failed tests and adjust detection logic
4. **Enable alerts** - Use `--EnableAlerts` flag to configure scheduled alerting
5. **Automate via CI/CD** - Configure GitHub secrets for fully automated deployment

---

## Support

- **Documentation**: See [README.md](README.md) and [OVERVIEW.md](OVERVIEW.md)
- **Issues**: Report bugs at the repository's Issues page
- **Sigma Resources**: [SigmaHQ](https://github.com/SigmaHQ/sigma)
- **Atomic Red Team**: [atomicredteam.io](https://atomicredteam.io/)
