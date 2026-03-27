# Project Overview

This document explains the Sigma Regression Testing project in layman's terms, including what it does, how the pipelines work, and what has been tested.

## What This Project Is

This is a collection of **detection rules** that help security teams find hackers and malware on their systems. Think of each rule as a "red flag pattern" - when something suspicious happens (like a hacker running a command to steal passwords), the rule recognizes it and raises an alert.

The rules are written in **Sigma**, which is like a universal language for detection rules. The advantage is that you write the rule once, and it can be translated to work with whatever security tool your company uses - Splunk, Elastic, Microsoft Sentinel, etc.

Currently there are **128 rules** covering:
- **Windows** (82 rules) - detecting suspicious processes, registry changes, file activity, network connections, DNS queries, and credential access
- **Linux** (17 rules) - detecting privilege escalation, backdoors, reconnaissance
- **Microsoft 365/Cloud** (8 rules) - detecting mailbox tampering, suspicious SharePoint activity
- **Azure** (4 rules) - detecting cloud resource modifications and firewall changes

---

## What the Workflows Do

There are 3 automated pipelines that run in GitHub when code changes:

### 1. Validation Workflow (`sigma-validate.yml`)
**Purpose:** Quality control - makes sure rules are properly formatted before they're accepted.

**How it works:**
- When someone submits a new rule (via pull request), GitHub automatically checks it
- If the rule has errors (typos, missing fields, bad syntax), the submission is blocked
- If the rule passes, it gets a green checkmark and can be merged

### 2. Splunk Pipeline (`splunk-pipeline.yml`)
**Purpose:** Converts rules to Splunk format, commits results, and optionally deploys them.

**How it works:**
- Takes the Sigma rules and translates them into Splunk's "saved searches" format
- **Automatically commits** the generated `savedsearches.conf` back to the repository
- Can automatically push those searches to your Splunk server (if secrets configured)
- Can also run automated tests to verify the rules actually detect attacks

### 3. Deployment Workflow (`deploy-rules.yml`)
**Purpose:** (Work in progress) Will push rules to endpoints running detection tools.

---

## What We've Tested So Far

We've successfully validated the end-to-end pipeline from writing a rule to it running in Splunk:

| Step | Status | What We Did |
|------|--------|-------------|
| **Rule Upload** | Tested | 128 Sigma rules across Windows, Linux, M365, and Azure |
| **Validation** | Tested | All rules pass `sigma check` - no syntax errors |
| **Conversion** | Tested | Ran `convert-to-splunk.py` to generate `savedsearches.conf` for Windows-compatible rules |
| **Auto-Commit** | Tested | Workflow automatically commits `savedsearches.conf` to repo on rule changes |
| **Push to Splunk** | Tested | Deployed saved searches to Splunk using `deploy-to-splunk.ps1` |
| **Regression Testing** | Tested | 40 Atomic Red Team test mappings across process, file, network, registry, and DNS event types |

### Atomic Red Team Coverage

Rules are mapped to verified Atomic Red Team tests in `tests/art_mapping.yaml`. Each mapping was confirmed by checking the actual ART executor command against the Sigma detection logic — only tests that genuinely trigger the rule are included.

Coverage spans multiple log source categories:
- **Process creation** - LOLBin abuse, defense evasion, persistence, credential access
- **Registry** - WDigest caching, Defender exclusions, UAC bypass, logon script persistence
- **File events** - LSASS dump files, startup folder writes
- **Network connections** - Regsvr32 and Rundll32 remote payload delivery
- **DNS queries** - Regsvr32 COM scriptlet resolution

### Earlier Regression Test Results

Using the `regression-test.py` script with Atomic Red Team on a remote Windows target:

- **7 tests passed** - Rules correctly detected the atomic attacks
- **12 tests needed tuning** - Identified rule gaps and detection logic mismatches

Passing tests include:
- Event log clearing detection
- Discovery command detection (systeminfo, whoami, ipconfig, hostname)
- PowerShell download cradle detection

### Issues We Fixed Along the Way
1. **PowerShell `$Host` conflict** - The deploy script used a reserved variable name; renamed to `$Server`
2. **Missing .NET class** - `System.Web.HttpUtility` wasn't available in PowerShell Core; switched to `[uri]::EscapeDataString()`
3. **Multi-line search parsing** - Searches with line continuations (`\`) weren't being parsed correctly; fixed the parser
4. **ART module loading** - WinRM sessions need explicit module import from `C:\AtomicRedTeam`
5. **Splunk REST API query syntax** - Fixed `| savedsearch` commands to not add `search` prefix
6. **ART parameter changes** - Updated to use `-Force` and `-InputArgs` for newer ART versions

---

## Installation

Install all required dependencies with:

```bash
pip install -r requirements.txt
```

This installs:
- `sigma-cli`, `pysigma` - Rule validation and conversion
- `pysigma-backend-splunk`, `pysigma-pipeline-windows` - Splunk conversion
- `PyYAML`, `requests` - Core dependencies
- `pywinrm` - Remote Atomic Red Team execution

For tab completion support, also install:
```bash
pip install argcomplete
```

---

## What's Next

- **Rule tuning** - Investigate why some rules didn't fire and adjust detection logic
- **Scheduled alerts** - Enable the saved searches to run automatically and send notifications
- **Aurora EDR integration** - Deploy rules to endpoint detection agents
- **CI/CD integration** - Automate regression testing on rule changes

---

## Pipeline & Script Flowchart

```text
                                    ┌─────────────────────────────────┐
                                    │      WRITE SIGMA RULES          │
                                    │   (sigma_rules/*.yml)          │
                                    └───────────────┬─────────────────┘
                                                    │
                                                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                           GITHUB ACTIONS (Automatic)                          │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │  sigma-validate.yml                                                  │    │
│   │  ─────────────────                                                   │    │
│   │  Trigger: Every push/PR                                              │    │
│   │                                                                      │    │
│   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │    │
│   │  │ sigma check  │───►│  Pass/Fail   │───►│ Package rules as     │   │    │
│   │  │ (validate)   │    │  PR gates    │    │ downloadable artifact│   │    │
│   │  └──────────────┘    └──────────────┘    └──────────────────────┘   │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│   ┌─────────────────────────────────────────────────────────────────────┐    │
│   │  splunk-pipeline.yml                                                 │    │
│   │  ───────────────────                                                 │    │
│   │  Trigger: Merge to main / Manual                                     │    │
│   │                                                                      │    │
│   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────────┐   │    │
│   │  │   Convert    │───►│ Auto-commit  │───►│   Deploy     │───►│ Regression Test │   │    │
│   │  │  to Splunk   │    │  to repo     │    │  to Splunk   │    │ (Atomic Red Team)│   │    │
│   │  └──────────────┘    └──────────────┘    └──────────────┘    └─────────────────┘   │    │
│   └─────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘


┌───────────────────────────────────────────────────────────────────────────────┐
│                           LOCAL SCRIPTS (Manual)                              │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│                        ┌────────────────────────┐                             │
│                        │  update-readme-stats.py │                            │
│                        │  ──────────────────────  │                            │
│                        │  Counts rules, updates   │                            │
│                        │  README.md statistics    │                            │
│                        └────────────────────────┘                             │
│                                                                               │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │                                                                       │   │
│   │  sigma_rules/*.yml                                                   │   │
│   │         │                                                             │   │
│   │         ▼                                                             │   │
│   │  ┌─────────────────────┐      ┌─────────────────────────────────┐    │   │
│   │  │ convert-to-splunk.py│      │  Output: splunk_output/         │    │   │
│   │  │ ─────────────────── │─────►│  ├── savedsearches.conf         │    │   │
│   │  │ Python script       │      │  └── conversion_report.json     │    │   │
│   │  └─────────────────────┘      └─────────────────┬───────────────┘    │   │
│   │                                                 │                     │   │
│   │                                                 ▼                     │   │
│   │                               ┌─────────────────────────────────┐    │   │
│   │                               │ deploy-to-splunk.ps1            │    │   │
│   │                               │ ────────────────────            │    │   │
│   │                               │ PowerShell script               │    │   │
│   │                               │                                 │    │   │
│   │                               │ • Parses savedsearches.conf     │    │   │
│   │                               │ • Authenticates via REST API    │    │   │
│   │                               │ • Creates/updates saved searches│    │   │
│   │                               └─────────────────┬───────────────┘    │   │
│   │                                                 │                     │   │
│   │                                                 ▼                     │   │
│   │                               ┌─────────────────────────────────┐    │   │
│   │                               │         SPLUNK SERVER           │    │   │
│   │                               │                                 │    │   │
│   │                               │  Saved Searches deployed        │    │   │
│   │                               └─────────────────────────────────┘    │   │
│   │                                                                       │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │  regression-test.py                                                    │   │
│   │  ──────────────────                                                   │   │
│   │                                                                       │   │
│   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐    │   │
│   │  │ Run Atomic   │───►│ Wait for     │───►│ Query Splunk for     │    │   │
│   │  │ Red Team     │    │ logs to      │    │ matching alerts      │    │   │
│   │  │ attack       │    │ arrive       │    │ (pass/fail)          │    │   │
│   │  └──────────────┘    └──────────────┘    └──────────────────────┘    │   │
│   │                                                                       │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## Simple Version

```text
  ┌─────────┐      ┌──────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐
  │  Write  │      │ Validate │      │ Convert │      │ Deploy  │      │  Test   │
  │  Rules  │─────►│  (CI)    │─────►│   to    │─────►│   to    │─────►│  with   │
  │ (.yml)  │      │          │      │ Splunk  │      │ Splunk  │      │ Atomics │
  └─────────┘      └──────────┘      └─────────┘      └─────────┘      └─────────┘
                        │                 │                │
                        ▼                 ▼                ▼
                   sigma check     convert-to-       deploy-to-
                   (GitHub)        splunk.py         splunk.ps1
                                        │
                                        ▼
                                  Auto-commit
                                  to repo
                                        │
                                        ▼
                                                   ┌─────────────┐
                                                   │   SPLUNK    │
                                                   │   SERVER    │
                                                   │  ┌───────┐  │
                                                   │  │Saved  │  │
                                                   │  │Search │  │
                                                   │  │ x 55  │  │
                                                   │  └───────┘  │
                                                   └─────────────┘
```

---

## Script Reference

| Script | Language | Purpose |
|--------|----------|---------|
| `convert-to-splunk.py` | Python | Converts Sigma YAML rules to Splunk `savedsearches.conf` format |
| `deploy-to-splunk.ps1` | PowerShell | Deploys saved searches to Splunk via REST API |
| `regression-test.py` | Python | Runs Atomic Red Team tests, validates Splunk detections, generates JSON and HTML reports |
| `update-readme-stats.py` | Python | Updates README.md with current rule counts |
| `Enable-TabCompletion.ps1` | PowerShell | Enables tab completion for regression-test.py in PowerShell |

## Key Files

| File | Purpose |
|------|---------|
| `requirements.txt` | Python dependencies - install with `pip install -r requirements.txt` |
| `tests/art_mapping.yaml` | Atomic Red Team test to Sigma rule mappings |
| `splunk_output/savedsearches.conf` | Generated Splunk saved searches (auto-updated by CI) |

---

## Regression Testing Details

The `regression-test.py` script supports two modes:

**Sequential Mode** (default): Runs each atomic test, waits for logs, checks the rule, then moves to the next test. Thorough but slow.

**Batch Mode** (`--batch`): Runs all atomic tests back-to-back, waits once for log ingestion, then checks all rules at the end. Much faster for large test suites.

### Key Parameters

| Parameter | Description |
|-----------|-------------|
| `--splunk-host` | Splunk server hostname |
| `--splunk-user` | Splunk username |
| `--splunk-web-port` | Splunk web UI port for HTML links (default: 8000) |
| `--splunk-app` | Splunk app context (default: search) |
| `--target` | Remote Windows target IP for atomic tests |
| `--winrm-user` | WinRM username (e.g., `DOMAIN\Administrator`) |
| `--winrm-pass` | WinRM password |
| `--test-config` | Path to test mapping YAML file |
| `--wait-time` | Seconds to wait for log ingestion (default: 60) |
| `--batch` | Run all atomics first, then check rules (faster) |
| `--skip-atomic-check` | Skip checking if ART is installed |
| `--dry-run` | Show tests without executing |
| `--test-id` | Filter by atomic test GUID (can specify multiple) |
| `--technique` | Filter by MITRE ATT&CK technique ID, e.g., T1018 (can specify multiple) |
| `--expected-rule` | Filter by expected rule name - partial match (can specify multiple) |
| `--list` | List tests instead of running them (works with filters) |
| `--fields` | Fields to show with --list: name, technique, guid, rules, description, cleanup, inputs |
| `--format` | Output format for --list: table (default) or csv |
| `--prompt-inputs` | Interactively prompt for input arguments |
| `--inputs-file` | Load input arguments from YAML file |
| `--use-defaults` | Ignore custom inputs, use ART default values |
| `--conversion-report` | Path to Sigma conversion report (for untested rules tracking) |
| `--savedsearches` | Path to Splunk savedsearches.conf (for untested rules tracking) |
| `--skip-untested-report` | Skip generating the untested rules section |

### Test Output

The script generates two output files:

**`test_results.json`** - Machine-readable results containing:
- Pass/fail status for each test
- Expected vs triggered rules
- Splunk search queries and results
- Execution time and lookback window

**`test_results.html`** - Interactive HTML report with:
- Summary cards (total tests, passed, failed, pass rate, untested rules count)
- Visual progress bar showing pass/fail ratio
- Filterable table (filter by status or search text)
- Detailed view of expected, triggered, and missing rules for each test
- **Clickable Splunk links** - Each expected rule is a hyperlink that opens the saved search directly in Splunk with a 15-minute time range
- **Untested Rules Section** - Shows which rules were not covered by any test:
  - No test mapping (rule exists but no Atomic test mapped)
  - Non-Windows/skipped (Linux, M365, or other non-Windows rules)
  - Conversion failed (rules that failed Splunk conversion)
  - Test error (tests that encountered errors during execution)

Open `test_results.html` in any browser to review results interactively.
