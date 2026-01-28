# SCYTHE Sigma Detection Rules

A detection engineering pipeline for developing, validating, deploying, and testing Sigma rules. This project includes a curated collection of detection rules for Windows, Linux, and Microsoft 365 environments, along with automated tooling to convert rules to Splunk format, deploy them via REST API, and validate detections using Atomic Red Team tests.

> **New here?** See [OVERVIEW.md](OVERVIEW.md) for a plain-English explanation of the project, pipeline flowcharts, and testing status.

## Overview

| Metric | Count |
|--------|-------|
| **Total Rules** | 75 |
| **Windows Rules** | 44 |
| **Linux Rules** | 13 |
| **M365/Cloud Rules** | 8 |

### Rule Categories

| Category | Description | Count |
|----------|-------------|-------|
| `proc_creation` | Process creation events | 45 |
| `file_event` | File system activity | 7 |
| `m365_*` | Microsoft 365 audit logs | 5 |
| `reg_set` | Registry modifications | 4 |
| `sysmon_lockbitv3` | Other events | 3 |
| `net_connection` | Network connections | 2 |
| `sysmon_ALPHVblackcat` | Other events | 2 |
| `web_sharepoint` | SharePoint web activity | 2 |
| `security_*` | Security event logs | 1 |
| `file_creation` | File creation events | 1 |
| `sysmon_medusa` | Other events | 1 |
| `sysmon_RAS` | Other events | 1 |
| `sysmon_netconnect` | Other events | 1 |

## Rule Design Philosophy

These rules are designed with the following principles:

1. **Low False Positive Rate** - Filters for package managers, config management tools, and legitimate admin activity
2. **Behavioral Focus** - Detect techniques, not just IOCs (no hardcoded hashes or IPs)
3. **Production Ready** - All rules pass `sigma check` validation
4. **MITRE ATT&CK Mapped** - Tagged with relevant technique IDs

## Quick Start

### Validate Rules

```bash
# Install sigma-cli
pip install sigma-cli pysigma

# Validate all rules
sigma check SCYTHE_Rules/*.yml
```

### Convert to SIEM Format

```bash
# Convert to Splunk
sigma convert -t splunk SCYTHE_Rules/*.yml

# Convert to Elastic
sigma convert -t elasticsearch SCYTHE_Rules/*.yml

# Convert to Microsoft Sentinel
sigma convert -t microsoft365defender SCYTHE_Rules/*.yml
```

## Repository Structure

```text
.
├── SCYTHE_Rules/              # Sigma detection rules
│   ├── proc_creation_*.yml    # Process creation rules
│   ├── file_event_*.yml       # File event rules
│   ├── reg_set_*.yml          # Registry rules
│   ├── net_connection_*.yml   # Network rules
│   └── m365_*.yml             # Microsoft 365 rules
├── scripts/
│   ├── update-readme-stats.py # Auto-update README statistics
│   ├── convert-to-splunk.py   # Convert rules to Splunk format
│   ├── deploy-to-splunk.ps1   # Deploy saved searches to Splunk
│   └── regression-test.py     # Atomic Red Team regression testing
├── tests/
│   └── art_mapping.yaml       # Atomic Red Team test to rule mappings
├── splunk_output/             # Generated Splunk artifacts (auto-updated)
│   ├── savedsearches.conf     # Splunk saved searches (auto-generated)
│   └── conversion_report.json # Conversion statistics
├── wip/                       # Work in progress (not production ready)
│   ├── aurora/                # Aurora EDR integration (coming soon)
│   └── scythe/                # SCYTHE integration (coming soon)
└── .github/workflows/
    ├── sigma-validate.yml     # CI validation workflow
    ├── splunk-pipeline.yml    # Splunk detection pipeline
    └── deploy-rules.yml       # Deployment workflow (WIP)
```

## CI/CD Pipeline

This repository includes GitHub Actions workflows for automated validation and deployment.

### Validation Workflow (`sigma-validate.yml`)

Automatically validates rules on every code change.

**Triggers:**
- Push to `main` branch (when `SCYTHE_Rules/` changes)
- Pull requests to `main` branch
- Manual trigger

**Pipeline:**

```text
┌─────────────────────────────────────────────────────────────┐
│  VALIDATE JOB (runs on every PR and push)                   │
├─────────────────────────────────────────────────────────────┤
│  1. Checkout code                                           │
│  2. Install Python 3.11 + sigma-cli                         │
│  3. Run: sigma check SCYTHE_Rules/*.yml                     │
│  4. If errors found → FAIL (blocks PR merge)                │
│  5. If clean → PASS and display rule count                  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (only on merge to main)
┌─────────────────────────────────────────────────────────────┐
│  RELEASE JOB                                                │
├─────────────────────────────────────────────────────────────┤
│  1. Package all .yml rules                                  │
│  2. Upload as downloadable artifact (90 day retention)      │
│  3. Create summary with commit and rule count               │
└─────────────────────────────────────────────────────────────┘
```

### Deployment Workflow (`deploy-rules.yml`) - WIP

> **Status: Work in Progress** - Template available but not yet configured for production use.

Template for deploying validated rules to endpoints. Supports Azure Blob, AWS S3, and SSH deployment options.

## Splunk Detection Pipeline

A complete detection engineering pipeline for deploying Sigma rules to Splunk and validating them with [Atomic Red Team](https://atomicredteam.io/) tests.

### Pipeline Overview

```text
┌─────────────────────────────────────────────────────────────┐
│  CONVERT JOB                                                │
├─────────────────────────────────────────────────────────────┤
│  1. Validate Sigma rules                                    │
│  2. Convert Windows rules to Splunk savedsearches.conf      │
│  3. Generate conversion report                              │
│  4. Commit savedsearches.conf back to repository            │
│  5. Upload artifacts                                        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (on merge to main or manual trigger)
┌─────────────────────────────────────────────────────────────┐
│  DEPLOY JOB (requires secrets configured)                   │
├─────────────────────────────────────────────────────────────┤
│  1. Download converted artifacts                            │
│  2. Deploy saved searches to Splunk via REST API            │
│  3. Configure alerts (optional)                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (manual trigger only)
┌─────────────────────────────────────────────────────────────┐
│  REGRESSION TEST JOB                                        │
├─────────────────────────────────────────────────────────────┤
│  1. Execute Atomic Red Team tests on target endpoint        │
│  2. Query Splunk for triggered rules                        │
│  3. Report coverage and failures                            │
└─────────────────────────────────────────────────────────────┘
```

> **Note:** The `savedsearches.conf` file is automatically regenerated and committed to the repository whenever Sigma rules change. You can always find the latest converted rules in `splunk_output/savedsearches.conf`.

### Local Usage

**Convert rules to Splunk format:**

```bash
# Install dependencies
pip install sigma-cli pysigma pysigma-backend-splunk pysigma-pipeline-windows PyYAML

# List compatible rules
python scripts/convert-to-splunk.py --list-compatible

# Convert all rules
python scripts/convert-to-splunk.py -i SCYTHE_Rules -o splunk_output
```

**Deploy to Splunk:**

```powershell
# Deploy saved searches (interactive)
.\scripts\deploy-to-splunk.ps1 -SplunkHost splunk.company.com -Username admin

# Deploy with alerts enabled
.\scripts\deploy-to-splunk.ps1 -SplunkHost splunk.company.com -Username admin -EnableAlerts -AlertEmail soc@company.com

# Dry run (validate without deploying)
.\scripts\deploy-to-splunk.ps1 -SplunkHost splunk.company.com -Username admin -DryRun
```

**Run regression tests with Atomic Red Team:**

```bash
# Dry run (show test cases without executing)
python scripts/regression-test.py --splunk-host splunk.company.com --dry-run --test-config tests/art_mapping.yaml

# Run tests on remote target via WinRM (sequential mode)
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --splunk-user admin \
  --target 192.168.1.100 \
  --winrm-user "DOMAIN\Administrator" \
  --winrm-pass "password" \
  --test-config tests/art_mapping.yaml \
  --wait-time 60 \
  --skip-atomic-check

# Batch mode (faster - runs all tests first, then checks rules)
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --splunk-user admin \
  --target 192.168.1.100 \
  --winrm-user "DOMAIN\Administrator" \
  --winrm-pass "password" \
  --test-config tests/art_mapping.yaml \
  --wait-time 90 \
  --skip-atomic-check \
  --batch
```

**Test Output:**

The regression test script generates two output files:

- `test_results.json` - Machine-readable results with pass/fail status, queries, and timing
- `test_results.html` - Interactive HTML report with filtering and visual summary

The HTML report includes:
- Summary cards showing total tests, passed, failed, and pass rate
- Visual progress bar for quick pass/fail overview
- Filterable table by status (All/Passed/Failed) and search text
- Details for each test including expected rules, triggered rules, and missing rules
- **Clickable Splunk links** for each expected rule that open the saved search directly in Splunk (with last 15 minutes time range)

**Additional Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--splunk-web-port` | 8000 | Splunk web UI port (for HTML report links) |
| `--splunk-app` | search | Splunk app context for saved searches |
| `--test-id` | (all) | Filter by atomic test GUID (can specify multiple) |
| `--expected-rule` | (all) | Filter by expected rule name - partial match (can specify multiple) |

**Run specific tests:**

```bash
# Run a single test by GUID
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --test-config tests/art_mapping.yaml \
  --test-id f1bf6c8f-9016-4edf-aff9-80b65f5d711f \
  --dry-run

# Run tests for a specific rule (partial match)
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --test-config tests/art_mapping.yaml \
  --expected-rule "Domain Discovery" \
  --dry-run

# Run multiple specific tests
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --test-config tests/art_mapping.yaml \
  --test-id f1bf6c8f-9016-4edf-aff9-80b65f5d711f \
  --test-id 80887bec-5a9b-4efc-a81d-f83eb2eb32ab \
  --skip-atomic-check
```

### Installing Atomic Red Team

On the test endpoint, install Atomic Red Team to a system-wide location (required for WinRM access):

```powershell
# Install Invoke-AtomicRedTeam module to C:\AtomicRedTeam
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force -InstallPath "C:\AtomicRedTeam"

# Verify installation
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Get-Command Invoke-AtomicTest
```

### GitHub Actions Setup

To enable automated deployment, configure these secrets in your repository:

| Secret | Description |
|--------|-------------|
| `SPLUNK_HOST` | Splunk server hostname |
| `SPLUNK_PORT` | Management port (default: 8089) |
| `SPLUNK_USER` | Splunk admin username |
| `SPLUNK_PASSWORD` | Splunk admin password |
| `SPLUNK_APP` | Target app (default: search) |

### Test Mapping Configuration

Define test cases in `tests/art_mapping.yaml` to map Atomic Red Team tests to expected Sigma rules:

```yaml
tests:
  - name: "Clear Security Event Log"
    description: "Validates detection of log clearing via wevtutil"
    technique_id: "T1070.001"
    atomic_test_guid: "e6abb60e-26b8-41da-8aae-0c35174b0967"
    expected_rules:
      - "Windows Event Log Manipulation"  # Must match Splunk saved search name exactly
    cleanup: false

  - name: "Create Local User Account"
    description: "Creates a new local user"
    technique_id: "T1136.001"
    atomic_test_guid: "a524ce99-86de-4f6c-88f5-8c3439e21ed5"
    expected_rules:
      - "Local User Account Creation via New-LocalUser PowerShell Cmdlet"
    input_arguments:
      username: "TestUser"
      password: "P@ssw0rd123!"
```

**Important:** The `expected_rules` values must match the Splunk saved search names exactly. These are the Sigma rule titles from the YAML files.

Find Atomic Test GUIDs at [atomicredteam.io](https://atomicredteam.io/atomics/) or by running:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
Invoke-AtomicTest T1070.001 -ShowDetailsBrief
```

## Aurora EDR Integration

> **Status: Work in Progress**
>
> Aurora integration is under development. See `wip/aurora/` for preliminary scripts.

These rules are compatible with [Aurora Agent](https://www.nextron-systems.com/aurora/) from Nextron Systems.

### Manual Installation

Copy rules to Aurora's custom signatures folder:

```powershell
Copy-Item .\SCYTHE_Rules\*.yml "C:\Program Files\Aurora-Agent\custom-signatures\"
Restart-Service "intend Aurora Agent Service"
```

Automated sync and deployment tooling coming soon.

## Contributing

### Adding New Rules

1. Create a new `.yml` file in `SCYTHE_Rules/`
2. Follow the naming convention: `<logsource>_<description>.yml`
3. Ensure the rule passes validation: `sigma check your-rule.yml`
4. Submit a pull request

### Rule Requirements

- Must pass `sigma check` validation
- Must include MITRE ATT&CK technique tags (e.g., `attack.t1059.001`)
- Must include `falsepositives` section
- Must include appropriate `level` (low/medium/high/critical)
- Should include filters to reduce false positives

### Naming Convention

```text
<logsource>_<platform>_<description>.yml

Examples:
  proc_creation_win_susp_rundll32.yml
  proc_creation_lnx_docker_priv.yml
  file_event_win_archive_creation.yml
  m365_mailbox_delegation.yml
```

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://atomicredteam.io/)
- [Aurora Agent Documentation](https://aurora-agent-manual.nextron-systems.com/)
- [SCYTHE Platform](https://www.scythe.io/)

## License

See [LICENSE](LICENSE) for details.
