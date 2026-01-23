# SCYTHE Sigma Detection Rules

A curated collection of Sigma detection rules developed by SCYTHE for threat detection and hunting. These rules are designed to detect adversary techniques, malware behaviors, and suspicious activity across Windows, Linux, and Microsoft 365 environments.

## Overview

| Metric | Count |
|--------|-------|
| **Total Rules** | 61 |
| **Windows Rules** | 42 |
| **Linux Rules** | 13 |
| **M365/Cloud Rules** | 6 |

### Rule Categories

| Category | Description | Count |
|----------|-------------|-------|
| `proc_creation` | Process creation events | 41 |
| `file_event` | File system activity | 7 |
| `reg_set` | Registry modifications | 4 |
| `m365_*` | Microsoft 365 audit logs | 3 |
| `net_connection` | Network connections | 2 |
| `web_sharepoint` | SharePoint web activity | 2 |
| `security_*` | Security event logs | 1 |
| `file_creation` | File creation events | 1 |

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

```
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
│   └── regression-test.py     # SCYTHE integration regression testing
├── tests/
│   └── test_mapping.yaml      # SCYTHE action to rule mappings
├── splunk_output/             # Generated Splunk artifacts (gitignored)
├── wip/                       # Work in progress (not production ready)
│   └── aurora/                # Aurora EDR integration (coming soon)
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

```
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

A complete detection engineering pipeline for deploying Sigma rules to Splunk and validating them with SCYTHE atomic actions.

### Pipeline Overview

```
┌─────────────────────────────────────────────────────────────┐
│  CONVERT JOB                                                │
├─────────────────────────────────────────────────────────────┤
│  1. Validate Sigma rules                                    │
│  2. Convert Windows rules to Splunk savedsearches.conf      │
│  3. Generate conversion report                              │
│  4. Upload artifacts                                        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (on merge to main or manual trigger)
┌─────────────────────────────────────────────────────────────┐
│  DEPLOY JOB                                                 │
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
│  1. Execute SCYTHE atomic actions                           │
│  2. Query Splunk for triggered rules                        │
│  3. Report coverage and failures                            │
└─────────────────────────────────────────────────────────────┘
```

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

**Run regression tests:**

```bash
# Dry run (show test cases without executing)
python scripts/regression-test.py --dry-run --test-config tests/test_mapping.yaml

# Run tests with SCYTHE
python scripts/regression-test.py \
  --splunk-host splunk.company.com \
  --splunk-user admin \
  --scythe-url https://scythe.company.com \
  --test-config tests/test_mapping.yaml
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
| `SCYTHE_API_URL` | SCYTHE API endpoint |
| `SCYTHE_API_KEY` | SCYTHE API key |

### Test Mapping Configuration

Define test cases in `tests/test_mapping.yaml`:

```yaml
tests:
  - name: "Event Log Clearing"
    description: "Test detection of Windows event log clearing"
    scythe_action: "run"
    scythe_params:
      command: "wevtutil cl Security"
    expected_rules:
      - "Windows Event Log Cleared"
    mitre_technique: "T1070.001"
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

```
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
- [Aurora Agent Documentation](https://aurora-agent-manual.nextron-systems.com/)
- [SCYTHE Platform](https://www.scythe.io/)

## License

See [LICENSE](LICENSE) for details.
