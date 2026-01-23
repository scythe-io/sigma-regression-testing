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
| `file_creation` | File creation events | 1 |
| `security_*` | Security event logs | 1 |

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
│   └── sync-aurora-rules.ps1  # Aurora endpoint sync script
└── .github/workflows/
    ├── sigma-validate.yml     # CI validation workflow
    └── deploy-rules.yml       # Deployment workflow
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

### Deployment Workflow (`deploy-rules.yml`)

Template for deploying validated rules to endpoints.

**Triggers:**
- Manual only (workflow_dispatch)
- Choose environment: `staging` or `production`
- Option for dry-run

**Pipeline:**

```
┌─────────────────────────────────────────────────────────────┐
│  VALIDATE-FIRST JOB                                         │
├─────────────────────────────────────────────────────────────┤
│  1. Run sigma check on all rules                            │
│  2. If validation fails → ABORT deployment                  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼ (only if validation passes)
┌─────────────────────────────────────────────────────────────┐
│  DEPLOY JOB                                                 │
├─────────────────────────────────────────────────────────────┤
│  1. Package rules                                           │
│  2. Deploy via Azure Blob / AWS S3 / SSH (configure one)    │
│  3. Create deployment summary                               │
└─────────────────────────────────────────────────────────────┘
```

### End-to-End Flow

```
Developer pushes rule change
            │
            ▼
┌───────────────────────┐
│  PR Created           │
│  sigma-validate runs  │──── FAIL ───→ PR blocked, fix required
└───────────────────────┘
            │
          PASS
            │
            ▼
┌───────────────────────┐
│  PR Merged to main    │
│  Release artifact     │
│  created              │
└───────────────────────┘
            │
            ▼
┌───────────────────────┐
│  Manual trigger       │
│  deploy-rules.yml     │──→ Rules pushed to file share/cloud
└───────────────────────┘
            │
            ▼
┌───────────────────────┐
│  Endpoints pull       │
│  new rules            │
└───────────────────────┘
```

## Aurora EDR Integration

These rules are compatible with [Aurora Agent](https://www.nextron-systems.com/aurora/) from Nextron Systems.

### Manual Installation

Copy rules to Aurora's custom signatures folder:

```powershell
Copy-Item .\SCYTHE_Rules\*.yml "C:\Program Files\Aurora-Agent\custom-signatures\"
Restart-Service "intend Aurora Agent Service"
```

### Automated Sync from GitHub

Use the included sync script to automatically pull rules from this repository:

```powershell
# One-time sync
.\scripts\sync-aurora-rules.ps1 -GitHubRepo "scythe-io/Sigma"

# Sync and restart Aurora
.\scripts\sync-aurora-rules.ps1 -GitHubRepo "scythe-io/Sigma" -RestartAurora $true

# Custom branch
.\scripts\sync-aurora-rules.ps1 -GitHubRepo "scythe-io/Sigma" -Branch "develop"
```

### Scheduled Task Setup

Create a scheduled task to keep rules updated:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File 'C:\Scripts\sync-aurora-rules.ps1' -GitHubRepo 'scythe-io/Sigma' -RestartAurora `$true"

$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"

Register-ScheduledTask -TaskName "Sync-Aurora-Sigma-Rules" `
    -Action $action -Trigger $trigger -RunLevel Highest `
    -User "SYSTEM"
```

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
