# Roadmap

Planned features and enhancements for the Sigma Regression Testing pipeline.

---

## Linux Testing Support

Extend the regression testing pipeline to cover the 16 Linux detection rules currently in `sigma_rules/`.

**What needs to be built:**

- **SSH execution in `regression-test.py`** — add `--ssh-user`, `--ssh-pass`/`--ssh-key`, and `--ssh-port` flags so the runner can connect to a Linux target instead of using WinRM. Execution method selected automatically based on target OS or a new `--os` flag.
- **Linux rule conversion in `convert-to-splunk.py`** — extend the converter to include Linux rules using the appropriate pySigma Linux pipeline. Requires clarifying what field names Linux process creation events land on in Splunk (depends on log source — syslog, Splunk UF with Linux add-on, etc.).
- **Linux ART mappings in `tests/art_mapping.yaml`** — map each Linux rule to an Atomic Red Team test GUID. ART has Linux atomics for most relevant techniques.
- **Infrastructure** — Linux target machine with Atomic Red Team installed, SSH enabled, Sysmon-for-Linux or equivalent log forwarding to Splunk.

**Open questions before starting:**
- What Linux target is available and how are Linux process/file/network events ingested into Splunk?
- What field names do Linux events land on (`CommandLine`/`Image` like Windows, or `process`/`cmd`)?

---

## M365 and Azure Testing Support

Extend the pipeline to cover the 5 M365 and 4 Azure detection rules currently in `sigma_rules/`.

**What needs to be built:**

- **M365/Azure test executor in `regression-test.py`** — add an API-based execution method (Microsoft Graph API or Exchange Online / SharePoint PowerShell modules) to trigger M365 actions (SharePoint file upload/deletion, user creation, mailbox permission changes) and Azure operations (firewall rule modification, security group changes). Separate from WinRM/SSH execution.
- **M365/Azure rule conversion in `convert-to-splunk.py`** — extend the converter to handle `m365` and `azure` logsources. Field mapping depends on how M365 audit and Azure Activity Logs are ingested into Splunk (Microsoft 365 Add-on, Azure Monitor Add-on, or Event Hub).
- **M365/Azure ART mappings in `tests/art_mapping.yaml`** — map each rule to a test action. Some M365 techniques have ART atomics; others may need custom test scripts.
- **Infrastructure** — M365 tenant with test credentials, Azure subscription with sufficient permissions, M365 audit logging enabled and forwarded to Splunk.

**Open questions before starting:**
- What M365 tenant and credentials are available for testing?
- How are M365 audit logs and Azure Activity Logs currently ingested into Splunk?

---

## Multi-SIEM Backend Support

Allow the conversion pipeline to target SIEMs other than Splunk by making the backend configurable.

**What needs to be built:**

- **Backend flag in `convert-to-splunk.py`** (or rename to `convert-to-siem.py`) — add a `--backend` argument supporting at minimum: `splunk`, `elastic`, `sentinel`, `qradar`. Uses the corresponding pySigma backend package for each.
- **Output format handling** — each backend produces different output formats (Splunk: `savedsearches.conf`; Elastic: NDJSON/EQL; Sentinel: KQL `.json`; QRadar: AQL). Output file naming and format should adapt automatically.
- **Backend-specific pipelines** — each SIEM requires the correct pySigma pipeline (e.g. `splunk_windows`, `ecs_windows`, `windows_audit`). The converter should select the right pipeline per backend automatically.
- **CI/CD parameterization** — update `splunk-pipeline.yml` and `deploy-rules.yml` GitHub Actions workflows to accept a backend parameter so conversions for multiple SIEMs can be triggered from a single push.
- **Deploy scripts** — `deploy-to-splunk.ps1` is Splunk-specific; add equivalent deploy scripts or a unified deploy layer for other backends.

**Supported pySigma backends to consider:**

| SIEM | pySigma Package | Output Format |
|------|----------------|---------------|
| Splunk | `pySigma-backend-splunk` | `savedsearches.conf` |
| Elastic / OpenSearch | `pySigma-backend-elasticsearch` | EQL / Lucene NDJSON |
| Microsoft Sentinel | `pySigma-backend-microsoft365defender` | KQL |
| IBM QRadar | `pySigma-backend-qradar` | AQL |
| CrowdStrike | `pySigma-backend-crowdstrike` | CrowdStrike Query Language |
| Panther | `pySigma-backend-panther` | Panther rules |
