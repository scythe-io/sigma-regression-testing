# Project Overview

This document explains the Sigma detection rules project in layman's terms, including what it does, how the pipelines work, and what has been tested.

## What This Project Is

This is a collection of **detection rules** that help security teams find hackers and malware on their systems. Think of each rule as a "red flag pattern" - when something suspicious happens (like a hacker running a command to steal passwords), the rule recognizes it and raises an alert.

The rules are written in **Sigma**, which is like a universal language for detection rules. The advantage is that you write the rule once, and it can be translated to work with whatever security tool your company uses - Splunk, Elastic, Microsoft Sentinel, etc.

Currently there are **61 rules** covering:
- **Windows** (42 rules) - detecting suspicious processes, registry changes, file activity
- **Linux** (13 rules) - detecting privilege escalation, backdoors, reconnaissance
- **Microsoft 365/Cloud** (6 rules) - detecting mailbox tampering, suspicious SharePoint activity

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
**Purpose:** Converts rules to Splunk format and optionally deploys them.

**How it works:**
- Takes the Sigma rules and translates them into Splunk's "saved searches" format
- Can automatically push those searches to your Splunk server
- Can also run automated tests to verify the rules actually detect attacks

### 3. Deployment Workflow (`deploy-rules.yml`)
**Purpose:** (Work in progress) Will push rules to endpoints running detection tools.

---

## What We've Tested So Far

We've successfully validated the end-to-end pipeline from writing a rule to it running in Splunk:

| Step | Status | What We Did |
|------|--------|-------------|
| **Rule Upload** | Tested | Added 61 Sigma rules to the repository |
| **Validation** | Tested | All rules pass `sigma check` - no syntax errors |
| **Conversion** | Tested | Ran `convert-to-splunk.py` to generate `savedsearches.conf` with 43 Windows rules |
| **Push to Splunk** | Tested | Deployed all 43 saved searches to `splunk.example.com` using `deploy-to-splunk.ps1` |

### Issues We Fixed Along the Way
1. **PowerShell `$Host` conflict** - The deploy script used a reserved variable name; renamed to `$Server`
2. **Missing .NET class** - `System.Web.HttpUtility` wasn't available in PowerShell Core; switched to `[uri]::EscapeDataString()`
3. **Multi-line search parsing** - Searches with line continuations (`\`) weren't being parsed correctly; fixed the parser

---

## What's Next (Not Yet Tested)

- **Regression testing** - Running Atomic Red Team attacks and verifying Splunk detects them
- **Scheduled alerts** - Enabling the saved searches to run automatically and send notifications
- **Aurora EDR integration** - Deploying rules to endpoint detection agents

---

## Pipeline & Script Flowchart

```text
                                    ┌─────────────────────────────────┐
                                    │      WRITE SIGMA RULES          │
                                    │   (SCYTHE_Rules/*.yml)          │
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
│   │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │    │
│   │  │   Convert    │───►│   Deploy     │───►│  Regression Test     │   │    │
│   │  │  to Splunk   │    │  to Splunk   │    │  (Atomic Red Team)   │   │    │
│   │  └──────────────┘    └──────────────┘    └──────────────────────┘   │    │
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
│   │  SCYTHE_Rules/*.yml                                                   │   │
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
│   │  regression-test.py  (Not yet tested)                                 │   │
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
                                                   ┌─────────────┐
                                                   │   SPLUNK    │
                                                   │   SERVER    │
                                                   │  ┌───────┐  │
                                                   │  │Saved  │  │
                                                   │  │Search │  │
                                                   │  │ x 43  │  │
                                                   │  └───────┘  │
                                                   └─────────────┘
```

---

## Script Reference

| Script | Language | Purpose |
|--------|----------|---------|
| `convert-to-splunk.py` | Python | Converts Sigma YAML rules to Splunk `savedsearches.conf` format |
| `deploy-to-splunk.ps1` | PowerShell | Deploys saved searches to Splunk via REST API |
| `regression-test.py` | Python | Runs Atomic Red Team tests and validates Splunk detections |
| `update-readme-stats.py` | Python | Updates README.md with current rule counts |
