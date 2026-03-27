#Requires -Version 5.1
<#
.SYNOPSIS
    Syncs Sigma rules from GitHub to Aurora Agent custom-signatures folder.

.DESCRIPTION
    This script downloads Sigma rules from a GitHub repository and copies them
    to the Aurora Agent custom-signatures directory. Run as a scheduled task
    to keep rules up to date.

.PARAMETER GitHubRepo
    GitHub repository in format "owner/repo" (e.g., "tyler.casey/Sigma")

.PARAMETER Branch
    Branch to pull from (default: main)

.PARAMETER RulesPath
    Path within the repo containing rules (default: sigma_rules)

.PARAMETER AuroraPath
    Aurora Agent installation path (default: C:\Program Files\Aurora-Agent)

.PARAMETER RestartAurora
    Whether to restart Aurora service after sync (default: $false)

.EXAMPLE
    .\sync-aurora-rules.ps1 -GitHubRepo "myorg/sigma-rules" -RestartAurora $true

.NOTES
    Run as Administrator to write to Program Files and restart services.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$GitHubRepo,

    [Parameter(Mandatory=$false)]
    [string]$Branch = "main",

    [Parameter(Mandatory=$false)]
    [string]$RulesPath = "sigma_rules",

    [Parameter(Mandatory=$false)]
    [string]$AuroraPath = "C:\Program Files\Aurora-Agent",

    [Parameter(Mandatory=$false)]
    [bool]$RestartAurora = $false
)

$ErrorActionPreference = "Stop"

# Configuration
$CustomSigPath = Join-Path $AuroraPath "custom-signatures"
$TempPath = Join-Path $env:TEMP "sigma-rules-sync"
$LogPath = Join-Path $AuroraPath "logs\sigma-sync.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
}

try {
    Write-Log "Starting Sigma rules sync from $GitHubRepo"

    # Ensure custom-signatures directory exists
    if (-not (Test-Path $CustomSigPath)) {
        New-Item -ItemType Directory -Path $CustomSigPath -Force | Out-Null
        Write-Log "Created custom-signatures directory"
    }

    # Clean up temp directory
    if (Test-Path $TempPath) {
        Remove-Item -Path $TempPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TempPath -Force | Out-Null

    # Download rules from GitHub
    $zipUrl = "https://github.com/$GitHubRepo/archive/refs/heads/$Branch.zip"
    $zipPath = Join-Path $TempPath "repo.zip"

    Write-Log "Downloading from $zipUrl"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

    # Extract archive
    Write-Log "Extracting archive"
    Expand-Archive -Path $zipPath -DestinationPath $TempPath -Force

    # Find the extracted folder (GitHub adds branch name suffix)
    $repoName = ($GitHubRepo -split "/")[-1]
    $extractedPath = Get-ChildItem -Path $TempPath -Directory | Where-Object { $_.Name -like "$repoName-*" } | Select-Object -First 1
    $rulesSourcePath = Join-Path $extractedPath.FullName $RulesPath

    if (-not (Test-Path $rulesSourcePath)) {
        throw "Rules path not found: $rulesSourcePath"
    }

    # Count rules before sync
    $existingRules = (Get-ChildItem -Path $CustomSigPath -Filter "*.yml" -ErrorAction SilentlyContinue).Count
    $newRules = (Get-ChildItem -Path $rulesSourcePath -Filter "*.yml").Count

    Write-Log "Found $newRules rules to sync (existing: $existingRules)"

    # Copy rules to Aurora custom-signatures
    $ruleFiles = Get-ChildItem -Path $rulesSourcePath -Filter "*.yml"
    foreach ($rule in $ruleFiles) {
        Copy-Item -Path $rule.FullName -Destination $CustomSigPath -Force
    }

    Write-Log "Successfully synced $newRules rules to $CustomSigPath"

    # Cleanup temp files
    Remove-Item -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue

    # Restart Aurora if requested
    if ($RestartAurora) {
        Write-Log "Restarting Aurora Agent service"
        $service = Get-Service -Name "intend Aurora Agent Service" -ErrorAction SilentlyContinue
        if ($service) {
            Restart-Service -Name "intend Aurora Agent Service" -Force
            Write-Log "Aurora Agent service restarted"
        } else {
            Write-Log "Aurora Agent service not found" -Level "WARN"
        }
    }

    Write-Log "Sigma rules sync completed successfully"
    exit 0

} catch {
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
