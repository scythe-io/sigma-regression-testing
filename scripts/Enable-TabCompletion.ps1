<#
.SYNOPSIS
    Enables tab completion for regression-test.py in PowerShell.

.DESCRIPTION
    Run this script to enable tab completion for the regression-test.py script.
    You can add this to your PowerShell profile for persistent completion.

.EXAMPLE
    . .\Enable-TabCompletion.ps1

.NOTES
    Requires: pip install argcomplete
#>

# Check if argcomplete is installed
$argcompleteCheck = python -c "import argcomplete" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "argcomplete not installed. Installing..." -ForegroundColor Yellow
    pip install argcomplete
}

# Register the argument completer for regression-test.py
Register-ArgumentCompleter -Native -CommandName @('regression-test.py', 'python') -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $command = $commandAst.ToString()

    # Only complete if it's our script
    if ($command -notmatch 'regression-test\.py') {
        return
    }

    $env:_ARGCOMPLETE = 1
    $env:_ARGCOMPLETE_IFS = "`n"
    $env:_ARGCOMPLETE_SUPPRESS_SPACE = 1
    $env:COMP_LINE = $command
    $env:COMP_POINT = $cursorPosition

    # Find the script path
    $scriptPath = $commandAst.CommandElements | Where-Object { $_.ToString() -match 'regression-test\.py' } | Select-Object -First 1

    if ($scriptPath) {
        $completions = python $scriptPath.ToString() 2>$null
        $completions -split "`n" | Where-Object { $_ -and $_.StartsWith($wordToComplete) } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }

    # Clean up environment
    Remove-Item Env:_ARGCOMPLETE -ErrorAction SilentlyContinue
    Remove-Item Env:_ARGCOMPLETE_IFS -ErrorAction SilentlyContinue
    Remove-Item Env:_ARGCOMPLETE_SUPPRESS_SPACE -ErrorAction SilentlyContinue
    Remove-Item Env:COMP_LINE -ErrorAction SilentlyContinue
    Remove-Item Env:COMP_POINT -ErrorAction SilentlyContinue
}

Write-Host "Tab completion enabled for regression-test.py" -ForegroundColor Green
Write-Host ""
Write-Host "Usage: python scripts/regression-test.py --<TAB>" -ForegroundColor Cyan
Write-Host ""
Write-Host "To make this permanent, add the following to your PowerShell profile:" -ForegroundColor Yellow
Write-Host "  . '$PSScriptRoot\Enable-TabCompletion.ps1'" -ForegroundColor Gray
Write-Host ""
Write-Host "Your profile is located at: $PROFILE" -ForegroundColor Gray
