$outputFile = "splunk_rules.txt"
if (Test-Path $outputFile) { Remove-Item $outputFile }

Get-ChildItem -Filter "*.yml" | Where-Object { $_.Name -notlike "*.bak*" } | ForEach-Object {
    $file = $_.Name
    $content = Get-Content $_.FullName -Raw
    if ($content -match "title:\s*(.+)") {
        $title = $Matches[1].Trim()
    } else {
        $title = "Unknown"
    }

    Add-Content -Path $outputFile -Value ("=" * 80)
    Add-Content -Path $outputFile -Value "File: $file"
    Add-Content -Path $outputFile -Value "Title: $title"
    Add-Content -Path $outputFile -Value ("=" * 80)

    $result = sigma convert -t splunk -p splunk_windows $_.FullName 2>&1
    Add-Content -Path $outputFile -Value $result
    Add-Content -Path $outputFile -Value ""

    Write-Host "Converted: $file"
}
Write-Host ""
Write-Host "Output saved to: $outputFile"
