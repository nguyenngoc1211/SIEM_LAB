param(
    [string]$WebhookUrl = "http://localhost:5678/webhook/soc-alert-analysis",
    [int]$TimeoutSeconds = 240
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$mockDir = Join-Path $repoRoot "mock-data-for-db"
$reportsDir = Join-Path $repoRoot "runtime\reports"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("soc-mock-refresh-" + [guid]::NewGuid().ToString("N"))
$backupDir = Join-Path $repoRoot ("mock-data-for-db-backup-" + $runStamp)

function Read-JsonFile {
    param([string]$Path)
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Require-Property {
    param(
        [object]$Object,
        [string]$Name,
        [string]$Context
    )
    if ($null -eq $Object -or $Object.PSObject.Properties.Name -notcontains $Name) {
        throw "$Context is missing required property '$Name'"
    }
}

$mockFiles = @(Get-ChildItem -LiteralPath $mockDir -File -Filter "*.json" | Sort-Object Name)
if ($mockFiles.Count -ne 15) {
    throw "Expected exactly 15 JSON files in $mockDir, found $($mockFiles.Count)"
}

New-Item -ItemType Directory -Path $stageDir | Out-Null
$results = [System.Collections.Generic.List[object]]::new()

try {
    for ($index = 0; $index -lt $mockFiles.Count; $index += 1) {
        $mockFile = $mockFiles[$index]
        if ($mockFile.BaseName -notmatch '^\d+_(.+?)_T') {
            throw "Cannot extract scenario ID from $($mockFile.Name)"
        }

        $scenarioId = $matches[1]
        $oldOutput = Read-JsonFile -Path $mockFile.FullName
        $sourceAlertId = [string]$oldOutput.source_alert_id
        if ([string]::IsNullOrWhiteSpace($sourceAlertId)) {
            throw "$($mockFile.Name) has no source_alert_id"
        }

        $matchingReports = @(
            Get-ChildItem -LiteralPath $reportsDir -Recurse -File -Filter ($scenarioId + ".json") |
                ForEach-Object {
                    $report = Read-JsonFile -Path $_.FullName
                    if ([string]$report.selected_wazuh_alert.id -eq $sourceAlertId) {
                        [pscustomobject]@{ Path = $_.FullName; Report = $report }
                    }
                }
        )

        if ($matchingReports.Count -ne 1) {
            throw "Expected one report for $scenarioId / alert $sourceAlertId, found $($matchingReports.Count)"
        }

        $selectedAlert = $matchingReports[0].Report.selected_wazuh_alert
        if ($null -eq $selectedAlert) {
            throw "Report for $scenarioId has no selected_wazuh_alert"
        }

        Write-Output ("[{0}/{1}] POST {2} ({3})" -f ($index + 1), $mockFiles.Count, $scenarioId, $sourceAlertId)
        $requestJson = $selectedAlert | ConvertTo-Json -Depth 100 -Compress
        $response = Invoke-WebRequest `
            -Uri $WebhookUrl `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($requestJson)) `
            -TimeoutSec $TimeoutSeconds `
            -UseBasicParsing

        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            throw "$scenarioId returned HTTP $($response.StatusCode)"
        }

        $output = $response.Content | ConvertFrom-Json
        foreach ($field in @("record_id", "source_alert_id", "detail")) {
            Require-Property -Object $output -Name $field -Context "$scenarioId response"
        }
        foreach ($field in @("wazuh_alert", "suricata_alert", "gemini_analysis")) {
            Require-Property -Object $output.detail -Name $field -Context "$scenarioId detail"
        }
        foreach ($field in @(
            "summary", "is_false_positive", "threat_level", "confidence",
            "attack_likelihood", "rationale", "observed_evidence",
            "recommended_actions", "need_admin_verification", "soar_action",
            "analyst_notes"
        )) {
            Require-Property -Object $output.detail.gemini_analysis -Name $field -Context "$scenarioId gemini_analysis"
        }

        if ([string]$output.source_alert_id -ne $sourceAlertId) {
            throw "$scenarioId response source_alert_id '$($output.source_alert_id)' does not match '$sourceAlertId'"
        }
        if ([string]$output.detail.wazuh_alert.id -ne $sourceAlertId) {
            throw "$scenarioId detail.wazuh_alert.id does not match '$sourceAlertId'"
        }
        if ($null -eq $output.detail.suricata_alert.alert) {
            throw "$scenarioId detail.suricata_alert does not contain alert data"
        }

        $stagePath = Join-Path $stageDir $mockFile.Name
        $prettyJson = $output | ConvertTo-Json -Depth 100
        [System.IO.File]::WriteAllText($stagePath, $prettyJson + [Environment]::NewLine, $utf8NoBom)

        $results.Add([pscustomobject]@{
            File = $mockFile.Name
            Scenario = $scenarioId
            AlertId = $sourceAlertId
            Technique = [string]$output.technique_id
            MappingStatus = [string]$output.mapping_status
            ThreatLevel = [string]$output.ai_threat_level
        })
        Write-Output ("[{0}/{1}] OK {2}: technique={3}, threat={4}" -f ($index + 1), $mockFiles.Count, $scenarioId, $output.technique_id, $output.ai_threat_level)
    }

    New-Item -ItemType Directory -Path $backupDir | Out-Null
    foreach ($mockFile in $mockFiles) {
        Copy-Item -LiteralPath $mockFile.FullName -Destination (Join-Path $backupDir $mockFile.Name)
    }
    foreach ($mockFile in $mockFiles) {
        Copy-Item -LiteralPath (Join-Path $stageDir $mockFile.Name) -Destination $mockFile.FullName -Force
    }

    Write-Output "All 15 responses validated and committed."
    Write-Output ("BackupDirectory=" + $backupDir)
    $results | Format-Table -AutoSize
}
finally {
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedStage = [System.IO.Path]::GetFullPath($stageDir)
    if ($resolvedStage.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedStage)) {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
