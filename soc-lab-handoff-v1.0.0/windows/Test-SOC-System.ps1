[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'Common.ps1')
$config = Get-SocConfig

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Check, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{
        Status = $(if ($Passed) { 'PASS' } else { 'FAIL' })
        Check  = $Check
        Detail = $Detail
    })
}

try {
    Add-Result -Check 'Docker Engine' -Passed (Test-DockerEngine) -Detail 'docker info'
}
catch {
    Add-Result -Check 'Docker Engine' -Passed $false -Detail $_.Exception.Message
}

$expectedContainers = @(
    'soc_gateway',
    'soc_juice_shop',
    'soc_suricata',
    'single-node-wazuh.manager-1',
    'single-node-wazuh.indexer-1',
    'single-node-wazuh.dashboard-1'
)

$containerRows = @{}
if (Test-DockerEngine) {
    foreach ($line in (& docker ps -a --format '{{.Names}}|{{.Status}}')) {
        $parts = $line -split '\|', 2
        if ($parts.Count -eq 2) {
            $containerRows[$parts[0]] = $parts[1]
        }
    }
}

foreach ($name in $expectedContainers) {
    $exists = $containerRows.ContainsKey($name)
    $running = $exists -and $containerRows[$name] -match '^Up '
    $detail = $(if ($exists) { $containerRows[$name] } else { 'Khong ton tai' })
    Add-Result -Check "Container $name" -Passed $running -Detail $detail
}

if ($containerRows.ContainsKey('soc_attacker')) {
    Add-Result -Check 'Container soc_attacker' -Passed ($containerRows['soc_attacker'] -match '^Up ') -Detail $containerRows['soc_attacker']
}

try {
    $httpCode = (& curl.exe -s -o NUL -w '%{http_code}' http://127.0.0.1:8080).Trim()
    Add-Result -Check 'Juice Shop qua gateway' -Passed ($httpCode -eq '200') -Detail "HTTP $httpCode"
}
catch {
    Add-Result -Check 'Juice Shop qua gateway' -Passed $false -Detail $_.Exception.Message
}

try {
    $dashboardCode = (& curl.exe -k -s -o NUL -w '%{http_code}' https://127.0.0.1:443).Trim()
    Add-Result -Check 'Wazuh Dashboard' -Passed ($dashboardCode -in @('200', '302')) -Detail "HTTPS $dashboardCode"
}
catch {
    Add-Result -Check 'Wazuh Dashboard' -Passed $false -Detail $_.Exception.Message
}

try {
    & docker exec single-node-wazuh.manager-1 sh -c 'test -s /var/log/suricata/eve.json'
    Add-Result -Check 'Wazuh thay eve.json' -Passed ($LASTEXITCODE -eq 0) -Detail '/var/log/suricata/eve.json'
}
catch {
    Add-Result -Check 'Wazuh thay eve.json' -Passed $false -Detail $_.Exception.Message
}

try {
    $suricataCount = (& docker exec soc_suricata sh -c "grep -c '\"event_type\":\"alert\"' /var/log/suricata/eve.json 2>/dev/null || true").Trim()
    Add-Result -Check 'Suricata alerts' -Passed ([int]$suricataCount -ge 0) -Detail "$suricataCount alert(s)"
}
catch {
    Add-Result -Check 'Suricata alerts' -Passed $false -Detail $_.Exception.Message
}

try {
    $wazuhCount = (& docker exec single-node-wazuh.manager-1 sh -c "grep -c '\"groups\":\[\"ids\",\"suricata\"\]' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true").Trim()
    Add-Result -Check 'Wazuh Suricata alerts' -Passed ([int]$wazuhCount -ge 0) -Detail "$wazuhCount alert(s)"
}
catch {
    Add-Result -Check 'Wazuh Suricata alerts' -Passed $false -Detail $_.Exception.Message
}

try {
    $task = Get-ScheduledTask -TaskName $config.TaskName -ErrorAction Stop
    Add-Result -Check 'Scheduled Task' -Passed ($task.State -ne 'Disabled') -Detail $task.State
}
catch {
    Add-Result -Check 'Scheduled Task' -Passed $false -Detail 'Chua dang ky'
}

$results | Format-Table -AutoSize
$failed = @($results | Where-Object Status -eq 'FAIL').Count
Write-Host "`nTong: $($results.Count) | PASS: $($results.Count - $failed) | FAIL: $failed"
if ($failed -gt 0) { exit 1 }
