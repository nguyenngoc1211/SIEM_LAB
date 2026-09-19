[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WazuhProjectPath,
    [Parameter(Mandatory = $true)][string]$SocProjectPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$managerConfig = Join-Path $WazuhProjectPath 'config\wazuh_cluster\wazuh_manager.conf'
if (-not (Test-Path -LiteralPath $managerConfig)) {
    throw "Khong tim thay Wazuh manager config: $managerConfig"
}

$suricataLogDirectory = Join-Path $SocProjectPath 'runtime\suricata-logs'
New-Item -ItemType Directory -Path $suricataLogDirectory -Force | Out-Null

$content = Get-Content -LiteralPath $managerConfig -Raw
$marker = '<location>/var/log/suricata/eve.json</location>'
if ($content -notmatch [regex]::Escape($marker)) {
    $closingTag = '</ossec_config>'
    $insertAt = $content.LastIndexOf($closingTag, [System.StringComparison]::OrdinalIgnoreCase)
    if ($insertAt -lt 0) {
        throw "Khong tim thay $closingTag trong $managerConfig"
    }

    $backup = "$managerConfig.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $managerConfig -Destination $backup -Force

    $snippet = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'wazuh\ossec-localfile-suricata.xml') -Raw
    $updated = $content.Insert($insertAt, "`r`n$snippet`r`n")
    Set-Content -LiteralPath $managerConfig -Value $updated -Encoding UTF8
    Write-Host "Da chen Suricata localfile vao Wazuh config. Backup: $backup"
}
else {
    Write-Host 'Wazuh manager config da co Suricata localfile, bo qua.'
}

Write-Host "Suricata logs: $suricataLogDirectory"
