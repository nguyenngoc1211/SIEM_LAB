[CmdletBinding()]
param(
    [switch]$RemoveGeneratedConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$configPath = Join-Path $PSScriptRoot 'Config.psd1'
$taskName = 'SOC Lab AutoStart'
if (Test-Path -LiteralPath $configPath) {
    $config = Import-PowerShellDataFile -LiteralPath $configPath
    if ($config.ContainsKey('TaskName')) {
        $taskName = [string]$config.TaskName
    }
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Da xoa Scheduled Task: $taskName"
}
else {
    Write-Host "Khong tim thay Scheduled Task: $taskName"
}

if ($RemoveGeneratedConfig -and (Test-Path -LiteralPath $configPath)) {
    Remove-Item -LiteralPath $configPath -Force
    Write-Host "Da xoa $configPath"
}

Write-Host 'Container, image, volume va Wazuh config khong bi xoa.'
