[CmdletBinding()]
param(
    [string]$SocProjectPath,
    [string]$WazuhProjectPath,
    [string]$TaskName = 'SOC Lab AutoStart',
    [ValidateRange(60, 900)][int]$DockerWaitSeconds = 240,
    [switch]$StartNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($SocProjectPath)) {
    $SocProjectPath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
else {
    $SocProjectPath = (Resolve-Path $SocProjectPath).Path
}

if ([string]::IsNullOrWhiteSpace($WazuhProjectPath)) {
    $codeRoot = Split-Path $SocProjectPath -Parent
    $candidate = Join-Path $codeRoot 'wazuh-docker\single-node'
    if (Test-Path -LiteralPath $candidate) {
        $WazuhProjectPath = (Resolve-Path $candidate).Path
    }
    else {
        throw "Khong tu dong tim thay Wazuh. Chay lai voi -WazuhProjectPath 'C:\...\wazuh-docker\single-node'"
    }
}
else {
    $WazuhProjectPath = (Resolve-Path $WazuhProjectPath).Path
}

$socCompose = Join-Path $SocProjectPath 'docker-compose.yml'
$wazuhCompose = Join-Path $WazuhProjectPath 'docker-compose.yml'
if (-not (Test-Path -LiteralPath $socCompose)) {
    throw "Khong tim thay $socCompose"
}
if (-not (Test-Path -LiteralPath $wazuhCompose)) {
    throw "Khong tim thay $wazuhCompose"
}

function Escape-Psd1String([string]$Value) {
    return $Value.Replace("'", "''")
}

$configPath = Join-Path $PSScriptRoot 'Config.psd1'
$configText = @"
@{
    SocProjectPath    = '$(Escape-Psd1String $SocProjectPath)'
    WazuhProjectPath  = '$(Escape-Psd1String $WazuhProjectPath)'
    TaskName          = '$(Escape-Psd1String $TaskName)'
    DockerWaitSeconds = $DockerWaitSeconds
    PullPolicy        = 'never'
}
"@
Set-Content -LiteralPath $configPath -Value $configText -Encoding UTF8
Write-Host "Da tao $configPath"

& (Join-Path $PSScriptRoot 'Install-Wazuh-SuricataIntegration.ps1') `
    -WazuhProjectPath $WazuhProjectPath `
    -SocProjectPath $SocProjectPath

$startScript = Join-Path $PSScriptRoot 'Start-SOC-System.ps1'
$powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$actionArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$startScript`""
$action = New-ScheduledTaskAction -Execute $powershellExe -Argument $actionArguments
$userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description 'Khoi dong Docker Desktop, SOC containers va Wazuh sau khi dang nhap Windows.' `
    -Force | Out-Null

Write-Host "Da dang ky Scheduled Task: $TaskName"
Write-Host 'Restart policy se duoc gan khi he thong khoi dong lan dau.'

if ($StartNow) {
    & $startScript -AllowPull
}

Write-Host ''
Write-Host 'CAI DAT HOAN TAT'
Write-Host "SOC project : $SocProjectPath"
Write-Host "Wazuh       : $WazuhProjectPath"
Write-Host "Task        : $TaskName"
Write-Host "Kiem tra    : .\windows\Test-SOC-System.ps1"
