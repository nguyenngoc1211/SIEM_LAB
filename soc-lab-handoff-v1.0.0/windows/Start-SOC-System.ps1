[CmdletBinding()]
param(
    [switch]$AllowPull
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$config = Get-SocConfig
$logPath = Get-AutoStartLogPath -Config $config
$effectivePullPolicy = $(if ($AllowPull) { 'missing' } else { [string]$config.PullPolicy })

try {
    Write-SocLog -Message '===== BAT DAU KHOI DONG SOC SYSTEM =====' -LogPath $logPath
    Start-DockerEngine -WaitSeconds ([int]$config.DockerWaitSeconds) -LogPath $logPath

    $socCompose = Join-Path $config.SocProjectPath 'docker-compose.yml'
    Invoke-DockerComposeUp -ComposeFiles @($socCompose) `
        -WorkingDirectory $config.SocProjectPath `
        -PullPolicy $effectivePullPolicy `
        -LogPath $logPath

    $wazuhCompose = Join-Path $config.WazuhProjectPath 'docker-compose.yml'
    $wazuhOverride = Join-Path $PSScriptRoot 'wazuh\docker-compose.suricata.yml'
    $env:SOC_SURICATA_LOGS = Join-Path $config.SocProjectPath 'runtime\suricata-logs'

    Invoke-DockerComposeUp -ComposeFiles @($wazuhCompose, $wazuhOverride) `
        -WorkingDirectory $config.WazuhProjectPath `
        -PullPolicy $effectivePullPolicy `
        -LogPath $logPath

    Ensure-WazuhManagerReady -LogPath $logPath
    Set-SocRestartPolicies -LogPath $logPath
    Write-SocLog -Message '===== SOC SYSTEM DA KHOI DONG XONG =====' -LogPath $logPath
}
catch {
    Write-SocLog -Message $_.Exception.Message -LogPath $logPath -Level 'ERROR'
    Write-SocLog -Message '===== KHOI DONG SOC SYSTEM THAT BAI =====' -LogPath $logPath -Level 'ERROR'
    throw
}
