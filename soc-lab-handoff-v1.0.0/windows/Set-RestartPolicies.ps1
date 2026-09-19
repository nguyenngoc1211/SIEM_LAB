[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot 'Common.ps1')
$config = Get-SocConfig
$logPath = Get-AutoStartLogPath -Config $config
Start-DockerEngine -WaitSeconds ([int]$config.DockerWaitSeconds) -LogPath $logPath
Set-SocRestartPolicies -LogPath $logPath
