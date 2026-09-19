[CmdletBinding()]
param(
    [switch]$StopDockerDesktop
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$config = Get-SocConfig
$logPath = Get-AutoStartLogPath -Config $config

function Invoke-ComposeStop {
    param([string[]]$ComposeFiles, [string]$WorkingDirectory)

    $arguments = @('compose')
    foreach ($composeFile in $ComposeFiles) {
        $arguments += @('-f', $composeFile)
    }
    $arguments += 'stop'

    Push-Location $WorkingDirectory
    try {
        & docker @arguments 2>&1 | Tee-Object -FilePath $logPath -Append
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose stop that bai tai $WorkingDirectory"
        }
    }
    finally {
        Pop-Location
    }
}

try {
    Write-SocLog -Message 'Dang dung Wazuh va SOC containers...' -LogPath $logPath
    $env:SOC_SURICATA_LOGS = Join-Path $config.SocProjectPath 'runtime\suricata-logs'
    Invoke-ComposeStop -ComposeFiles @(
        (Join-Path $config.WazuhProjectPath 'docker-compose.yml'),
        (Join-Path $PSScriptRoot 'wazuh\docker-compose.suricata.yml')
    ) -WorkingDirectory $config.WazuhProjectPath

    Invoke-ComposeStop -ComposeFiles @(
        (Join-Path $config.SocProjectPath 'docker-compose.yml')
    ) -WorkingDirectory $config.SocProjectPath

    if ($StopDockerDesktop) {
        & docker desktop stop --detach 2>&1 | Tee-Object -FilePath $logPath -Append
    }

    Write-SocLog -Message 'Da dung SOC system.' -LogPath $logPath
}
catch {
    Write-SocLog -Message $_.Exception.Message -LogPath $logPath -Level 'ERROR'
    exit 1
}
