Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SocConfig {
    $configPath = Join-Path $PSScriptRoot 'Config.psd1'
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "Khong tim thay $configPath. Hay chay .\windows\Install-All.ps1 truoc."
    }

    $config = Import-PowerShellDataFile -LiteralPath $configPath
    foreach ($required in @('SocProjectPath', 'WazuhProjectPath', 'TaskName', 'DockerWaitSeconds', 'PullPolicy')) {
        if (-not $config.ContainsKey($required) -or [string]::IsNullOrWhiteSpace([string]$config[$required])) {
            throw "Config.psd1 thieu gia tri: $required"
        }
    }
    return $config
}

function Get-AutoStartLogPath {
    param([hashtable]$Config)

    $logDirectory = Join-Path $Config.SocProjectPath 'runtime\autostart-logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    return (Join-Path $logDirectory 'soc-autostart.log')
}

function Write-SocLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $line | Tee-Object -FilePath $LogPath -Append
}

function Test-DockerEngine {
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Start-DockerEngine {
    param(
        [Parameter(Mandatory = $true)][int]$WaitSeconds,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
        throw 'Khong tim thay docker.exe trong PATH.'
    }

    if (Test-DockerEngine) {
        Write-SocLog -Message 'Docker Engine da san sang.' -LogPath $LogPath
        return
    }

    Write-SocLog -Message 'Dang khoi dong Docker Desktop...' -LogPath $LogPath
    $desktopCommandStarted = $false

    try {
        & docker desktop start --detach *> $null
        if ($LASTEXITCODE -eq 0) {
            $desktopCommandStarted = $true
        }
    }
    catch {
        Write-SocLog -Message "docker desktop start khong kha dung: $($_.Exception.Message)" -LogPath $LogPath -Level 'WARN'
    }

    if (-not $desktopCommandStarted) {
        $desktopCandidates = @(
            (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
            (Join-Path $env:LOCALAPPDATA 'Docker\Docker Desktop.exe')
        )
        $desktopExe = $desktopCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $desktopExe) {
            throw 'Khong tim thay Docker Desktop CLI hoac Docker Desktop.exe.'
        }
        Start-Process -FilePath $desktopExe | Out-Null
    }

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Seconds 5
        if (Test-DockerEngine) {
            Write-SocLog -Message 'Docker Engine da san sang.' -LogPath $LogPath
            return
        }
    } while ((Get-Date) -lt $deadline)

    throw "Docker Engine chua san sang sau $WaitSeconds giay."
}

function Invoke-DockerComposeUp {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComposeFiles,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$PullPolicy,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    foreach ($composeFile in $ComposeFiles) {
        if (-not (Test-Path -LiteralPath $composeFile)) {
            throw "Khong tim thay compose file: $composeFile"
        }
    }

    $arguments = @('compose')
    foreach ($composeFile in $ComposeFiles) {
        $arguments += @('-f', $composeFile)
    }
    $arguments += @('up', '-d')
    if ($PullPolicy -eq 'never') {
        $arguments += @('--pull', 'never')
    }

    Write-SocLog -Message "Chay: docker $($arguments -join ' ')" -LogPath $LogPath
    Push-Location $WorkingDirectory
    try {
        & docker @arguments 2>&1 | Tee-Object -FilePath $LogPath -Append
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose up that bai, exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Set-SocRestartPolicies {
    param([Parameter(Mandatory = $true)][string]$LogPath)

    $containerNames = & docker ps -a --format '{{.Names}}'
    if ($LASTEXITCODE -ne 0) {
        throw 'Khong the doc danh sach container.'
    }

    $targets = @($containerNames | Where-Object {
        $_ -match '^soc_' -or $_ -match '^single-node-wazuh\.' -or $_ -match '^single-node-wazuh-'
    })

    if ($targets.Count -eq 0) {
        Write-SocLog -Message 'Chua co container nao de gan restart policy.' -LogPath $LogPath -Level 'WARN'
        return
    }

    & docker update --restart unless-stopped @targets 2>&1 | Tee-Object -FilePath $LogPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw 'Gan restart policy that bai.'
    }
    Write-SocLog -Message "Da gan unless-stopped cho $($targets.Count) container." -LogPath $LogPath
}
function Get-SocLabPort {
    param([Parameter(Mandatory = $true)][string]$SocProjectPath)

    $port = 8081
    $envPath = Join-Path $SocProjectPath '.env'
    if (Test-Path -LiteralPath $envPath) {
        $match = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^\s*LAB_PORT\s*=\s*\d+\s*$' } | Select-Object -Last 1
        if ($match -and $match -match '=\s*(\d+)\s*$') {
            $candidate = [int]$Matches[1]
            if ($candidate -ge 1 -and $candidate -le 65535) {
                $port = $candidate
            }
        }
    }
    return $port
}

function Get-WazuhManagerContainer {
    $container = & docker ps --filter 'label=com.docker.compose.service=wazuh.manager' --format '{{.Names}}' 2>$null | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
        return $null
    }
    return [string]$container
}

function Test-WazuhManagerReady {
    $container = Get-WazuhManagerContainer
    if (-not $container) {
        return $false
    }

    $status = & docker exec $container /var/ossec/bin/wazuh-control status 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    foreach ($daemon in @('wazuh-analysisd', 'wazuh-logcollector', 'wazuh-remoted', 'wazuh-apid')) {
        $pattern = '(?m)^' + [regex]::Escape($daemon) + ' is running'
        if (($status -join "`n") -notmatch $pattern) {
            return $false
        }
    }
    return $true
}

function Wait-WazuhManagerReady {
    param([int]$WaitSeconds = 90)

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        if (Test-WazuhManagerReady) {
            return $true
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Ensure-WazuhManagerReady {
    param([Parameter(Mandatory = $true)][string]$LogPath)

    if (Wait-WazuhManagerReady -WaitSeconds 90) {
        Write-SocLog -Message 'Wazuh Manager da san sang.' -LogPath $LogPath
        return
    }

    $container = Get-WazuhManagerContainer
    if (-not $container) {
        throw 'Khong tim thay container Wazuh Manager dang chay.'
    }

    Write-SocLog -Message 'Wazuh Manager chua san sang; xoa start-script-lock cu va khoi dong lai container.' -LogPath $LogPath -Level 'WARN'
    & docker exec $container rm -f /var/ossec/var/start-script-lock 2>&1 | Tee-Object -FilePath $LogPath -Append
    & docker restart $container 2>&1 | Tee-Object -FilePath $LogPath -Append
    if ($LASTEXITCODE -ne 0 -or -not (Wait-WazuhManagerReady -WaitSeconds 120)) {
        throw 'Wazuh Manager van chua san sang sau khi khoi dong lai.'
    }
    Write-SocLog -Message 'Wazuh Manager da khoi phuc va san sang.' -LogPath $LogPath
}