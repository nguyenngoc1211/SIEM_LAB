param(
  [Parameter(Mandatory=$true)]
  [string]$SocLabDir,
  [switch]$RestartSuricata
)

$ErrorActionPreference = "Stop"
$SocLabDir = (Resolve-Path $SocLabDir).Path
$RulesSource = Join-Path $PSScriptRoot "..\rules\soc-attacker-v3.rules"
$LocalRules = Join-Path $SocLabDir "sensor\local.rules"

if (!(Test-Path $RulesSource)) { throw "Rules file not found: $RulesSource" }
if (!(Test-Path $LocalRules)) { throw "SOC lab local.rules not found: $LocalRules" }

$Start = "# --- SOC attacker advanced v3 rules BEGIN ---"
$End = "# --- SOC attacker advanced v3 rules END ---"
$Existing = Get-Content $LocalRules -Raw
$Block = Get-Content $RulesSource -Raw
$NewBlock = "`n$Start`n$Block`n$End`n"

$Backup = "$LocalRules.bak.$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item $LocalRules $Backup

$Pattern = "(?s)`n?# --- SOC attacker advanced v3 rules BEGIN ---.*?# --- SOC attacker advanced v3 rules END ---`n?"
$Clean = [regex]::Replace($Existing, $Pattern, "`n")
Set-Content -Path $LocalRules -Value ($Clean.TrimEnd() + $NewBlock) -Encoding ASCII

Write-Host "Installed v3 Suricata rules into: $LocalRules"
Write-Host "Backup created: $Backup"

if ($RestartSuricata) {
  Push-Location $SocLabDir
  try {
    docker compose up -d --build --force-recreate suricata
  } finally {
    Pop-Location
  }
}
