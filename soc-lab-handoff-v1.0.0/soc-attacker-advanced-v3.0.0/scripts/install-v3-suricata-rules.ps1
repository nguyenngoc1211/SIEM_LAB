param(
  [Parameter(Mandatory=$true)]
  [string]$SocLabDir,
  [switch]$RestartSuricata
)

$ErrorActionPreference = "Stop"
$SocLabDir = (Resolve-Path $SocLabDir).Path
$LocalRules = Join-Path $SocLabDir "sensor\local.rules"
if (!(Test-Path $LocalRules)) { throw "SOC lab local.rules not found: $LocalRules" }

Write-Host "Compatibility wrapper: v2 custom rules are already managed by $LocalRules."
Write-Host "No ET rule is copied, replaced, or modified."

if ($RestartSuricata) {
  Push-Location $SocLabDir
  try { docker compose up -d --build --force-recreate suricata }
  finally { Pop-Location }
}

Push-Location $SocLabDir
try { docker compose exec -T suricata suricata -T -c /etc/suricata/suricata.yaml }
finally { Pop-Location }
