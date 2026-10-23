# Safe CarThing SOC diagnostic: never prints or logs the API key, nor raw Wazuh alerts.
$ErrorActionPreference = 'Stop'
$file = Join-Path $env:LOCALAPPDATA 'CarThingSOC\config.json'
Write-Host 'CarThing SOC Windows Bridge Test' -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
  Write-Host 'FAIL: Windows configuration file missing. Run scripts\configure-windows.ps1.' -ForegroundColor Red
  exit 1
}
Write-Host 'OK: Windows configuration file exists.' -ForegroundColor Green
try { $cfg = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json }
catch { Write-Host 'FAIL: Cannot parse configuration file.' -ForegroundColor Red; exit 1 }
if ([string]::IsNullOrWhiteSpace($cfg.backendUrl) -or [string]::IsNullOrWhiteSpace($cfg.apiKey)) {
  Write-Host 'FAIL: Backend URL or API key not configured.' -ForegroundColor Red; exit 1
}
Write-Host 'OK: URL and API key fields present. Key is hidden.' -ForegroundColor Green
try {
  $url = [uri]$cfg.backendUrl
  if ($url.Scheme -ne 'https' -and $url.Host -notin @('localhost', '127.0.0.1')) { throw 'HTTPS is required for a remote SOC URL.' }
  $endpoint = [uri]::new($url, '/api/v1/overview').AbsoluteUri
  $json = Invoke-RestMethod -Uri $endpoint -Headers @{ 'X-API-Key' = $cfg.apiKey } -TimeoutSec 12 -Method GET
  if ($json.schema_version -ne 1) { throw 'Unexpected backend data schema.' }
  Write-Host 'OK: Backend authenticated and returned SOC data.' -ForegroundColor Green
  Write-Host ('Server: {0} | Docker: {1} | Wazuh: {2}' -f $json.server.status, $json.docker.status, $json.wazuh.status)
} catch {
  # Do not echo exception details; certain failures contain URL strings.
  Write-Host 'FAIL: Unable to fetch authenticated SOC data. Check Tailscale, backend service, and API key.' -ForegroundColor Red
  Write-Host ('Error category: {0}' -f $_.CategoryInfo.Category)
  exit 1
}
Write-Host 'Windows connectivity is good. If Car Thing still says OFFLINE, restart/reinitialize the app in DeskThing and check its app logs.'
