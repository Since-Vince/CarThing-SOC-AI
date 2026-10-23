# Run this on the Windows computer running DeskThing. API key never leaves Windows except HTTPS requests to Ubuntu.
$ErrorActionPreference = 'Stop'
$folder = Join-Path $env:LOCALAPPDATA 'CarThingSOC'
$file = Join-Path $folder 'config.json'
Write-Host 'CarThing SOC Windows Bridge Configuration' -ForegroundColor Cyan
Write-Host 'This file stays on your Windows computer and must not be uploaded to GitHub.'
$url = Read-Host 'Enter the HTTPS Tailscale Serve URL of your Ubuntu SOC backend'
if ([string]::IsNullOrWhiteSpace($url)) { throw 'The backend URL is required.' }
try { $uri = [uri]$url } catch { throw 'Invalid URL.' }
if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.Host -in @('127.0.0.1','localhost'))) { throw 'HTTPS is required for remote connections.' }
$keySecret = Read-Host 'Enter your NEW CarThing SOC API key (input hidden)' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($keySecret)
try { $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
if ([string]::IsNullOrWhiteSpace($key)) { throw 'The API key cannot be empty.' }
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$payload = @{ backendUrl = $url; apiKey = $key } | ConvertTo-Json -Compress
[IO.File]::WriteAllText($file, $payload, (New-Object Text.UTF8Encoding($false)))
# A private directory under the current user's LocalAppData protects against casual access.
# ACLs: remove inherited access and grant only the current account and SYSTEM.
try {
  $account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  & icacls $file /inheritance:r /grant:r "${account}:(R,W)" 'SYSTEM:(F)' | Out-Null
} catch { Write-Warning 'Could not tighten config file ACL. Check Windows file permissions.' }
$key = $null
$payload = $null
Write-Host "Saved private configuration to $file" -ForegroundColor Green
Write-Host 'Restart the CarThing SOC app in DeskThing to load your configuration.'
