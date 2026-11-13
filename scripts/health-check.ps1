param(
  [string]$Base = 'http://127.0.0.1:4000/api'
)

$ErrorActionPreference = 'Stop'
$script:failures = @()
$script:checks = 0

function New-Session {
  param([string]$Email, [string]$Password)
  $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  $login = Invoke-RestMethod -Uri "$Base/auth/login" -Method Post -ContentType 'application/json' `
    -Body (@{ email = $Email; password = $Password } | ConvertTo-Json) -WebSession $session
  $csrf = $session.Cookies.GetCookies([Uri]$Base)['sf_csrf'].Value
  return @{ Session = $session; Csrf = $csrf; Login = $login }
}

function Get-Json {
  param([string]$Path, [hashtable]$Auth, [int[]]$Allow = @(200))
  $script:checks += 1
  $timer = [Diagnostics.Stopwatch]::StartNew()
  try {
    $response = Invoke-WebRequest -Uri "$Base$Path" -WebSession $Auth.Session `
      -Headers @{ 'x-csrf-token' = $Auth.Csrf } -UseBasicParsing
    $status = [int]$response.StatusCode
    $text = $response.Content
  } catch {
    $status = [int]$_.Exception.Response.StatusCode.value__
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $text = $reader.ReadToEnd()
  }
  $timer.Stop()
  $ok = $Allow -contains $status
  if (-not $ok) {
    $script:failures += "$Path returned $status (expected $($Allow -join '/'))"
  }
  $json = $null
  if ($text) { try { $json = $text | ConvertFrom-Json } catch { } }
  [pscustomobject]@{
    Path = $Path
    Status = $status
    Ms = $timer.ElapsedMilliseconds
    Ok = $ok
    Data = $json
  }
}

function Assert-True {
  param([bool]$Condition, [string]$Message)
  $script:checks += 1
  if (-not $Condition) { $script:failures += $Message }
}

$accounts = (Invoke-RestMethod -Uri "$Base/auth/demo-accounts").Data
$adminAccount = $accounts | Where-Object { $_.role -eq 'Admin' } | Select-Object -First 1
$analystAccount = $accounts | Where-Object { $_.role -eq 'Analyst' } | Select-Object -First 1
$viewerAccount = $accounts | Where-Object { $_.role -eq 'Viewer' } | Select-Object -First 1
$admin = New-Session -Email $adminAccount.email -Password $adminAccount.password
$analyst = New-Session -Email $analystAccount.email -Password $analystAccount.password
$viewer = New-Session -Email $viewerAccount.email -Password $viewerAccount.password

$paths = @(
  '/auth/me', '/auth/sessions',
  '/overview/summary', '/overview/trends?days=14',
  '/events?limit=5', '/events/facets',
  '/assets?limit=5', '/assets/summary',
  '/incidents?limit=5',
  '/detections?limit=5', '/detections/summary', '/detections/rules',
  '/threat-intel?limit=5', '/threat-intel/summary', '/threat-intel/lookups/recent',
  '/vulnerabilities?limit=5',
  '/network?limit=5', '/network/summary',
  '/phishing?limit=5',
  '/automation/workflows', '/automation/executions',
  '/forensics?limit=5', '/forensics/stats',
  '/reports/types', '/reports?limit=5',
  '/simulations?limit=5', '/simulations/scenarios', '/simulations/mirofish/status',
  '/settings/organization', '/settings/users', '/settings/integrations',
  '/settings/audit-logs?limit=5', '/settings/audit-logs/verify', '/settings/health',
  '/demo/status', '/demo/runs',
  '/v1/websites'
)
$results = foreach ($path in $paths) { Get-Json -Path $path -Auth $admin }

$events = ($results | Where-Object { $_.Path -eq '/events?limit=5' }).Data.data
$assets = ($results | Where-Object { $_.Path -eq '/assets?limit=5' }).Data.data
$incidents = ($results | Where-Object { $_.Path -eq '/incidents?limit=5' }).Data.data
$detections = ($results | Where-Object { $_.Path -eq '/detections?limit=5' }).Data.data
$reports = ($results | Where-Object { $_.Path -eq '/reports?limit=5' }).Data.data
$simulations = ($results | Where-Object { $_.Path -eq '/simulations?limit=5' }).Data.data
$sites = ($results | Where-Object { $_.Path -eq '/v1/websites' }).Data.data
$evidence = ($results | Where-Object { $_.Path -eq '/forensics?limit=5' }).Data.data
$investigations = (Get-Json -Path '/investigations?limit=5' -Auth $admin).Data.data

$detailPaths = @()
if ($events) { $detailPaths += "/events/$($events[0].id)" }
if ($assets) { $detailPaths += "/assets/$($assets[0].id)" }
if ($incidents) { $detailPaths += "/incidents/$($incidents[0].id)" }
if ($detections) { $detailPaths += "/detections/$($detections[0].id)" }
if ($reports) { $detailPaths += "/reports/$($reports[0].id)" }
if ($simulations) { $detailPaths += "/simulations/$($simulations[0].id)" }
if ($sites) { $detailPaths += "/v1/websites/$($sites[0].id)", "/v1/websites/$($sites[0].id)/events", "/v1/websites/$($sites[0].id)/detections", "/v1/websites/$($sites[0].id)/incidents", "/v1/websites/$($sites[0].id)/keys" }
if ($evidence) { $detailPaths += "/forensics/$($evidence[0].id)" }
if ($investigations) { $detailPaths += "/investigations/$($investigations[0].id)" }

foreach ($path in $detailPaths) { $results += Get-Json -Path $path -Auth $admin }

# RBAC boundaries. A viewer must not write; an analyst must not administer users.
$viewerWrite = $null
try {
  Invoke-WebRequest -Uri "$Base/assets" -Method Post -WebSession $viewer.Session -Headers @{ 'x-csrf-token' = $viewer.Csrf } `
    -ContentType 'application/json' -Body '{}' -UseBasicParsing | Out-Null
  $viewerWrite = 200
} catch { $viewerWrite = [int]$_.Exception.Response.StatusCode.value__ }
Assert-True ($viewerWrite -eq 403) "viewer write returned $viewerWrite instead of 403"

$analystAdmin = $null
try {
  Invoke-WebRequest -Uri "$Base/settings/users" -Method Post -WebSession $analyst.Session -Headers @{ 'x-csrf-token' = $analyst.Csrf } `
    -ContentType 'application/json' -Body '{}' -UseBasicParsing | Out-Null
  $analystAdmin = 201
} catch { $analystAdmin = [int]$_.Exception.Response.StatusCode.value__ }
Assert-True ($analystAdmin -eq 403) "analyst admin write returned $analystAdmin instead of 403"

$badDetail = Get-Json -Path '/incidents/does_not_exist' -Auth $admin -Allow @(404)
Assert-True ($badDetail.Status -eq 404) 'unknown incident did not return 404'

$results | Sort-Object Path | Format-Table Path, Status, Ms, Ok -AutoSize

Write-Host ""
Write-Host "Checks: $script:checks"
if ($script:failures.Count -gt 0) {
  Write-Host "FAILURES:" -ForegroundColor Red
  $script:failures | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
  exit 1
}
Write-Host "All API health checks passed." -ForegroundColor Green
