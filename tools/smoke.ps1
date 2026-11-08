$ErrorActionPreference = 'Stop'
$base = 'http://localhost:4000/api'
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$login = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -Body (@{email='analyst@secureflow.dev';password='Analyst#2026'} | ConvertTo-Json) -ContentType 'application/json' -WebSession $session
Write-Host "login ok: $($login.data.user.name) / $($login.data.user.role)"

$checks = @(
  @{ m='GET'; p='/events?limit=3' },
  @{ m='GET'; p='/events/facets' },
  @{ m='GET'; p='/assets?limit=3' },
  @{ m='GET'; p='/assets/summary' },
  @{ m='GET'; p='/incidents?limit=3' },
  @{ m='GET'; p='/investigations?limit=3' },
  @{ m='GET'; p='/threat-intel?limit=3' },
  @{ m='GET'; p='/detections?limit=3' },
  @{ m='GET'; p='/detections/summary' },
  @{ m='GET'; p='/detections/rules' },
  @{ m='GET'; p='/vulnerabilities?limit=3' },
  @{ m='GET'; p='/automation/workflows' },
  @{ m='GET'; p='/automation/executions' },
  @{ m='GET'; p='/forensics?limit=3' },
  @{ m='GET'; p='/forensics/stats' },
  @{ m='GET'; p='/network?limit=3' },
  @{ m='GET'; p='/network/summary' },
  @{ m='GET'; p='/reports?limit=3' },
  @{ m='GET'; p='/reports/types' },
  @{ m='GET'; p='/simulations?limit=3' },
  @{ m='GET'; p='/simulations/scenarios' },
  @{ m='GET'; p='/simulations/mirofish/status' },
  @{ m='GET'; p='/settings/organization' },
  @{ m='GET'; p='/settings/users' },
  @{ m='GET'; p='/settings/integrations' },
  @{ m='GET'; p='/settings/health' },
  @{ m='GET'; p='/overview/trends?days=7' }
)

$fail = 0
foreach ($c in $checks) {
  try {
    $r = Invoke-RestMethod -Uri "$base$($c.p)" -Method $c.m -WebSession $session
    Write-Host ("OK   {0} {1}" -f $c.m, $c.p)
  } catch {
    $fail++
    $msg = $_.Exception.Message
    $detail = ''
    if ($_.ErrorDetails) { $detail = $_.ErrorDetails.Message }
    Write-Host ("FAIL {0} {1} -> {2} {3}" -f $c.m, $c.p, $msg, $detail)
  }
}
Write-Host "failures: $fail"
