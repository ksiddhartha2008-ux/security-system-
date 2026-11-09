$ErrorActionPreference = 'Continue'
$base = 'http://localhost:4000/api'
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -Body (@{email='analyst@secureflow.dev';password='Analyst#2026'} | ConvertTo-Json) -ContentType 'application/json' -WebSession $s | Out-Null
function Call($method, $path, $body) {
  try {
    if ($null -ne $body) {
      $json = $body | ConvertTo-Json -Depth 8
      $r = Invoke-RestMethod -Uri "$base$path" -Method $method -Body $json -ContentType 'application/json' -WebSession $s
    } else {
      $r = Invoke-RestMethod -Uri "$base$path" -Method $method -WebSession $s
    }
    Write-Host ("OK   {0} {1}" -f $method, $path)
    return $r
  } catch {
    $detail = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }
    Write-Host ("FAIL {0} {1} -> {2}" -f $method, $path, $detail)
    return $null
  }
}

$asset = Call POST '/assets' @{ name='Test API host'; hostname='test-api-01'; ipAddress='10.20.9.9'; os='Ubuntu 24.04'; assetType='server'; criticality='high'; owner='QA'; tags=@('test') }
$incident = Call POST '/incidents' @{ title='Suspicious login burst from a new ASN'; description='Created by the integration smoke test.'; severity='high'; priority='P2'; assigneeId=$null }
if ($incident) {
  Call PATCH "/incidents/$($incident.data.id)" @{ status='investigating' } | Out-Null
  Call POST "/incidents/$($incident.data.id)/notes" @{ message='Reviewed the sign-in telemetry and blocked the source range.' } | Out-Null
}
$inv = Call POST '/investigations' @{ title='Smoke test investigation'; hypothesis='The burst is automated.'; severity='medium'; incidentId=$incident.data.id }
if ($inv) { Call POST "/investigations/$($inv.data.id)/notes" @{ body='Correlated 14 events from one source.' } | Out-Null }

$ingest = Call POST '/events' @{ eventType='auth.failure'; source='identity-provider'; severity='medium'; category='identity'; title='Smoke test failed sign-in'; srcIp='203.0.113.9'; userEmail='smoke@meridian.demo' }
Call POST '/detections/run' @{} | Out-Null
$dets = Call GET '/detections?limit=1' $null
if ($dets -and $dets.data.Count -gt 0) {
  Call POST "/detections/$($dets.data[0].id)/feedback" @{ status='confirmed'; note='Validated during smoke test.' } | Out-Null
  Call POST "/detections/$($dets.data[0].id)/promote" @{} | Out-Null
}

$sim = Call POST '/simulations' @{ scenario='api-abuse'; name='Smoke test api abuse'; totalRounds=4; seed=1234 }
if ($sim) {
  Call POST "/simulations/$($sim.data.id)/start" @{} | Out-Null
  Start-Sleep -Seconds 4
  $detail = Call GET "/simulations/$($sim.data.id)" $null
  Write-Host ("   simulation status={0} rounds={1} events={2} risk={3}" -f $detail.data.status, $detail.data.currentRound, $detail.data.events.Count, $detail.data.riskScore)
}

$report = Call POST '/reports/generate' @{ type='executive' }
if ($report) {
  try {
    $md = Invoke-WebRequest -Uri "$base/reports/$($report.data.id)/download?format=md" -WebSession $s
    Write-Host ("OK   report download bytes={0}" -f $md.RawContentLength)
  } catch { Write-Host "FAIL report download $_" }
}

$wf = Call GET '/automation/workflows' $null
if ($wf -and $wf.data.Count -gt 0) {
  $run = Call POST "/automation/workflows/$($wf.data[0].id)/run" @{}
  if ($run -and $run.data.status -eq 'pending_approval') {
    Call POST "/automation/executions/$($run.data.id)/approve" @{} | Out-Null
  }
}

$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('smoke test evidence content'))
$ev = Call POST '/forensics' @{ caseRef='CASE-SMOKE-1'; filename='smoke.txt'; description='Smoke test evidence'; mimeType='text/plain'; contentBase64=$b64; collectedFrom='qa' }
if ($ev) {
  Call GET "/forensics/$($ev.data.id)" $null | Out-Null
  Call POST "/forensics/$($ev.data.id)/verify" @{} | Out-Null
  Call POST "/forensics/$($ev.data.id)/custody" @{ action='in_review'; note='Reviewing the smoke test artefact.' } | Out-Null
}

Call POST '/network' @{ srcIp='10.20.1.11'; srcPort=51000; destIp='198.51.100.5'; destPort=443; protocol='TLS'; bytesOut=2048; bytesIn=4096; direction='outbound'; verdict='allowed' } | Out-Null
Call POST '/threat-intel' @{ type='domain'; value='smoke-test.example'; threatType='testing'; confidence=40; description='Smoke test indicator' } | Out-Null
Call POST '/threat-intel/lookup' @{ query='smoke-test.example'; type='auto' } | Out-Null
Call POST '/phishing/scan' @{ url='http://127.0.0.1/admin' } | Out-Null
Call POST '/phishing/scan' @{ url='https://secure-paypal-verify.example/login' } | Out-Null
Call POST '/vulnerabilities' @{ cveId='CVE-2025-0000'; title='Smoke test vulnerability'; severity='medium'; cvss=5.4; assetId=$asset.data.id } | Out-Null

# RBAC: viewer must not be able to write
$v = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Invoke-RestMethod -Uri "$base/auth/login" -Method Post -Body (@{email='viewer@secureflow.dev';password='Viewer#2026'} | ConvertTo-Json) -ContentType 'application/json' -WebSession $v | Out-Null
try {
  Invoke-RestMethod -Uri "$base/assets" -Method Post -Body (@{name='Nope';hostname='nope-01'} | ConvertTo-Json) -ContentType 'application/json' -WebSession $v | Out-Null
  Write-Host 'FAIL viewer was able to create an asset'
} catch {
  Write-Host ("OK   viewer blocked ({0})" -f $_.Exception.Response.StatusCode.value__)
}
