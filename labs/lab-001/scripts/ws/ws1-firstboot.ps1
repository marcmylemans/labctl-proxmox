# ws1-firstboot.ps1
# Run once on first boot after sysprep.
# Sets DNS to DC, joins domain, reboots.
# PowerShell 5.1 compatible.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Get-EnvOrDefault([string]$Name, [string]$DefaultValue) {
  $v = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($v)) { return $DefaultValue }
  return $v
}

function Get-EnvRequired([string]$Name) {
  $v = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($v)) { throw "$Name not set" }
  return $v
}

# -----------------------------
# CONFIG (injected by labctl via env)
# -----------------------------
$DomainFqdn   = Get-EnvOrDefault "LAB_DOMAIN_FQDN"    "corp.local"
$NetbiosName  = Get-EnvOrDefault "LAB_DOMAIN_NETBIOS" "CORP"
$DcIp         = Get-EnvRequired  "LAB_DC_IP"

# Prefer passing a dedicated join user later; for now use Domain Admin
$JoinUser     = Get-EnvOrDefault "LAB_JOIN_USER" "$NetbiosName\Administrator"
$JoinPassword = Get-EnvRequired  "LAB_JOIN_PASS"

$MarkerDir    = "C:\ProgramData\LabBootstrap"
$MarkerFile   = Join-Path $MarkerDir "ws1.done"
$LogFile      = Join-Path $MarkerDir "ws1-firstboot.log"

New-Item -ItemType Directory -Path $MarkerDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append | Out-Null

function Wait-Until($ScriptBlock, $TimeoutSec = 300, $DelaySec = 5) {
  $start = Get-Date
  while ((Get-Date) - $start -lt (New-TimeSpan -Seconds $TimeoutSec)) {
    try { if (& $ScriptBlock) { return $true } } catch {}
    Start-Sleep -Seconds $DelaySec
  }
  return $false
}

try {
  if (Test-Path $MarkerFile) {
    Write-Host "WS bootstrap already done ($MarkerFile exists). Exiting."
    return
  }

  Write-Host "=== WS1 bootstrap start: $(Get-Date) ==="

  $If = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
  if (-not $If) { throw "No active NIC found." }

  Write-Host "Waiting for DC DNS to become ready (UDP query)..."

  # We consider DC DNS "ready" when AD SRV records resolve.
  # This is much more reliable than TCP port 53 checks.
  $SrvName = "_ldap._tcp.dc._msdcs.$DomainFqdn"

  $ok = Wait-Until -TimeoutSec 900 -DelaySec 5 -ScriptBlock {
    try {
      Resolve-DnsName -Name $SrvName -Type SRV -Server $DcIp -ErrorAction Stop | Out-Null
      $true
    } catch { $false }
  }

  if (-not $ok) {
    # As a helpful debug fallback, try a simple A record lookup too
    try { Resolve-DnsName -Name $DomainFqdn -Server $DcIp -ErrorAction Stop | Out-Null } catch {}
    throw "DC DNS not ready: SRV lookup failed for $SrvName via $DcIp"
  }

  Write-Host "DNS SRV records found. Domain DNS is ready."


  # Already joined?
  $cs = Get-CimInstance Win32_ComputerSystem
  if ($cs.PartOfDomain -and $cs.Domain -ieq $DomainFqdn) {
    Write-Host "Already joined to $DomainFqdn"
    New-Item -ItemType File -Path $MarkerFile -Force | Out-Null
    return
  }

  Write-Host "Joining domain $DomainFqdn as $JoinUser ..."
  $sec  = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($JoinUser, $sec)

  Add-Computer -DomainName $DomainFqdn -Credential $cred -Force -ErrorAction Stop

  New-Item -ItemType File -Path $MarkerFile -Force | Out-Null
  Write-Host "Domain join complete. Rebooting..."
  Restart-Computer -Force
}
finally {
  Stop-Transcript | Out-Null
}
