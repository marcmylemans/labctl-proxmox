# ws1-firstboot.ps1
# Run on first boot after sysprep (safe to re-run).
# Sets DNS to DC, waits for AD DNS readiness, joins domain, reboots, then marks ready.
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

function Wait-Until($ScriptBlock, $TimeoutSec = 300, $DelaySec = 5) {
  $start = Get-Date
  while ((Get-Date) - $start -lt (New-TimeSpan -Seconds $TimeoutSec)) {
    try { if (& $ScriptBlock) { return $true } } catch {}
    Start-Sleep -Seconds $DelaySec
  }
  return $false
}

# -----------------------------
# CONFIG (injected by labctl via env)
# -----------------------------
$DomainFqdn   = Get-EnvOrDefault "LAB_DOMAIN_FQDN"    "corp.local"
$NetbiosName  = Get-EnvOrDefault "LAB_DOMAIN_NETBIOS" "CORP"
$DcIp         = Get-EnvRequired  "LAB_DC_IP"

$JoinUser     = Get-EnvOrDefault "LAB_JOIN_USER" "$NetbiosName\Administrator"
$JoinPassword = Get-EnvRequired  "LAB_JOIN_PASS"

# -----------------------------
# MARKERS
# -----------------------------
$MarkerDir   = "C:\ProgramData\LabBootstrap"
$JoinedMark  = Join-Path $MarkerDir "ws1.joined"
$ReadyMark   = Join-Path $MarkerDir "ws1.ready"
$LogFile     = Join-Path $MarkerDir "ws1-firstboot.log"

New-Item -ItemType Directory -Path $MarkerDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append | Out-Null

try {
  Write-Host "=== WS1 bootstrap start: $(Get-Date) ==="

  # If already ready, exit
  if (Test-Path $ReadyMark) {
    Write-Host "WS already ready ($ReadyMark exists). Exiting."
    return
  }

  # If we already joined earlier, confirm and mark ready post-reboot
  if (Test-Path $JoinedMark) {
    Write-Host "Join was previously executed. Verifying domain membership..."
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain -and $cs.Domain -ieq $DomainFqdn) {
      New-Item -ItemType File -Path $ReadyMark -Force | Out-Null
      Write-Host "WS is domain-joined and ready ✅"
      return
    } else {
      Write-Host "Joined marker exists but system not in domain yet (likely mid-reboot). Waiting..."
      $ok = Wait-Until -TimeoutSec 600 -DelaySec 10 -ScriptBlock {
        $cs2 = Get-CimInstance Win32_ComputerSystem
        $cs2.PartOfDomain -and ($cs2.Domain -ieq $DomainFqdn)
      }
      if (-not $ok) { throw "System did not become domain-joined after join marker was present." }
      New-Item -ItemType File -Path $ReadyMark -Force | Out-Null
      Write-Host "WS is domain-joined and ready ✅"
      return
    }
  }

  # -----------------------------
  # Network: set DNS to DC (no static IP required)
  # -----------------------------
  $If = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
  if (-not $If) { throw "No active NIC found." }

  Write-Host "Setting client DNS to DC ($DcIp) ..."
  Set-DnsClientServerAddress -InterfaceIndex $If.ifIndex -ServerAddresses @($DcIp)
  ipconfig /flushdns | Out-Null

  # -----------------------------
  # Wait for DC readiness via SRV records (UDP DNS query)
  # -----------------------------
  Write-Host "Waiting for DC AD DNS SRV records..."
  $SrvName = "_ldap._tcp.dc._msdcs.$DomainFqdn"

  $ok = Wait-Until -TimeoutSec 1200 -DelaySec 5 -ScriptBlock {
    try {
      Resolve-DnsName -Name $SrvName -Type SRV -Server $DcIp -ErrorAction Stop | Out-Null
      $true
    } catch { $false }
  }
  if (-not $ok) {
    try { Resolve-DnsName -Name $DomainFqdn -Server $DcIp -ErrorAction Stop | Out-Null } catch {}
    throw "DC DNS not ready: SRV lookup failed for $SrvName via $DcIp"
  }
  Write-Host "DC DNS looks ready ✅"

  # Already joined?
  $cs = Get-CimInstance Win32_ComputerSystem
  if ($cs.PartOfDomain -and $cs.Domain -ieq $DomainFqdn) {
    Write-Host "Already joined to $DomainFqdn. Marking ready."
    New-Item -ItemType File -Path $ReadyMark -Force | Out-Null
    return
  }

  # -----------------------------
  # Join domain
  # -----------------------------
  Write-Host "Joining domain $DomainFqdn as $JoinUser ..."
  $sec  = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($JoinUser, $sec)

  Add-Computer -DomainName $DomainFqdn -Credential $cred -Force -ErrorAction Stop

  # Mark "joined" before reboot (so re-runs know to verify, not rejoin)
  New-Item -ItemType File -Path $JoinedMark -Force | Out-Null

  Write-Host "Domain join complete. Rebooting..."
  Restart-Computer -Force
}
finally {
  Stop-Transcript | Out-Null
}
