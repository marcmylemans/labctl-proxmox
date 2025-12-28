# dc1-firstboot.ps1 (PowerShell 5.1 compatible)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -----------------------------
# Helpers (PS 5.1 compatible defaults)
# -----------------------------
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
# INPUT (injected by labctl via env)
# -----------------------------
$DomainFqdn        = Get-EnvOrDefault "LAB_DOMAIN_FQDN"    "corp.local"
$NetbiosName       = Get-EnvOrDefault "LAB_DOMAIN_NETBIOS" "CORP"
$DcIp              = Get-EnvRequired  "LAB_DC_IP"
$PrefixLength      = [int](Get-EnvOrDefault "LAB_PREFIX" "24")
$Gateway           = Get-EnvOrDefault "LAB_GW" ""   # optional
$SafeModeAdminPass = Get-EnvOrDefault "LAB_DSRM_PASS" "LabDSRM123!"

# DHCP options (optional)
$DhcpScopeNetwork  = Get-EnvOrDefault "LAB_SCOPE_NET"   "10.48.30.0"
$DhcpScopeStart    = Get-EnvOrDefault "LAB_SCOPE_START" "10.48.30.50"
$DhcpScopeEnd 	    = Get-EnvOrDefault "LAB_SCOPE_END"   "10.48.30.200"

# Optional DNS forwarders (comma separated, e.g. "1.1.1.1,8.8.8.8")
$DnsForwarders     = Get-EnvOrDefault "LAB_DNS_FORWARDERS" ""

# -----------------------------
# MARKERS
# -----------------------------
$StateDir        = "C:\ProgramData\LabBootstrap"
$NetDone         = Join-Path $StateDir "phase-network.done"
$PromoteStarted  = Join-Path $StateDir "phase-ad.promote-started"
$AdDone          = Join-Path $StateDir "phase-ad.done"
$Phase3Done      = Join-Path $StateDir "phase-services.done"
$ReadyMarker     = Join-Path $StateDir "dc1.ready"
$AllDone         = Join-Path $StateDir "dc1.done"
$LogFile         = Join-Path $StateDir "dc1-firstboot.log"

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append | Out-Null

try {
  Write-Host "=== DC1 bootstrap start: $(Get-Date) ==="

  # -----------------------------
  # PHASE 1 — NETWORK
  # -----------------------------
  if (-not (Test-Path $NetDone)) {
    Write-Host "Phase 1: configuring static network..."

    $If = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $If) { throw "No active NIC found" }

    # Remove DHCP IPv4 address if present
    $dhcpIps = Get-NetIPAddress -InterfaceIndex $If.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.PrefixOrigin -eq "Dhcp" }

    foreach ($ip in $dhcpIps) {
      Write-Host "Removing DHCP IP $($ip.IPAddress)"
      Remove-NetIPAddress -InterfaceIndex $If.ifIndex -IPAddress $ip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Assign static IP if not already present
    $hasIp = Get-NetIPAddress -InterfaceIndex $If.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -eq $DcIp }

    if (-not $hasIp) {
      Write-Host "Assigning static IP $DcIp/$PrefixLength"
      if ([string]::IsNullOrWhiteSpace($Gateway)) {
        New-NetIPAddress -InterfaceIndex $If.ifIndex -IPAddress $DcIp -PrefixLength $PrefixLength | Out-Null
      } else {
        New-NetIPAddress -InterfaceIndex $If.ifIndex -IPAddress $DcIp -PrefixLength $PrefixLength -DefaultGateway $Gateway | Out-Null
      }
    }

    # DNS client points to itself only (best practice)
    Write-Host "Setting NIC DNS to self ($DcIp)"
    Set-DnsClientServerAddress -InterfaceIndex $If.ifIndex -ServerAddresses @($DcIp)

    New-Item -ItemType File -Path $NetDone -Force | Out-Null
    Write-Host "Network configured. Rebooting..."
    Restart-Computer -Force
    return
  }

  # -----------------------------
  # PHASE 2 — AD DS + DNS (resume-safe)
  # -----------------------------
  if (-not (Test-Path $AdDone)) {
    Write-Host "Phase 2: installing AD DS + DNS..."
    Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

    $isDcReady = $false
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Get-ADDomain -ErrorAction Stop | Out-Null
      $isDcReady = $true
    } catch { $isDcReady = $false }

    if (-not $isDcReady) {
      if (-not (Test-Path $PromoteStarted)) {
        Write-Host "Promoting new forest $DomainFqdn"
        $sec = ConvertTo-SecureString $SafeModeAdminPass -AsPlainText -Force

        Install-ADDSForest `
          -DomainName $DomainFqdn `
          -DomainNetbiosName $NetbiosName `
          -SafeModeAdministratorPassword $sec `
          -InstallDNS `
          -Force `
          -NoRebootOnCompletion

        # IMPORTANT: only mark 'started' here, NOT done
        New-Item -ItemType File -Path $PromoteStarted -Force | Out-Null
        Write-Host "AD promotion initiated. Rebooting..."
        Restart-Computer -Force
        return
      } else {
        # promotion was started earlier; we are likely post-reboot. Wait for AD to become available.
        Write-Host "Promotion was started earlier. Waiting for AD to become available..."
        $ok = $false
        for ($i=0; $i -lt 120; $i++) { # 10 minutes
          try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADDomain -ErrorAction Stop | Out-Null
            $ok = $true
            break
          } catch {
            Start-Sleep -Seconds 5
          }
        }
        if (-not $ok) { throw "AD did not become available after promotion timeout" }
      }
    }

    # Only now we can safely mark Phase 2 done
    New-Item -ItemType File -Path $AdDone -Force | Out-Null
    Write-Host "Phase 2 complete."
  }

  # -----------------------------
  # PHASE 3 — DNS forwarders + DHCP (idempotent)
  # -----------------------------
  if (-not (Test-Path $Phase3Done)) {
    Write-Host "Phase 3: DNS forwarders + DHCP..."

    # Optional forwarders (don’t hardcode public DNS)
    if (-not [string]::IsNullOrWhiteSpace($DnsForwarders)) {
      try {
        $ips = $DnsForwarders -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        if ($ips.Count -gt 0) {
          Add-DnsServerForwarder -IPAddress $ips -ErrorAction SilentlyContinue | Out-Null
          Write-Host "Configured DNS forwarders: $DnsForwarders"
        }
      } catch {}
    } else {
      Write-Host "No DNS forwarders configured (LAB_DNS_FORWARDERS empty)."
    }

    # DHCP Server (optional; keep if you want clients to DHCP inside lab)
    Install-WindowsFeature DHCP -IncludeManagementTools | Out-Null
    try { Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $DcIp -ErrorAction SilentlyContinue | Out-Null } catch {}

    $scopeId = $DhcpScopeNetwork
    $existing = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.ScopeId.IPAddressToString -eq $scopeId }
    if (-not $existing) {
      Write-Host "Creating DHCP scope $scopeId"
      Add-DhcpServerv4Scope -Name "LAB" -StartRange $DhcpScopeStart -EndRange $DhcpScopeEnd -SubnetMask "255.255.255.0" -State Active | Out-Null
    }

    Set-DhcpServerv4OptionValue -DnsDomain $DomainFqdn -DnsServer $DcIp | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($Gateway)) {
      Set-DhcpServerv4OptionValue -Router $Gateway | Out-Null
    }

    New-Item -ItemType File -Path $Phase3Done -Force | Out-Null
    Write-Host "Phase 3 complete."
  }

  # -----------------------------
  # READY GATE — SRV records + Netlogon
  # -----------------------------
  Write-Host "Waiting for Netlogon..."
  $svcOk = $false
  for ($i=0; $i -lt 60; $i++) {
    $svc = Get-Service Netlogon -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { $svcOk = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $svcOk) { throw "Netlogon not running after timeout" }

  Write-Host "Waiting for AD DNS SRV records to appear..."
  $Srv = "_ldap._tcp.dc._msdcs.$DomainFqdn"
  $ready = $false
  for ($i=0; $i -lt 120; $i++) { # 10 minutes
    try {
      Resolve-DnsName -Name $Srv -Type SRV -Server 127.0.0.1 -ErrorAction Stop | Out-Null
      $ready = $true
      break
    } catch {
      Start-Sleep -Seconds 5
    }
  }
  if (-not $ready) { throw "AD DNS SRV records not ready after timeout" }

  New-Item -ItemType File -Path $ReadyMarker -Force | Out-Null
  New-Item -ItemType File -Path $AllDone -Force | Out-Null
  Write-Host "DC is fully ready ✅"
  Write-Host "=== DC1 bootstrap complete ==="
}
finally {
  Stop-Transcript | Out-Null
}
