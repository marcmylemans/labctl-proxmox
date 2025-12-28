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
$DhcpScopeNetwork  = Get-EnvOrDefault "LAB_SCOPE_NET"   "10.50.1.0"
$DhcpScopeStart    = Get-EnvOrDefault "LAB_SCOPE_START" "10.50.1.50"
$DhcpScopeEnd      = Get-EnvOrDefault "LAB_SCOPE_END"   "10.50.1.200"

# -----------------------------
# MARKERS
# -----------------------------
$StateDir = "C:\ProgramData\LabBootstrap"
$NetDone  = Join-Path $StateDir "phase-network.done"
$AdDone   = Join-Path $StateDir "phase-ad.done"
$AllDone  = Join-Path $StateDir "dc1.done"
$LogFile  = Join-Path $StateDir "dc1-firstboot.log"

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
    $hasStatic = Get-NetIPAddress -InterfaceIndex $If.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -eq $DcIp }

    if (-not $hasStatic) {
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
  # PHASE 2 — AD DS + DNS
  # -----------------------------
  if (-not (Test-Path $AdDone)) {
    Write-Host "Phase 2: installing AD DS + DNS..."
    Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

    $alreadyDc = $false
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      Get-ADDomain -ErrorAction Stop | Out-Null
      $alreadyDc = $true
    } catch { $alreadyDc = $false }

    if (-not $alreadyDc) {
      Write-Host "Promoting new forest $DomainFqdn"
      $sec = ConvertTo-SecureString $SafeModeAdminPass -AsPlainText -Force

      Install-ADDSForest `
        -DomainName $DomainFqdn `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $sec `
        -InstallDNS `
        -Force `
        -NoRebootOnCompletion

      New-Item -ItemType File -Path $AdDone -Force | Out-Null
      Write-Host "AD promotion complete. Rebooting..."
      Restart-Computer -Force
      return
    }

    New-Item -ItemType File -Path $AdDone -Force | Out-Null
  }

  # -----------------------------
  # PHASE 3 — DNS forwarders + DHCP
  # -----------------------------
  Write-Host "Phase 3: DNS forwarders + DHCP..."

  # Forwarders belong in DNS Server role, not NIC
  try { Add-DnsServerForwarder -IPAddress 1.1.1.1,8.8.8.8 -ErrorAction SilentlyContinue | Out-Null } catch {}

  # DHCP Server (optional; keep if you want clients to DHCP inside lab)
  Install-WindowsFeature DHCP -IncludeManagementTools | Out-Null

  try { Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $DcIp -ErrorAction SilentlyContinue | Out-Null } catch {}

  # Scope creation (expects /24; if you want variable masks later, we’ll adjust)
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

  New-Item -ItemType File -Path $AllDone -Force | Out-Null
  Write-Host "=== DC1 bootstrap complete ==="
}
finally {
  Stop-Transcript | Out-Null
}
