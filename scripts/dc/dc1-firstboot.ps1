# dc1-firstboot.ps1
# Run once on first boot after sysprep.
# Creates AD DS forest + DNS + DHCP baseline for labs.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -----------------------------
# CONFIG (edit these)
# -----------------------------
$DomainFqdn        = "corp.local"
$NetbiosName       = "CORP"
$SafeModeAdminPass = "P@ssw0rd!ChangeMe"   # DSRM password (lab only)

# Network for DHCP scope (adjust to your lab)
$ScopeNetwork      = "10.0.0.0"
$ScopePrefix       = 24
$ScopeStart        = "10.0.0.50"
$ScopeEnd          = "10.0.0.200"
$Router            = "10.0.0.1"           # optional, can be empty if none
$DnsServer         = "10.0.0.10"          # DC1 intended IP

# Optional: create a lab user for testing
$CreateLabUser     = $true
$LabUsername       = "labuser"
$LabUserPassword   = "P@ssw0rd!ChangeMe"

# Marker
$MarkerDir         = "C:\ProgramData\LabBootstrap"
$MarkerFile        = Join-Path $MarkerDir "dc1.done"
$LogFile           = Join-Path $MarkerDir "dc1-firstboot.log"

New-Item -ItemType Directory -Path $MarkerDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append | Out-Null

try {
  if (Test-Path $MarkerFile) {
    Write-Host "DC bootstrap already done ($MarkerFile exists). Exiting."
    return
  }

  Write-Host "=== DC1 bootstrap start: $(Get-Date) ==="

  # Pick first active NIC
  $If = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
  if (-not $If) { throw "No active NIC found." }

  # Ensure DC uses itself for DNS
  Write-Host "Setting DNS server on DC NIC to $DnsServer ..."
  Set-DnsClientServerAddress -InterfaceIndex $If.ifIndex -ServerAddresses @($DnsServer)

  # Install roles
  Write-Host "Installing AD DS + DNS..."
  Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

  # Promote if not already a DC
  $isDc = $false
  try {
    $null = Get-ADDomain -ErrorAction Stop
    $isDc = $true
  } catch { $isDc = $false }

  if (-not $isDc) {
    Write-Host "Promoting to new forest: $DomainFqdn ..."
    $sec = ConvertTo-SecureString $SafeModeAdminPass -AsPlainText -Force

    Install-ADDSForest `
      -DomainName $DomainFqdn `
      -DomainNetbiosName $NetbiosName `
      -SafeModeAdministratorPassword $sec `
      -InstallDNS `
      -Force `
      -NoRebootOnCompletion

    Write-Host "AD DS promotion completed. Rebooting..."
    Restart-Computer -Force
    return
  }

  Write-Host "AD DS already present. Continuing with DHCP + objects."

  # DHCP
  Write-Host "Installing DHCP..."
  Install-WindowsFeature DHCP -IncludeManagementTools | Out-Null

  # Authorize DHCP in AD (safe if already authorized)
  try {
    Add-DhcpServerInDC -DnsName $env:COMPUTERNAME -IPAddress $DnsServer -ErrorAction SilentlyContinue | Out-Null
  } catch {}

  # Create scope if missing
  $scopeId = $ScopeNetwork
  $existing = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue | Where-Object { $_.ScopeId.IPAddressToString -eq $scopeId }
  if (-not $existing) {
    Write-Host "Creating DHCP scope $ScopeNetwork/$ScopePrefix ..."
    Add-DhcpServerv4Scope -Name "LAB" -StartRange $ScopeStart -EndRange $ScopeEnd -SubnetMask (("255.255.255.0")) -State Active | Out-Null
    # NOTE: SubnetMask above assumes /24; for other prefixes, set mask accordingly.
  } else {
    Write-Host "DHCP scope already exists."
  }

  # Set options (006 DNS, 015 DNS suffix, 003 router optional)
  Write-Host "Setting DHCP options..."
  Set-DhcpServerv4OptionValue -DnsDomain $DomainFqdn -DnsServer $DnsServer | Out-Null
  if ($Router -and $Router.Trim().Length -gt 0) {
    Set-DhcpServerv4OptionValue -Router $Router | Out-Null
  }

  # Create lab user (optional)
  if ($CreateLabUser) {
    Import-Module ActiveDirectory
    $ouDn = "OU=LabUsers,DC=" + ($DomainFqdn -split "\." -join ",DC=")

    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=LabUsers)" -ErrorAction SilentlyContinue)) {
      Write-Host "Creating OU LabUsers..."
      New-ADOrganizationalUnit -Name "LabUsers" -Path ("DC=" + ($DomainFqdn -split "\." -join ",DC=")) | Out-Null
    }

    $u = Get-ADUser -Filter "SamAccountName -eq '$LabUsername'" -ErrorAction SilentlyContinue
    if (-not $u) {
      Write-Host "Creating user $LabUsername ..."
      $up = ConvertTo-SecureString $LabUserPassword -AsPlainText -Force
      New-ADUser `
        -Name $LabUsername `
        -SamAccountName $LabUsername `
        -UserPrincipalName "$LabUsername@$DomainFqdn" `
        -Path $ouDn `
        -AccountPassword $up `
        -Enabled $true | Out-Null
      Add-ADGroupMember -Identity "Domain Users" -Members $LabUsername -ErrorAction SilentlyContinue
    } else {
      Write-Host "User $LabUsername already exists."
    }
  }

  New-Item -ItemType File -Path $MarkerFile -Force | Out-Null
  Write-Host "=== DC1 bootstrap complete ==="
}
finally {
  Stop-Transcript | Out-Null
}
