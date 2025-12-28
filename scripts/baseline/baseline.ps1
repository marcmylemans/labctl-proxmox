# Baseline for lab templates (run via SetupComplete.cmd)
# - Enables WinRM (HTTP 5985)
# - Enables RDP
# - Enables QEMU Guest Agent service if installed
# - Makes the machine automation-friendly (lab VLAN only)

$ErrorActionPreference = "Stop"

Write-Host "=== Baseline start: $(Get-Date) ==="

# -----------------------------
# WinRM
# -----------------------------
Write-Host "Configuring WinRM..."
winrm quickconfig -quiet | Out-Null

# Ensure service
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

# Allow required auth + unencrypted (OK only in isolated lab network)
winrm set winrm/config/service '@{AllowUnencrypted="true"}' | Out-Null
winrm set winrm/config/service/auth '@{Basic="true";Kerberos="true";Negotiate="true";NTLM="true"}' | Out-Null

# Increase shell limits a bit (optional)
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}' | Out-Null

# Open firewall for WinRM
Write-Host "Opening firewall for WinRM..."
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management" | Out-Null

# Ensure listener exists on HTTP 5985
# (quickconfig usually does this, but keep it deterministic)
$listener = winrm enumerate winrm/config/Listener | Out-String
if ($listener -notmatch "Transport\s*=\s*HTTP") {
    Write-Host "Creating HTTP WinRM listener..."
    winrm create winrm/config/Listener?Address=*+Transport=HTTP | Out-Null
}

# -----------------------------
# RDP
# -----------------------------
Write-Host "Enabling RDP..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" | Out-Null

# -----------------------------
# Power settings (optional but nice for labs)
# -----------------------------
Write-Host "Disabling sleep/hibernation..."
powercfg /hibernate off | Out-Null
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change standby-timeout-dc 0 | Out-Null

# -----------------------------
# QEMU Guest Agent (if installed)
# -----------------------------
$svc = Get-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Enabling QEMU Guest Agent..."
    Set-Service -Name "QEMU-GA" -StartupType Automatic
    Start-Service -Name "QEMU-GA" -ErrorAction SilentlyContinue
} else {
    Write-Host "QEMU Guest Agent not found (OK if not installed yet)."
}

# -----------------------------
# WinRM sanity check
# -----------------------------
Write-Host "Testing local WinRM..."
try {
    Test-WSMan -ComputerName localhost | Out-Null
    Write-Host "WinRM OK."
} catch {
    Write-Host "WinRM test failed: $($_.Exception.Message)"
    throw
}

Write-Host "=== Baseline complete: $(Get-Date) ==="
