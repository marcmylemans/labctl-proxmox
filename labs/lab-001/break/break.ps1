
$if = Get-NetAdapter | Where Status -eq Up | Select -First 1
Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses 1.1.1.1,10.0.0.10
ipconfig /flushdns
Write-Host "DNS subtly broken"
