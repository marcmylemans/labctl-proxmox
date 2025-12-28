@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Windows\Setup\Scripts\baseline.ps1" >> "C:\Windows\Setup\Scripts\baseline.log" 2>&1
exit /b 0
