# LAB ONLY. Writes the industry-standard EICAR anti-malware test file on the lab VM and reports what
# Microsoft Defender Antivirus did with it. EICAR is a harmless 68-byte text string that every AV
# product detects on purpose (https://www.eicar.org). Run through Azure Run Command on vm-soc-win:
#   az vm run-command invoke -g rg-soc-lab -n vm-soc-win --command-id RunPowerShellScript --scripts @Invoke-EicarTest.ps1
# The string is kept in two halves so this script itself is not flagged when stored on a workstation.

$dir = "C:\soclab-eicar"
New-Item -ItemType Directory -Force $dir | Out-Null
$start = (Get-Date).AddMinutes(-1)
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

try {
    [IO.File]::WriteAllText("$dir\eicar-test.txt", $eicar, [Text.Encoding]::ASCII)
    "Wrote EICAR test file at " + (Get-Date).ToUniversalTime().ToString("o")
} catch {
    "Write blocked: " + $_.Exception.Message
}

Start-Sleep -Seconds 20
"File still on disk: " + (Test-Path "$dir\eicar-test.txt")

$detections = Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $start }
foreach ($x in $detections) {
    $t = Get-MpThreat -ThreatID $x.ThreatID
    "Detection: " + $t.ThreatName + " | action success: " + $x.ActionSuccess + " | " + ($x.Resources -join "; ")
}

Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Id = 1116, 1117; StartTime = $start } -ErrorAction SilentlyContinue |
    ForEach-Object { "Event " + $_.Id + " at " + $_.TimeCreated.ToUniversalTime().ToString("o") }
