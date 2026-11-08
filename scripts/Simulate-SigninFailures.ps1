# Run as an administrator on the dedicated Windows lab VM only.
param([ValidateSet('Smoke', 'Full')][string]$Mode = 'Full')

$ErrorActionPreference = 'Stop'
$started = Get-Date
$logonAudit = '{0CCE9215-69AE-11D9-BED3-505054503030}'
& auditpol.exe /set /subcategory:$logonAudit /failure:enable
if ($LASTEXITCODE -ne 0) { throw 'Could not enable failed-logon auditing.' }

if (-not ('SocLabLogon' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class SocLabLogon {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUser(string username, string domain, string password,
        int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr token);
}
'@
}

$tests = if ($Mode -eq 'Smoke') {
    [ordered]@{ 'soclab-smoke' = 1 }
} else {
    [ordered]@{ 'soclab-control' = 1; 'soclab-probe' = 6 }
}
foreach ($account in $tests.Keys) {
    $existingAccount = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
    if ($existingAccount) { throw "Test account '$account' must not exist." }
    foreach ($attempt in 1..$tests[$account]) {
        $token = [IntPtr]::Zero
        $success = [SocLabLogon]::LogonUser($account, $env:COMPUTERNAME,
            'FakePasswordUsedOnlyToGenerateLabEvents9', 2, 0, [ref]$token)
        if ($success) {
            [void][SocLabLogon]::CloseHandle($token)
            throw 'A simulated sign-in unexpectedly succeeded.'
        }
        $win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($win32Error -ne 1326) { throw "Unexpected logon status: $win32Error." }
        Start-Sleep -Milliseconds 300
    }
}

$deadline = (Get-Date).AddSeconds(30)
do {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $started.AddSeconds(-1) } -ErrorAction SilentlyContinue
    $summary = foreach ($event in $events) {
        $data = ([xml]$event.ToXml()).Event.EventData.Data
        $target = ($data | Where-Object { $_.GetAttribute('Name') -eq 'TargetUserName' }).InnerText
        if ($target -and $tests.Contains($target)) {
            [pscustomobject]@{
                Account = $target
                TimeUtc = $event.TimeCreated.ToUniversalTime().ToString('o')
                EventId = $event.Id
                RecordId = $event.RecordId
            }
        }
    }
    if (@($summary).Count -ge ($tests.Values | Measure-Object -Sum).Sum) { break }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)
foreach ($account in $tests.Keys) {
    $count = @($summary | Where-Object Account -eq $account).Count
    if ($count -lt $tests[$account]) { throw "Expected $($tests[$account]) local events for $account, found $count." }
}
$summary | Sort-Object TimeUtc | ConvertTo-Json -Compress
