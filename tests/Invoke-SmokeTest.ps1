#Requires -Version 7.0
<#
.SYNOPSIS
    Smoke test runnable outside Windows (PowerShell 7 on Linux/macOS/CI).

.DESCRIPTION
    1) Parses every .ps1 of the repository.
    2) Static read-only guarantee: Invoke-ShareAudit.ps1 must not call any state-changing cmdlet.
    3) Runs Invoke-ShareAudit.ps1 against SIMULATED Windows cmdlets (tests/mocks/WinStubs) describing
       a "PC-SRV01" Windows 11 Pro file server with a mix of good and bad practices.
    4) Checks the outputs, the expected findings and the effective access matrix.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$script:fail = 0
function Check($cond, $msg) { if ($cond) { Write-Host "  [OK]   $msg" -ForegroundColor Green } else { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:fail++ } }

Write-Host '== 1. Syntax' -ForegroundColor Cyan
foreach ($f in Get-ChildItem $root -Filter *.ps1 -Recurse) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    Check (-not $e) "$($f.Name) $(if ($e) { $e[0].Message + ' L' + $e[0].Extent.StartLineNumber })"
}

Write-Host '== 2. Read-only guarantee (static analysis)' -ForegroundColor Cyan
$main = Join-Path $root 'Invoke-ShareAudit.ps1'
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($main, [ref]$t, [ref]$e)
$allowed = @('New-Item', 'Remove-Item', 'New-Object', 'Add-Member', 'Add-Content', 'Add-Type', 'Add-Finding', 'Add-CollectionError', 'New-SidSet', 'New-ZipFromFolder', 'Start-Process', 'Format-Value')
$verbs = '^(Set|Grant|Revoke|Block|Unblock|Disable|Enable|Remove|New|Add|Install|Uninstall|Rename|Stop|Start|Restart|Clear|Reset|Suspend|Resume|Register|Unregister|Update|Move|Copy|Close|Mount|Dismount|Lock|Unlock|Initialize|Format|Repair)-'
$calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
$bad = @($calls | Where-Object { $_ -match $verbs -and $_ -notin $allowed } | Select-Object -Unique)
Check (-not $bad.Count) "no state-changing cmdlet called $(if ($bad.Count) { '(found: ' + ($bad -join ', ') + ')' })"
$natives = @($calls | Where-Object { $_ -in @('net', 'icacls', 'reg', 'sc', 'netsh', 'wmic', 'cacls', 'takeown', 'vssadmin', 'bcdedit') })
Check (-not $natives.Count) "no risky native command $(if ($natives.Count) { '(found: ' + ($natives -join ', ') + ')' })"
$removes = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Remove-Item' }, $true))
Check ($removes.Count -le 2 -and @($removes | Where-Object { $_.Extent.Text -notmatch '\$tmp' }).Count -eq 0) 'Remove-Item only used on the secedit temporary file'

Write-Host '== 3. Audit on simulated environment' -ForegroundColor Cyan
$out = Join-Path ([System.IO.Path]::GetTempPath()) ('smoke_' + [guid]::NewGuid().ToString('N'))
$env:PSModulePath = (Join-Path $PSScriptRoot 'mocks') + [System.IO.Path]::PathSeparator + $env:PSModulePath
$env:COMPUTERNAME = 'PC-SRV01'
Import-Module WinStubs -Force
$res = & $main -OutputPath $out -Depth 3 6>$null 3>$null | Select-Object -Last 1
Check ($res -and (Test-Path $res.Report)) 'HTML report generated'
Check ($res.Zip -and (Test-Path $res.Zip)) 'ZIP archive generated'
foreach ($csv in 'findings.csv', 'shares.csv', 'share_permissions.csv', 'ntfs_share_roots.csv', 'access_matrix.csv', 'subfolders_explicit_permissions.csv', 'smb_sessions.csv', 'local_users.csv', 'firewall_smb_rules.csv', 'volumes.csv') {
    Check (Test-Path (Join-Path $res.Folder $csv)) "$csv present"
}
$json = Get-Content (Join-Path $res.Folder 'audit.json') -Raw | ConvertFrom-Json
Check ($json.Meta.Host -eq 'PC-SRV01') 'audit.json readable'
$errs = @($json.Sections | ForEach-Object { $s = $_; $_.Errors | ForEach-Object { "[$($s.Id)] $_" } })
# On Linux only the audit-policy API (advapi32) can fail; everything else is mocked
$unexpected = @($errs | Where-Object { $_ -notmatch '^\[Protection\]' })
Check (-not $unexpected.Count) "no unexpected collection error $(if ($unexpected.Count) { '(' + ($unexpected -join ' | ') + ')' })"
Check ($res.Verdict -eq 'At risk' -and $res.Critical -ge 1) "verdict 'At risk' with a Critical finding (got '$($res.Verdict)')"

$titles = $json.Findings.Title -join "`n"
foreach ($exp in @(
        "Share 'Scan' is reachable by the Guest account",
        'The Guest account is enabled',
        'uses the Public profile',
        'SMB is allowed inbound on the Public profile',
        'SMB inbound rules accept any source address',
        'SMB signing is not required by the server',
        'Insecure guest logons are allowed',
        'SMB encryption is not enabled',
        'LAN Manager authentication level is 3',
        "Share 'Commun' inherits the permissions of the volume root",
        "Any local account can modify share 'Commun'",
        "Any local account can modify share 'Scan'",
        "Sub-folders of 'Commun' explicitly grant write access",
        "Share 'Utenti' is inside user profiles",
        "Share 'Old' points to a missing folder",
        "Permissions granted to individual users on share 'Compta'",
        "Orphaned SIDs in the ACL of share 'Compta'",
        "Access-Based Enumeration is off on 'Commun'",
        'Enabled accounts are allowed to have no password',
        'No account lockout policy',
        'Minimum password length is 0',
        'Generic / shared account names',
        '16 distinct clients connected',
        'Guest or anonymous SMB sessions are active',
        'old SMB dialect',
        'Low free space on D:',
        "is not protected by BitLocker",
        'No shadow copies on D:',
        'PC goes to sleep after 30 minutes',
        'No known backup agent detected',
        'LLMNR is not disabled',
        'NetBIOS over TCP/IP is enabled',
        'Share host uses a DHCP address',
        '20 concurrent inbound SMB connections'
    )) { Check ($titles -like "*$exp*") "finding: $exp" }

# Things that must NOT be reported for the well-configured share
foreach ($notExp in @("Access-Based Enumeration is off on 'Compta'", "Any local account can modify share 'Compta'", "Share 'Compta' inherits", 'SMBv1 is enabled', "Share 'Compta' is reachable by the Guest")) {
    Check ($titles -notlike "*$notExp*") "no false positive: $notExp"
}

Write-Host '== 4. Effective access matrix' -ForegroundColor Cyan
$m = @($json.Data.AccessMatrix)
function Cell($u, $s) { ($m | Where-Object { $_.User -like "$u*" -and $_.Share -eq $s } | Select-Object -First 1).Effective }
Check ((Cell 'm.rossi' 'Compta') -eq 'Change') 'm.rossi (GRP_Compta_RW) -> Compta = Change'
Check ((Cell 'ufficio' 'Compta') -eq 'Read') 'ufficio (GRP_Compta_RO) -> Compta = Read'
Check ((Cell 'svc_scan' 'Compta') -eq 'None') 'svc_scan -> Compta = None'
Check ((Cell 'l.bianchi' 'Compta') -eq 'Change') 'l.bianchi (explicit ACE) -> Compta = Change'
Check ((Cell 'pietro' 'Compta') -eq 'None') 'pietro (local admin, remote UAC filtering) -> Compta = None'
Check ((Cell 'Guest' 'Scan') -eq 'Change') 'Guest -> Scan = Change'
Check ((Cell 'Guest' 'Commun') -eq 'None') 'Guest -> Commun = None (NTFS grants Authenticated Users, not Guest)'
Check (-not ($m | Where-Object Share -eq 'Old')) 'missing-path share excluded from the matrix'

Write-Host '== 5. Report and archive' -ForegroundColor Cyan
$html = Get-Content $res.Report -Raw
Check ($html -match 'Who can access what' -and $html -match 'Findings and recommendations') 'report sections present'
Check ($html -notmatch '<script') 'report contains no script'
Check (([regex]::Matches($html, '<table')).Count -eq ([regex]::Matches($html, '</table>')).Count) 'balanced <table> tags'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$za = [System.IO.Compression.ZipFile]::OpenRead($res.Zip)
$names = @($za.Entries | ForEach-Object FullName)
$logEntry = $za.GetEntry('audit.log'); $logTxt = ''
if ($logEntry) { $sr = New-Object System.IO.StreamReader($logEntry.Open()); $logTxt = $sr.ReadToEnd(); $sr.Dispose() }
$za.Dispose()
Check ('report.html' -in $names -and 'audit.json' -in $names) 'ZIP contains report.html and audit.json'
Check (-not @($names | Where-Object { $_ -match '\\' }).Count) 'ZIP entries use forward slashes'
Check ($logTxt -match 'Verdict :') 'audit.log in the ZIP is complete'

Write-Host '== 6. -Quick mode' -ForegroundColor Cyan
$res2 = & $main -OutputPath $out -Quick -NoZip 6>$null 3>$null | Select-Object -Last 1
$j2 = Get-Content (Join-Path $res2.Folder 'audit.json') -Raw | ConvertFrom-Json
Check ($j2.Data.SubfolderStats.Skipped -eq $true) 'sub-folder scan skipped'
Check (-not $res2.Zip) 'no ZIP with -NoZip'

Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($script:fail) { Write-Host "$($script:fail) check(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'All checks passed' -ForegroundColor Green
