#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of the SMB file shares of a Windows PC (workstation or server),
    with an HTML summary report, findings ranked by severity and raw CSV/JSON data.

.DESCRIPTION
    Designed for small businesses without a domain, where "the server" is often a
    Windows 10/11 Pro PC sharing folders in a workgroup. Works on domain members and
    Windows Server too.

    The script collects:
      - host information (OS, edition, workgroup/domain, uptime, client-OS limits)
      - network profiles (Private/Public/Domain) and IPv4 addressing
      - SMB server/client configuration (SMB1, signing, encryption, guest access,
        NTLM level, anonymous access, remote UAC filtering, auth rate limiter)
      - Windows Firewall profiles and File and Printer Sharing / SMB inbound rules
      - every share: share-level permissions, NTFS permissions of the share root,
        inheritance, ABE, encryption, offline caching, SACL
      - an approximate "who can access what" matrix (local users x shares)
      - sub-folders with explicit or broken-inheritance permissions (bounded scan)
      - volumes: file system, free space, BitLocker, shadow copies
      - local accounts, groups, password/lockout policy, logon rights
      - active SMB sessions and open files (client-OS 20 connections limit)
      - protection: Defender / antivirus, Controlled Folder Access, audit policy,
        power settings (sleep), LLMNR / NetBIOS, known backup agents

    It then produces findings (Critical / High / Medium / Low / Info) with
    recommendations, an overall verdict and score.

    NOTHING IS CHANGED ON THE SYSTEM. The only writes are the report files in
    -OutputPath and a temporary export of the local security policy (secedit),
    deleted immediately.

.PARAMETER OutputPath
    Root folder for the results. A sub-folder ShareAudit_<HOST>_<timestamp> is created.
    Default: C:\ShareAudit

.PARAMETER Depth
    How many levels of sub-folders below each share root are scanned for explicit
    permissions (0 = share roots only). Default: 2.

.PARAMETER MaxFolders
    Upper bound on the number of sub-folders scanned across all shares. Default: 3000.

.PARAMETER IncludeAdminShares
    Also analyse NTFS permissions of administrative shares (C$, D$, ADMIN$).

.PARAMETER Quick
    Skip the sub-folder scan and the scan of all firewall rules for ports 445/139.

.PARAMETER NoZip
    Do not create the ZIP archive of the results.

.PARAMETER OpenReport
    Open the HTML report at the end.

.EXAMPLE
    .\Invoke-ShareAudit.ps1
    Full audit, results in C:\ShareAudit\ShareAudit_<HOST>_<timestamp>\ + ZIP.

.EXAMPLE
    .\Invoke-ShareAudit.ps1 -OutputPath D:\Audits -Depth 3 -OpenReport

.OUTPUTS
    PSCustomObject with Folder, Report, Zip, Verdict, Score and counts per severity.

.NOTES
    Run as Administrator for complete results (sessions, SMB1 feature state, BitLocker,
    security policy, audit policy, SACLs). Compatible with Windows PowerShell 5.1 and
    PowerShell 7. Read-only.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = $(if ($env:SystemDrive) { Join-Path $env:SystemDrive 'ShareAudit' } else { Join-Path ([System.IO.Path]::GetTempPath()) 'ShareAudit' }),
    [ValidateRange(0, 10)][int]$Depth = 2,
    [ValidateRange(1, 100000)][int]$MaxFolders = 3000,
    [switch]$IncludeAdminShares,
    [switch]$Quick,
    [switch]$NoZip,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Continue'
$ScriptVersion = '1.0.0'
$StartTime = Get-Date

#region ---------------------------------------------------------------- constants

$SID_EVERYONE      = 'S-1-1-0'
$SID_CREATOR_OWNER = 'S-1-3-0'
$SID_NETWORK       = 'S-1-5-2'
$SID_INTERACTIVE   = 'S-1-5-4'
$SID_ANONYMOUS     = 'S-1-5-7'
$SID_AUTHUSERS     = 'S-1-5-11'
$SID_SYSTEM        = 'S-1-5-18'
$SID_ADMINS        = 'S-1-5-32-544'
$SID_USERS         = 'S-1-5-32-545'
$SID_GUESTS        = 'S-1-5-32-546'
$SID_BACKUPOPS     = 'S-1-5-32-551'
$SID_TRUSTEDINST   = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

# English fallback names (used only when the OS cannot translate a name, e.g. in tests)
$WellKnownNames = @{
    'Everyone'                          = $SID_EVERYONE
    'CREATOR OWNER'                     = $SID_CREATOR_OWNER
    'NT AUTHORITY\NETWORK'              = $SID_NETWORK
    'NT AUTHORITY\INTERACTIVE'          = $SID_INTERACTIVE
    'NT AUTHORITY\ANONYMOUS LOGON'      = $SID_ANONYMOUS
    'ANONYMOUS LOGON'                   = $SID_ANONYMOUS
    'NT AUTHORITY\Authenticated Users'  = $SID_AUTHUSERS
    'Authenticated Users'               = $SID_AUTHUSERS
    'NT AUTHORITY\SYSTEM'               = $SID_SYSTEM
    'SYSTEM'                            = $SID_SYSTEM
    'BUILTIN\Administrators'            = $SID_ADMINS
    'Administrators'                    = $SID_ADMINS
    'BUILTIN\Users'                     = $SID_USERS
    'Users'                             = $SID_USERS
    'BUILTIN\Guests'                    = $SID_GUESTS
    'Guests'                            = $SID_GUESTS
    'BUILTIN\Backup Operators'          = $SID_BACKUPOPS
    'NT SERVICE\TrustedInstaller'       = $SID_TRUSTEDINST
}
$WellKnownSidNames = @{
    $SID_EVERYONE = 'Everyone'; $SID_CREATOR_OWNER = 'CREATOR OWNER'; $SID_NETWORK = 'NETWORK'
    $SID_INTERACTIVE = 'INTERACTIVE'; $SID_ANONYMOUS = 'ANONYMOUS LOGON'; $SID_AUTHUSERS = 'Authenticated Users'
    $SID_SYSTEM = 'SYSTEM'; $SID_ADMINS = 'Administrators'; $SID_USERS = 'Users'; $SID_GUESTS = 'Guests'
    $SID_BACKUPOPS = 'Backup Operators'; $SID_TRUSTEDINST = 'TrustedInstaller'
}

# "Broad" identities: anyone (World) / any local account (AnyUser)
$WorldSids   = @($SID_EVERYONE, $SID_ANONYMOUS, $SID_GUESTS)
$AnyUserSids = @($SID_EVERYONE, $SID_AUTHUSERS, $SID_USERS, $SID_NETWORK, $SID_INTERACTIVE)
# Identities that are expected to have Full Control
$TrustedFullSids = @($SID_SYSTEM, $SID_ADMINS, $SID_CREATOR_OWNER, $SID_TRUSTEDINST, $SID_BACKUPOPS)

$LevelNames = @('None', 'Read', 'Change', 'Full')
$SeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

$AuditSubcategories = [ordered]@{
    'File System'         = '0CCE921D-69AE-11D9-BED3-505054503030'
    'File Share'          = '0CCE9224-69AE-11D9-BED3-505054503030'
    'Detailed File Share' = '0CCE9244-69AE-11D9-BED3-505054503030'
    'Logon'               = '0CCE9215-69AE-11D9-BED3-505054503030'
    'Account Lockout'     = '0CCE9217-69AE-11D9-BED3-505054503030'
}

$BackupAgentPattern = 'Veeam|Acronis|Active ?Backup|Cobian|Duplicati|UrBackup|Macrium|Backup ?Exec|Arcserve|Datto|Altaro|Nakivo|Iperius|Uranium|Bacula|Carbonite|Backblaze|IDrive|CrashPlan|Synology|Hyper ?Backup|Restic|Kopia|Arq|AOMEI|EaseUS|Paragon|Cohesity|Rubrik|Commvault|Unitrends'

#endregion

#region ---------------------------------------------------------------- helpers

$Data = [ordered]@{}
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Sections = New-Object System.Collections.Generic.List[object]
$script:CurrentSection = $null
$script:SidCache = @{}
$script:PrincipalMap = @{}
$script:LogFile = $null

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
}

function Add-CollectionError {
    param([string]$Message)
    if ($script:CurrentSection) { $script:CurrentSection.Errors.Add($Message) }
    Write-Log "  $Message" 'WARN'
}

function Invoke-Safe {
    param([scriptblock]$ScriptBlock, [string]$What)
    try { & $ScriptBlock } catch { Add-CollectionError ('{0}: {1}' -f $What, $_.Exception.Message); $null }
}

function Invoke-Section {
    param([string]$Id, [string]$Name, [scriptblock]$Body)
    Write-Log "Collecting: $Name"
    $sec = [pscustomobject]@{ Id = $Id; Name = $Name; Errors = (New-Object System.Collections.Generic.List[string]); DurationMs = 0 }
    $script:CurrentSection = $sec
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Body } catch { Add-CollectionError ('Section failed: {0} (line {1})' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) }
    $sw.Stop()
    $sec.DurationMs = $sw.ElapsedMilliseconds
    $script:Sections.Add($sec)
    $script:CurrentSection = $null
}

function Add-Finding {
    param(
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Category, [string]$Title, [string]$Detail, [string]$Recommendation, [string]$Target = ''
    )
    $script:Findings.Add([pscustomobject][ordered]@{
            Severity = $Severity; Category = $Category; Target = $Target; Title = $Title
            Detail = $Detail; Recommendation = $Recommendation
        })
}

function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        if ($null -ne $p.$Name) { return $p.$Name }
    } catch { Write-Verbose "Registry value not found: $Path\$Name" }
    return $Default
}

function Select-Props {
    param($Object, [string[]]$Names)
    $h = [ordered]@{}
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        if ($Object.PSObject.Properties[$n]) {
            $v = $Object.$n
            if ($null -ne $v -and $v -isnot [string] -and $v -isnot [bool] -and $v -isnot [datetime] -and $v -isnot [ValueType] -and $v -is [System.Collections.IEnumerable]) { $v = (@($v) | ForEach-Object { "$_" }) -join ', ' }
            elseif ($null -ne $v -and $v -is [enum]) { $v = "$v" }
            $h[$n] = $v
        }
    }
    [pscustomobject]$h
}

function Resolve-Sid {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ($Name -match '^S-1-[0-9-]+$') { return $Name }
    if ($script:SidCache.ContainsKey($Name)) { return $script:SidCache[$Name] }
    $sid = $null
    try { $sid = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null }
    if (-not $sid) {
        if ($WellKnownNames.ContainsKey($Name)) { $sid = $WellKnownNames[$Name] }
        elseif ($script:PrincipalMap.ContainsKey($Name)) { $sid = $script:PrincipalMap[$Name] }
        else {
            $short = ($Name -split '\\')[-1]
            if ($WellKnownNames.ContainsKey($short)) { $sid = $WellKnownNames[$short] }
            elseif ($script:PrincipalMap.ContainsKey($short)) { $sid = $script:PrincipalMap[$short] }
        }
    }
    $script:SidCache[$Name] = $sid
    return $sid
}

function Get-SidLabel {
    param([string]$Sid, [string]$Fallback)
    if ($WellKnownSidNames.ContainsKey("$Sid")) { return $WellKnownSidNames[$Sid] }
    if ($Fallback) { return $Fallback }
    return $Sid
}

function ConvertTo-RightsMask {
    param($Rights)
    if ($null -eq $Rights) { return [long]0 }
    try { return ([long]([int]([System.Security.AccessControl.FileSystemRights]$Rights))) -band 4294967295L } catch { Write-Verbose 'Rights not an enum' }
    try { return ([long]$Rights) -band 4294967295L } catch { return [long]0 }
}

function Get-NtfsLevel {
    # 0 None, 1 Read, 2 Change (write/delete), 3 Full (or can change permissions / take ownership)
    param([long]$Mask)
    $GENERIC_ALL = 0x10000000; $GENERIC_EXECUTE = 0x20000000; $GENERIC_WRITE = 0x40000000; $GENERIC_READ = 2147483648L
    if ((($Mask -band 0x1F01FF) -eq 0x1F01FF) -or ($Mask -band $GENERIC_ALL) -or ($Mask -band 0xC0000)) { return 3 }
    if ($Mask -band (0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor $GENERIC_WRITE)) { return 2 }
    if ($Mask -band (0x1 -bor 0x20 -bor $GENERIC_READ -bor $GENERIC_EXECUTE)) { return 1 }
    return 0
}

function Get-ShareRightLevel {
    param([string]$Right)
    switch ($Right) { 'Full' { 3 } 'Change' { 2 } 'Read' { 1 } 'Custom' { 1 } default { 0 } }
}

function ConvertTo-AceRow {
    param($Rule)
    $id = "$($Rule.IdentityReference)"
    $sid = Resolve-Sid $id
    $mask = ConvertTo-RightsMask $Rule.FileSystemRights
    [pscustomobject][ordered]@{
        Identity    = $id
        SID         = $sid
        Type        = "$($Rule.AccessControlType)"
        Rights      = "$($Rule.FileSystemRights)"
        Level       = Get-NtfsLevel $mask
        Mask        = $mask
        IsInherited = [bool]$Rule.IsInherited
        Inheritance = "$($Rule.InheritanceFlags)"
        Propagation = "$($Rule.PropagationFlags)"
    }
}

function Get-ParentPath {
    param([string]$Path)
    $p = $Path.TrimEnd('\')
    if ($p -notmatch '\\') { return $null }
    return ($p -replace '\\[^\\]+$', '')
}

function Test-DriveRoot { param([string]$Path) return ($Path -match '^[A-Za-z]:\\?$') }
function Get-DriveOf { param([string]$Path) if ($Path -match '^([A-Za-z]:)') { return $Matches[1].ToUpper() } return $null }

function Join-Limited {
    param($Items, [int]$Max = 12)
    $a = @($Items)
    if ($a.Count -le $Max) { return ($a -join ', ') }
    return (($a | Select-Object -First $Max) -join ', ') + (' ... (+{0} more)' -f ($a.Count - $Max))
}

function Get-GroupMembersSafe {
    param($Group)
    try {
        return @(Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{ Group = $Group.Name; GroupSID = "$($Group.SID)"; Name = "$($_.Name)"; SID = "$($_.SID)"; ObjectClass = "$($_.ObjectClass)"; Source = "$($_.PrincipalSource)" }
            })
    } catch {
        # Get-LocalGroupMember fails on groups containing orphaned / Entra ID SIDs: fall back to ADSI
        try {
            $adsi = [ADSI]"WinNT://./$($Group.Name),group"
            return @($adsi.psbase.Invoke('Members') | ForEach-Object {
                    $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
                    $bytes = $_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
                    $sid = (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
                    [pscustomobject][ordered]@{ Group = $Group.Name; GroupSID = "$($Group.SID)"; Name = (($path -replace '^WinNT://', '') -replace '/', '\'); SID = $sid; ObjectClass = ''; Source = 'ADSI' }
                })
        } catch {
            Add-CollectionError ('Members of group {0}: {1}' -f $Group.Name, $_.Exception.Message)
            return @()
        }
    }
}

function Get-UserToken {
    # Approximation of the SIDs present in the network logon token of a local account
    param($User)
    $sids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [void]$sids.Add($User.SID)
    $isGuest = $User.SID -match '-501$'
    if ($isGuest) { foreach ($s in @($SID_EVERYONE, $SID_GUESTS, $SID_NETWORK)) { [void]$sids.Add($s) } }
    else { foreach ($s in @($SID_EVERYONE, $SID_AUTHUSERS, $SID_USERS, $SID_NETWORK)) { [void]$sids.Add($s) } }
    foreach ($m in @($Data.GroupMembers)) {
        if ($m.SID -and $sids.Contains($m.SID) -and $m.GroupSID) { [void]$sids.Add($m.GroupSID) }
    }
    $filtered = $false
    if (-not $isGuest -and $sids.Contains($SID_ADMINS)) {
        $is500 = $User.SID -match '-500$'
        $latfp = [int]$Data.SecurityRegistry.LocalAccountTokenFilterPolicy
        $fat = [int]$Data.SecurityRegistry.FilterAdministratorToken
        if (($is500 -and $fat -eq 1) -or (-not $is500 -and $latfp -ne 1)) { [void]$sids.Remove($SID_ADMINS); $filtered = $true }
    }
    [pscustomobject]@{ Sids = $sids; AdminFiltered = $filtered; IsGuest = $isGuest }
}

function New-SidSet {
    param([string[]]$Sids)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Sids) { if ($s) { [void]$set.Add($s) } }
    return , $set
}

function Get-ShareEffectiveLevel {
    param([string]$ShareName, $Sids)
    $aces = @($Data.ShareAccess | Where-Object { $_.Share -eq $ShareName -and $_.SID -and $Sids.Contains($_.SID) })
    if (@($aces | Where-Object { $_.AccessControlType -eq 'Deny' }).Count) { return 0 }
    $max = 0
    foreach ($a in $aces) { $l = Get-ShareRightLevel $a.AccessRight; if ($l -gt $max) { $max = $l } }
    return $max
}

function Get-NtfsEffectiveLevel {
    param($Aces, $Sids)
    $max = 0; [long]$deny = 0
    foreach ($a in @($Aces)) {
        if (-not $a.SID -or -not $Sids.Contains($a.SID)) { continue }
        if ($a.Type -eq 'Deny') { $deny = $deny -bor [long]$a.Mask }
        elseif ($a.Level -gt $max) { $max = $a.Level }
    }
    if ($deny) {
        if ((Get-NtfsLevel $deny) -eq 3 -or ($deny -band 0x1)) { return 0 }
        if ((Get-NtfsLevel $deny) -ge 2 -and $max -gt 1) { return 1 }
    }
    return $max
}

function Get-Effective {
    param([string]$ShareName, $Sids)
    $sl = Get-ShareEffectiveLevel -ShareName $ShareName -Sids $Sids
    $aces = @($Data.NtfsRoot | Where-Object { $_.Share -eq $ShareName })
    $nl = Get-NtfsEffectiveLevel -Aces $aces -Sids $Sids
    [pscustomobject]@{ Share = $sl; Ntfs = $nl; Effective = [Math]::Min($sl, $nl) }
}

function Get-PowerSettingAc {
    param([string]$SubGroup, [string]$Setting)
    $out = (powercfg /query SCHEME_CURRENT $SubGroup $Setting 2>$null) -join "`n"
    $hex = [regex]::Matches($out, '0x[0-9a-fA-F]{8}')
    if ($hex.Count -ge 2) { return [Convert]::ToInt64($hex[$hex.Count - 2].Value.Substring(2), 16) }
    return $null
}

function Get-AuditPolicyState {
    param([string]$Guid)
    if (-not ('ShareAuditPol' -as [type])) {
        try {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ShareAuditPol {
    [StructLayout(LayoutKind.Sequential)]
    public struct AUDIT_POLICY_INFORMATION { public Guid AuditSubCategoryGuid; public uint AuditingInformation; public Guid AuditCategoryGuid; }
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AuditQuerySystemPolicy(Guid[] pSubCategoryGuids, uint dwPolicyCount, out IntPtr ppAuditPolicy);
    [DllImport("advapi32.dll")]
    static extern void AuditFree(IntPtr buffer);
    public static int Query(Guid g) {
        IntPtr p;
        if (!AuditQuerySystemPolicy(new Guid[] { g }, 1, out p)) { return -1; }
        AUDIT_POLICY_INFORMATION info = (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(p, typeof(AUDIT_POLICY_INFORMATION));
        AuditFree(p);
        return (int)info.AuditingInformation;
    }
}
'@
        } catch { Write-Verbose 'Add-Type ShareAuditPol failed' }
    }
    $state = -1
    try { $state = [ShareAuditPol]::Query([guid]$Guid) } catch { $state = -1 }
    if ($state -ge 0) {
        return [pscustomobject]@{ Success = [bool]($state -band 1); Failure = [bool]($state -band 2); Raw = $state; Source = 'API' }
    }
    # Fallback: auditpol (setting text is localized, Raw is kept for the report)
    $csv = auditpol /get "/subcategory:{$Guid}" /r 2>$null
    if ($csv) {
        $row = @($csv | Where-Object { $_ } | ConvertFrom-Csv) | Select-Object -First 1
        if ($row) {
            $txt = "$($row.PSObject.Properties.Value[4])"
            return [pscustomobject]@{ Success = $null; Failure = $null; Raw = $txt; Source = 'auditpol' }
        }
    }
    return $null
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm') }
    if ($Value -is [bool]) { if ($Value) { return 'Yes' } else { return 'No' } }
    if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) { return ((@($Value) | ForEach-Object { "$_" }) -join ', ') }
    return "$Value"
}

function ConvertTo-Html-Encoded { param($Value) return [System.Net.WebUtility]::HtmlEncode((Format-Value $Value)) }

function ConvertTo-HtmlTable {
    param($Rows, [string[]]$Columns, [string]$Empty = 'No data.')
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return ('<p class="muted">{0}</p>' -f [System.Net.WebUtility]::HtmlEncode($Empty)) }
    if (-not $Columns) { $Columns = @($rows[0].PSObject.Properties.Name) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tw"><table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + [System.Net.WebUtility]::HtmlEncode($c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $r.$c
            if ($c -eq 'Severity') { [void]$sb.Append(('<td><span class="sev sev-{0}">{0}</span></td>' -f $v)) }
            else { [void]$sb.Append('<td>' + (ConvertTo-Html-Encoded $v) + '</td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function Export-CsvSafe {
    param($Rows, [string]$Name)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return }
    $path = Join-Path $script:Folder $Name
    $flat = foreach ($r in $rows) {
        $h = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = Format-Value $p.Value }
        [pscustomobject]$h
    }
    $flat | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -UseCulture
}

function New-ZipFromFolder {
    param([string]$Folder, [string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $root = $Folder.TrimEnd('\', '/')
    $fs = [System.IO.File]::Open($ZipPath, [System.IO.FileMode]::Create)
    $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Folder -File -Recurse)) {
            $rel = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($za, $f.FullName, $rel)
        }
    } finally { $za.Dispose(); $fs.Dispose() }
}

#endregion

#region ---------------------------------------------------------------- init

$HostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
$IsAdmin = $false
try { $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $IsAdmin = $false }

$script:Folder = Join-Path $OutputPath ('ShareAudit_{0}_{1}' -f $HostName, $StartTime.ToString('yyyyMMdd_HHmmss'))
$null = New-Item -ItemType Directory -Path $script:Folder -Force -ErrorAction Stop
$script:LogFile = Join-Path $script:Folder 'audit.log'

Write-Log "SMB Share Audit v$ScriptVersion on $HostName (read-only)"
Write-Log "Output folder: $($script:Folder)"
if (-not $IsAdmin) { Write-Log 'Not running elevated: sessions, SMB1 feature, BitLocker, security/audit policy and SACLs may be incomplete. Run as Administrator for a full audit.' 'WARN' }

#endregion

#region ---------------------------------------------------------------- collection

Invoke-Section 'Host' 'Host and operating system' {
    $os = Invoke-Safe { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } 'Win32_OperatingSystem'
    $cs = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } 'Win32_ComputerSystem'
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $lastBoot = $null; $uptime = $null
    if ($os -and $os.LastBootUpTime) { $lastBoot = [datetime]$os.LastBootUpTime; $uptime = [Math]::Round(((Get-Date) - $lastBoot).TotalDays, 1) }
    $ptype = $null; if ($os) { $ptype = [int]$os.ProductType }
    $Data.Host = [pscustomobject][ordered]@{
        ComputerName   = $HostName
        OS             = $(if ($os) { $os.Caption } else { $null })
        DisplayVersion = Get-RegValue $cv 'DisplayVersion'
        Build          = $(if ($os) { '{0}.{1}' -f $os.BuildNumber, (Get-RegValue $cv 'UBR' 0) } else { $null })
        EditionID      = Get-RegValue $cv 'EditionID'
        Architecture   = $(if ($os) { $os.OSArchitecture } else { $null })
        ProductType    = $ptype
        IsClientOS     = ($ptype -eq 1)
        PartOfDomain   = $(if ($cs) { [bool]$cs.PartOfDomain } else { $null })
        DomainOrWorkgroup = $(if ($cs) { if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup } } else { $null })
        Manufacturer   = $(if ($cs) { $cs.Manufacturer } else { $null })
        Model          = $(if ($cs) { $cs.Model } else { $null })
        LastBoot       = $lastBoot
        UptimeDays     = $uptime
        Elevated       = $IsAdmin
        PSVersion      = $PSVersionTable.PSVersion.ToString()
        AuditDate      = $StartTime
        ScriptVersion  = $ScriptVersion
    }
}

Invoke-Section 'Accounts' 'Local accounts and groups' {
    $Data.Users = @(); $Data.Groups = @(); $Data.GroupMembers = @()
    $users = @(Invoke-Safe { Get-LocalUser -ErrorAction Stop } 'Get-LocalUser')
    $Data.Users = @($users | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{
                Name = "$($_.Name)"; SID = "$($_.SID)"; Enabled = [bool]$_.Enabled; PasswordRequired = [bool]$_.PasswordRequired
                PasswordExpires = $_.PasswordExpires; PasswordLastSet = $_.PasswordLastSet; LastLogon = $_.LastLogon
                Description = "$($_.Description)"; Source = "$($_.PrincipalSource)"
            }
        })
    foreach ($u in $Data.Users) { $script:PrincipalMap[$u.Name] = $u.SID; $script:PrincipalMap["$HostName\$($u.Name)"] = $u.SID }
    $groups = @(Invoke-Safe { Get-LocalGroup -ErrorAction Stop } 'Get-LocalGroup')
    $Data.Groups = @($groups | Where-Object { $_ } | ForEach-Object { [pscustomobject][ordered]@{ Name = "$($_.Name)"; SID = "$($_.SID)"; Description = "$($_.Description)" } })
    foreach ($g in $Data.Groups) { $script:PrincipalMap[$g.Name] = $g.SID; $script:PrincipalMap["$HostName\$($g.Name)"] = $g.SID; $script:PrincipalMap["BUILTIN\$($g.Name)"] = $g.SID }
    $members = New-Object System.Collections.Generic.List[object]
    foreach ($g in $Data.Groups) { foreach ($m in @(Get-GroupMembersSafe $g)) { if ($m) { $members.Add($m) } } }
    $Data.GroupMembers = $members.ToArray()
}

Invoke-Section 'Policy' 'Local security policy (password, lockout, logon rights)' {
    $Data.Policy = $null
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('shareaudit_secpol_{0}.inf' -f [guid]::NewGuid().ToString('N'))
    try {
        $null = secedit /export /cfg "$tmp" /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if (Test-Path -LiteralPath $tmp) {
            $ini = @{}
            foreach ($line in Get-Content -LiteralPath $tmp) { if ($line -match '^\s*([^=\[;]+?)\s*=\s*(.*)$') { $ini[$Matches[1]] = $Matches[2].Trim() } }
            $toInt = { param($k) if ($ini.ContainsKey($k) -and $ini[$k] -match '^-?\d+$') { [int]$ini[$k] } else { $null } }
            $toList = { param($k) if ($ini.ContainsKey($k)) { @($ini[$k] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }) } else { @() } }
            $Data.Policy = [pscustomobject][ordered]@{
                MinimumPasswordLength      = & $toInt 'MinimumPasswordLength'
                PasswordComplexity         = & $toInt 'PasswordComplexity'
                MaximumPasswordAge         = & $toInt 'MaximumPasswordAge'
                LockoutBadCount            = & $toInt 'LockoutBadCount'
                LockoutDuration            = & $toInt 'LockoutDuration'
                EnableGuestAccount         = & $toInt 'EnableGuestAccount'
                LSAAnonymousNameLookup     = & $toInt 'LSAAnonymousNameLookup'
                SeNetworkLogonRight        = (& $toList 'SeNetworkLogonRight') -join ', '
                SeDenyNetworkLogonRight    = (& $toList 'SeDenyNetworkLogonRight') -join ', '
                SeInteractiveLogonRight    = (& $toList 'SeInteractiveLogonRight') -join ', '
                SeDenyInteractiveLogonRight = (& $toList 'SeDenyInteractiveLogonRight') -join ', '
            }
        } else { Add-CollectionError 'secedit export produced no file (requires elevation)' }
    } catch { Add-CollectionError ('secedit: {0}' -f $_.Exception.Message) }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

Invoke-Section 'Network' 'Network profiles and addressing' {
    $Data.NetProfiles = @(Invoke-Safe { Get-NetConnectionProfile -ErrorAction Stop } 'Get-NetConnectionProfile' | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{ Name = "$($_.Name)"; InterfaceAlias = "$($_.InterfaceAlias)"; InterfaceIndex = $_.InterfaceIndex; NetworkCategory = "$($_.NetworkCategory)"; IPv4Connectivity = "$($_.IPv4Connectivity)" }
        })
    $Data.IPv4 = @(Invoke-Safe { Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop } 'Get-NetIPAddress' | Where-Object { $_ -and "$($_.IPAddress)" -notmatch '^(127\.|169\.254\.)' } | ForEach-Object {
            [pscustomobject][ordered]@{ InterfaceAlias = "$($_.InterfaceAlias)"; InterfaceIndex = $_.InterfaceIndex; IPAddress = "$($_.IPAddress)"; PrefixLength = $_.PrefixLength; PrefixOrigin = "$($_.PrefixOrigin)" }
        })
    $Data.NetBios = @(Invoke-Safe { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop } 'Win32_NetworkAdapterConfiguration' | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{ Adapter = "$($_.Description)"; TcpipNetbiosOptions = $_.TcpipNetbiosOptions; NetBIOS = $(switch ($_.TcpipNetbiosOptions) { 0 { 'Default (DHCP)' } 1 { 'Enabled' } 2 { 'Disabled' } default { 'Unknown' } }) }
        })
    $Data.Llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
}

Invoke-Section 'Smb' 'SMB server / client configuration and security registry' {
    $srv = Invoke-Safe { Get-SmbServerConfiguration -ErrorAction Stop } 'Get-SmbServerConfiguration'
    $Data.SmbServer = Select-Props $srv @('EnableSMB1Protocol', 'EnableSMB2Protocol', 'Smb2DialectMin', 'Smb2DialectMax', 'RequireSecuritySignature', 'EnableSecuritySignature',
        'EncryptData', 'RejectUnencryptedAccess', 'EnableAuthRateLimiter', 'InvalidAuthenticationDelayTimeInMs', 'AutoShareServer', 'AutoShareWorkstation',
        'AnnounceServer', 'AuditSmb1Access', 'EnableLeasing', 'EnableMultiChannel', 'ServerHidden', 'NullSessionPipes', 'NullSessionShares', 'RestrictNamedpipeAccessViaQuic')
    $cli = Invoke-Safe { Get-SmbClientConfiguration -ErrorAction Stop } 'Get-SmbClientConfiguration'
    $Data.SmbClient = Select-Props $cli @('EnableInsecureGuestLogons', 'RequireSecuritySignature', 'EnableSecuritySignature', 'RequireEncryption', 'BlockNTLM', 'Smb2DialectMin', 'Smb2DialectMax')
    $Data.Smb1Feature = $null
    if ($IsAdmin -or (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        $f = Invoke-Safe { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop } 'Get-WindowsOptionalFeature SMB1Protocol'
        if ($f) { $Data.Smb1Feature = "$($f.State)" }
    }
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lms = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lmw = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $lmwPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $Data.SecurityRegistry = [pscustomobject][ordered]@{
        LmCompatibilityLevel          = Get-RegValue $lsa 'LmCompatibilityLevel'
        NoLmHash                      = Get-RegValue $lsa 'NoLmHash'
        RestrictAnonymous             = Get-RegValue $lsa 'RestrictAnonymous'
        RestrictAnonymousSAM          = Get-RegValue $lsa 'RestrictAnonymousSAM'
        EveryoneIncludesAnonymous     = Get-RegValue $lsa 'EveryoneIncludesAnonymous'
        ForceGuest                    = Get-RegValue $lsa 'ForceGuest'
        LimitBlankPasswordUse         = Get-RegValue $lsa 'LimitBlankPasswordUse'
        RestrictNullSessAccess        = Get-RegValue $lms 'RestrictNullSessAccess'
        NullSessionShares             = Format-Value (Get-RegValue $lms 'NullSessionShares')
        AutoShareWks                  = Get-RegValue $lms 'AutoShareWks'
        AllowInsecureGuestAuth        = Get-RegValue $lmw 'AllowInsecureGuestAuth'
        AllowInsecureGuestAuthPolicy  = Get-RegValue $lmwPol 'AllowInsecureGuestAuth'
        LocalAccountTokenFilterPolicy = Get-RegValue $sys 'LocalAccountTokenFilterPolicy'
        FilterAdministratorToken      = Get-RegValue $sys 'FilterAdministratorToken'
    }
}

Invoke-Section 'Firewall' 'Windows Firewall profiles and SMB rules' {
    $Data.FirewallProfiles = @(Invoke-Safe { Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop } 'Get-NetFirewallProfile' | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{ Profile = "$($_.Name)"; Enabled = ("$($_.Enabled)" -eq 'True'); DefaultInboundAction = "$($_.DefaultInboundAction)"; LogBlocked = "$($_.LogBlocked)" }
        })
    $rules = New-Object System.Collections.Generic.List[object]
    $addRule = {
        param($r, [string]$Source)
        $af = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $rules.Add([pscustomobject][ordered]@{
                Source = $Source; Name = "$($r.Name)"; DisplayName = "$($r.DisplayName)"; Enabled = ("$($r.Enabled)" -eq 'True')
                Direction = "$($r.Direction)"; Action = "$($r.Action)"; Profile = "$($r.Profile)"
                Protocol = $(if ($pf) { "$($pf.Protocol)" } else { '' }); LocalPort = $(if ($pf) { Format-Value $pf.LocalPort } else { '' })
                RemoteAddress = $(if ($af) { Format-Value $af.RemoteAddress } else { '' })
            })
    }
    $fps = @(Invoke-Safe { Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' -PolicyStore ActiveStore -ErrorAction Stop } 'File and Printer Sharing rules')
    foreach ($r in $fps) { if ($r -and "$($r.Direction)" -eq 'Inbound') { & $addRule $r 'File and Printer Sharing' } }
    if (-not $Quick) {
        $known = @{}; foreach ($r in $rules) { $known[$r.Name] = $true }
        $inbound = @(Invoke-Safe { Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -PolicyStore ActiveStore -ErrorAction Stop } 'Inbound allow rules')
        foreach ($r in $inbound) {
            if (-not $r -or $known.ContainsKey("$($r.Name)")) { continue }
            $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($pf -and (@($pf.LocalPort) | Where-Object { "$_" -in @('445', '139') })) { & $addRule $r 'Other rule (port 445/139)' }
        }
    }
    $Data.FirewallRules = $rules.ToArray()
}

Invoke-Section 'Shares' 'Shares, share permissions and NTFS permissions of share roots' {
    $Data.Shares = @(); $Data.ShareAccess = @(); $Data.NtfsRoot = @()
    $shares = @(Get-SmbShare -ErrorAction Stop)
    $rowsS = New-Object System.Collections.Generic.List[object]
    $rowsA = New-Object System.Collections.Generic.List[object]
    $rowsN = New-Object System.Collections.Generic.List[object]
    foreach ($s in $shares) {
        if (-not $s) { continue }
        $name = "$($s.Name)"; $path = "$($s.Path)"
        $isFs = ("$($s.ShareType)" -eq 'FileSystemDirectory' -or -not "$($s.ShareType)")
        $isAdminShare = ([bool]$s.Special -or $name -match '^[A-Za-z]\$$' -or $name -in @('ADMIN$', 'IPC$'))
        $isData = ($isFs -and -not $isAdminShare -and $name -ne 'print$' -and $path)
        $exists = $null; $owner = $null; $protected = $null; $saclCount = $null
        if ($path -and $isFs -and $name -ne 'IPC$') { $exists = [bool](Test-Path -LiteralPath $path -PathType Container) }
        foreach ($a in @(Invoke-Safe { Get-SmbShareAccess -Name $name -ErrorAction Stop } "Get-SmbShareAccess $name")) {
            if (-not $a) { continue }
            $rowsA.Add([pscustomobject][ordered]@{ Share = $name; AccountName = "$($a.AccountName)"; SID = (Resolve-Sid "$($a.AccountName)"); AccessControlType = "$($a.AccessControlType)"; AccessRight = "$($a.AccessRight)" })
        }
        if ($exists -and ($isData -or ($IncludeAdminShares -and $isAdminShare -and $name -ne 'IPC$'))) {
            $acl = Invoke-Safe { Get-Acl -LiteralPath $path -ErrorAction Stop } "Get-Acl $path"
            if ($acl) {
                $owner = "$($acl.Owner)"; $protected = [bool]$acl.AreAccessRulesProtected
                foreach ($rule in @($acl.Access)) {
                    if (-not $rule) { continue }
                    $row = ConvertTo-AceRow $rule
                    $row | Add-Member -NotePropertyName Share -NotePropertyValue $name -PassThru | Add-Member -NotePropertyName Path -NotePropertyValue $path
                    $rowsN.Add($row)
                }
            }
            if ($IsAdmin) {
                $aclA = $null
                try { $aclA = Get-Acl -LiteralPath $path -Audit -ErrorAction Stop } catch { $aclA = $null }
                if ($aclA) { $saclCount = @($aclA.Audit | Where-Object { $_ }).Count }
            }
        }
        $rowsS.Add([pscustomobject][ordered]@{
                Name = $name; Path = $path; Description = "$($s.Description)"; Type = "$($s.ShareType)"; IsData = [bool]$isData; IsAdminShare = $isAdminShare
                PathExists = $exists; ABE = "$($s.FolderEnumerationMode)"; EncryptData = $s.EncryptData; CachingMode = "$($s.CachingMode)"
                ConcurrentUserLimit = $s.ConcurrentUserLimit; CurrentUsers = $s.CurrentUsers; ScopeName = "$($s.ScopeName)"
                Owner = $owner; InheritanceBlocked = $protected; SaclEntries = $saclCount
            })
    }
    $Data.Shares = $rowsS.ToArray(); $Data.ShareAccess = $rowsA.ToArray(); $Data.NtfsRoot = $rowsN.ToArray()
    Write-Log ('  {0} share(s), {1} data share(s)' -f $Data.Shares.Count, @($Data.Shares | Where-Object IsData).Count)
}

$DataShares = @($Data.Shares | Where-Object { $_.IsData })
$MatrixShares = @($DataShares | Where-Object { $_.PathExists -ne $false })

Invoke-Section 'Volumes' 'Volumes, BitLocker and shadow copies' {
    $Data.Volumes = @()
    $disks = @(Invoke-Safe { Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop } 'Win32_LogicalDisk')
    $vols = @(Invoke-Safe { Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop } 'Win32_Volume')
    $shadows = @(Invoke-Safe { Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop } 'Win32_ShadowCopy')
    $shareDrives = @($Data.Shares | Where-Object { $_.IsData } | ForEach-Object { Get-DriveOf $_.Path } | Where-Object { $_ } | Select-Object -Unique)
    $rows = foreach ($d in $disks) {
        if (-not $d) { continue }
        $dl = "$($d.DeviceID)".ToUpper()
        $vol = $vols | Where-Object { "$($_.DriveLetter)".ToUpper() -eq $dl } | Select-Object -First 1
        $sc = 0
        if ($vol) { $sc = @($shadows | Where-Object { "$($_.VolumeName)" -eq "$($vol.DeviceID)" }).Count }
        $bl = $null
        if ($dl -in $shareDrives -or $dl -eq "$env:SystemDrive".ToUpper()) {
            $b = $null
            try { $b = Get-BitLockerVolume -MountPoint $dl -ErrorAction Stop } catch { $b = $null }
            if ($b) { $bl = "$($b.ProtectionStatus)" }
            else {
                try {
                    $ev = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$dl'" -ErrorAction Stop
                    if ($ev) { $bl = $(switch ([int]$ev.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } default { 'Unknown' } }) }
                } catch { Write-Verbose "BitLocker state unavailable for $dl" }
            }
        }
        $size = [double]$d.Size; $free = [double]$d.FreeSpace
        [pscustomobject][ordered]@{
            Drive = $dl; Label = "$($d.VolumeName)"; FileSystem = "$($d.FileSystem)"
            SizeGB = [Math]::Round($size / 1GB, 1); FreeGB = [Math]::Round($free / 1GB, 1)
            FreePct = $(if ($size -gt 0) { [Math]::Round(100 * $free / $size, 1) } else { $null })
            HostsShares = ($dl -in $shareDrives); BitLocker = $bl; ShadowCopies = $sc
        }
    }
    $Data.Volumes = @($rows)
}

Invoke-Section 'Matrix' 'Effective access matrix (local users x data shares)' {
    $Data.AccessMatrix = @()
    $rows = New-Object System.Collections.Generic.List[object]
    $candidates = @($Data.Users | Where-Object { $_.Enabled })
    foreach ($u in $candidates) {
        $tok = Get-UserToken $u
        $label = $u.Name
        if ($tok.IsGuest) { $label = "$($u.Name) (guest)" }
        elseif ($tok.AdminFiltered) { $label = "$($u.Name) (admin, filtered remotely)" }
        elseif ($tok.Sids.Contains($SID_ADMINS)) { $label = "$($u.Name) (admin)" }
        foreach ($s in $MatrixShares) {
            $e = Get-Effective -ShareName $s.Name -Sids $tok.Sids
            $rows.Add([pscustomobject][ordered]@{ User = $label; Share = $s.Name; ShareLevel = $LevelNames[$e.Share]; NtfsLevel = $LevelNames[$e.Ntfs]; Effective = $LevelNames[$e.Effective]; EffectiveLevel = $e.Effective })
        }
    }
    $Data.AccessMatrix = $rows.ToArray()
}

Invoke-Section 'Subfolders' 'Sub-folders with explicit or blocked permissions' {
    $Data.Subfolders = @(); $Data.SubfolderStats = [pscustomobject]@{ Scanned = 0; Truncated = $false; Depth = $Depth; Skipped = [bool]($Quick -or $Depth -lt 1) }
    if ($Quick -or $Depth -lt 1) { Write-Log '  skipped (-Quick or -Depth 0)'; return }
    $rows = New-Object System.Collections.Generic.List[object]
    $count = 0
    foreach ($s in @($DataShares | Where-Object { $_.PathExists })) {
        if ($count -ge $MaxFolders) { $Data.SubfolderStats.Truncated = $true; break }
        $root = $s.Path.TrimEnd('\')
        $dirs = @(Get-ChildItem -LiteralPath $s.Path -Directory -Recurse -Depth ($Depth - 1) -Force -ErrorAction SilentlyContinue | Select-Object -First ($MaxFolders - $count + 1))
        if ($dirs.Count -gt ($MaxFolders - $count)) { $Data.SubfolderStats.Truncated = $true; $dirs = @($dirs | Select-Object -First ($MaxFolders - $count)) }
        foreach ($d in $dirs) {
            $count++
            $acl = $null
            try { $acl = Get-Acl -LiteralPath $d.FullName -ErrorAction Stop } catch { $acl = $null }
            if (-not $acl) { continue }
            $aces = @($acl.Access | Where-Object { $_ } | ForEach-Object { ConvertTo-AceRow $_ })
            $explicit = @($aces | Where-Object { -not $_.IsInherited })
            if ($acl.AreAccessRulesProtected -or $explicit.Count) {
                $broad = @($explicit | Where-Object { $_.Type -eq 'Allow' -and $_.Level -ge 2 -and ($_.SID -in ($AnyUserSids + $WorldSids)) })
                $rel = $d.FullName.Substring([Math]::Min($root.Length, $d.FullName.Length)).TrimStart('\')
                $rows.Add([pscustomobject][ordered]@{
                        Share = $s.Name; Path = $d.FullName; RelativeDepth = @($rel -split '\\').Count
                        InheritanceBlocked = [bool]$acl.AreAccessRulesProtected; ExplicitAces = $explicit.Count
                        Explicit = Join-Limited (@($explicit | ForEach-Object { '{0}:{1}{2}' -f (Get-SidLabel $_.SID $_.Identity), $LevelNames[$_.Level], $(if ($_.Type -eq 'Deny') { '(DENY)' } else { '' }) })) 8
                        BroadWrite = [bool]$broad.Count
                    })
            }
        }
    }
    $Data.SubfolderStats.Scanned = $count
    $Data.Subfolders = $rows.ToArray()
    Write-Log ('  {0} folder(s) scanned, {1} with explicit permissions' -f $count, $rows.Count)
}

Invoke-Section 'Sessions' 'Active SMB sessions and open files' {
    $Data.Sessions = @(Invoke-Safe { Get-SmbSession -ErrorAction Stop } 'Get-SmbSession' | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{ ClientComputerName = "$($_.ClientComputerName)"; ClientUserName = "$($_.ClientUserName)"; Dialect = "$($_.Dialect)"; NumOpens = $_.NumOpens; SecondsExists = $_.SecondsExists; SecondsIdle = $_.SecondsIdle }
        })
    $Data.OpenFiles = @(Invoke-Safe { Get-SmbOpenFile -ErrorAction Stop } 'Get-SmbOpenFile' | Where-Object { $_ } | ForEach-Object {
            [pscustomobject][ordered]@{ ClientComputerName = "$($_.ClientComputerName)"; ClientUserName = "$($_.ClientUserName)"; Path = "$($_.Path)"; ShareRelativePath = "$($_.ShareRelativePath)" }
        })
}

Invoke-Section 'Protection' 'Antivirus, ransomware protection, audit policy, power, backup' {
    $mp = Invoke-Safe { Get-MpComputerStatus -ErrorAction Stop } 'Get-MpComputerStatus'
    $mpp = Invoke-Safe { Get-MpPreference -ErrorAction Stop } 'Get-MpPreference'
    $sigAge = $null
    if ($mp -and $mp.AntivirusSignatureLastUpdated) { $sigAge = [Math]::Round(((Get-Date) - [datetime]$mp.AntivirusSignatureLastUpdated).TotalDays, 1) }
    $av = @()
    if ($Data.Host.IsClientOS) {
        $av = @(Invoke-Safe { Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop } 'SecurityCenter2 AntiVirusProduct' | Where-Object { $_ } | ForEach-Object { "$($_.displayName)" })
    }
    $cfaPaths = @(); if ($mpp) { $cfaPaths = @($mpp.ControlledFolderAccessProtectedFolders | Where-Object { $_ }) }
    $Data.Protection = [pscustomobject][ordered]@{
        DefenderServiceEnabled = $(if ($mp) { [bool]$mp.AMServiceEnabled } else { $null })
        RealTimeProtection     = $(if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null })
        SignatureAgeDays       = $sigAge
        AntivirusProducts      = ($av -join ', ')
        ControlledFolderAccess = $(if ($mpp) { switch ([int]$mpp.EnableControlledFolderAccess) { 0 { 'Disabled' } 1 { 'Enabled' } 2 { 'Audit' } 3 { 'Block disk modification' } 4 { 'Audit disk modification' } default { "$($mpp.EnableControlledFolderAccess)" } } } else { $null })
        CfaProtectedFolders    = ($cfaPaths -join '; ')
    }
    $Data.AuditPolicy = @(foreach ($k in $AuditSubcategories.Keys) {
            $st = Invoke-Safe { Get-AuditPolicyState $AuditSubcategories[$k] } "Audit policy $k"
            [pscustomobject][ordered]@{ Subcategory = $k; Success = $(if ($st) { $st.Success } else { $null }); Failure = $(if ($st) { $st.Failure } else { $null }); Raw = $(if ($st) { "$($st.Raw)" } else { '' }); Source = $(if ($st) { $st.Source } else { 'unavailable' }) }
        })
    $Data.Power = [pscustomobject][ordered]@{
        SleepAfterSecondsAC     = Invoke-Safe { Get-PowerSettingAc 'SUB_SLEEP' 'STANDBYIDLE' } 'powercfg STANDBYIDLE'
        HibernateAfterSecondsAC = Invoke-Safe { Get-PowerSettingAc 'SUB_SLEEP' 'HIBERNATEIDLE' } 'powercfg HIBERNATEIDLE'
    }
    $Data.BackupAgents = @(Invoke-Safe { Get-Service -ErrorAction Stop } 'Get-Service' | Where-Object { $_ -and ("$($_.Name)" -match $BackupAgentPattern -or "$($_.DisplayName)" -match $BackupAgentPattern) } | ForEach-Object {
            [pscustomobject][ordered]@{ Name = "$($_.Name)"; DisplayName = "$($_.DisplayName)"; Status = "$($_.Status)"; StartType = "$($_.StartType)" }
        })
}

#endregion

#region ---------------------------------------------------------------- analysis

Invoke-Section 'Analysis' 'Analysis and findings' {
    $h = $Data.Host
    $reg = $Data.SecurityRegistry
    $srv = $Data.SmbServer
    $cli = $Data.SmbClient
    $hasShares = [bool]$DataShares.Count
    $shareList = Join-Limited @($DataShares | ForEach-Object { $_.Name })

    # ---------------------------------------------------------------- network
    try {
        foreach ($p in @($Data.NetProfiles)) {
            if ($p.NetworkCategory -eq 'Public' -and $hasShares) {
                Add-Finding High 'Network' "Network '$($p.Name)' uses the Public profile" `
                    "This PC publishes $($DataShares.Count) share(s) ($shareList) but the interface '$($p.InterfaceAlias)' is on a Public network. On Public, File and Printer Sharing rules are normally blocked: either clients cannot connect, or the firewall was opened on the Public profile, exposing SMB on every untrusted network the PC joins." `
                    "If this is the trusted office LAN, set it to Private: Settings > Network & internet > adapter > Network profile type, or Set-NetConnectionProfile -InterfaceAlias '$($p.InterfaceAlias)' -NetworkCategory Private. Keep guest/untrusted networks Public." $p.InterfaceAlias
            }
        }
        $dhcp = @($Data.IPv4 | Where-Object { $_.PrefixOrigin -eq 'Dhcp' })
        if ($hasShares -and $dhcp.Count) {
            Add-Finding Low 'Network' 'Share host uses a DHCP address' `
                ('IPv4 address(es) obtained by DHCP: {0}. If the address changes, mapped drives by IP, scanner profiles and firewall rules break.' -f (Join-Limited @($dhcp | ForEach-Object { "$($_.IPAddress) ($($_.InterfaceAlias))" }))) `
                'Create a DHCP reservation on the router/firewall (or a static IP) and map drives by host name.'
        }
        if ("$($Data.Llmnr)" -ne '0') {
            Add-Finding Low 'Network' 'LLMNR is not disabled' `
                'Link-Local Multicast Name Resolution answers name queries on the LAN and is a classic vector for credential capture (Responder-type attacks), which is especially damaging in a workgroup where NTLM is the only protocol.' `
                'Disable it: Local Group Policy > Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled (registry EnableMulticast = 0).'
        }
        $nb = @($Data.NetBios | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        if ($nb.Count) {
            Add-Finding Low 'Network' 'NetBIOS over TCP/IP is enabled' `
                ('Adapters: {0}. NBT-NS poisoning allows the same credential-capture attacks as LLMNR.' -f (Join-Limited @($nb | ForEach-Object { $_.Adapter }))) `
                'If no legacy device needs it, disable NetBIOS over TCP/IP on the adapter (IPv4 > Advanced > WINS) or via the DHCP server option. Test old scanners/NAS first.'
        }
    } catch { Add-CollectionError ('Network rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- SMB protocol
    try {
        if (($srv -and $srv.EnableSMB1Protocol -eq $true) -or $Data.Smb1Feature -eq 'Enabled') {
            Add-Finding Critical 'SMB' 'SMBv1 is enabled' `
                "SMB1 server protocol: $(Format-Value $srv.EnableSMB1Protocol); SMB1Protocol optional feature: $(Format-Value $Data.Smb1Feature). SMBv1 is obsolete, has no modern protection and was the vector of WannaCry/NotPetya." `
                'Disable and remove it: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. If an old scanner/NAS needs it, upgrade its firmware or switch it to scan-to-email.'
        }
        if ($srv -and $srv.PSObject.Properties['RequireSecuritySignature'] -and $srv.RequireSecuritySignature -ne $true) {
            Add-Finding High 'SMB' 'SMB signing is not required by the server' `
                'Without mandatory signing, SMB sessions can be relayed or tampered with (NTLM relay). Windows 11 24H2 requires signing by default: if it is off, it was probably disabled for an old device.' `
                'Set-SmbServerConfiguration -RequireSecuritySignature $true. Fix the incompatible device rather than weakening the whole server.'
        }
        if ($srv -and $srv.PSObject.Properties['EnableAuthRateLimiter'] -and $srv.EnableAuthRateLimiter -eq $false) {
            Add-Finding Low 'SMB' 'SMB authentication rate limiter is disabled' `
                'The rate limiter adds a delay after each failed NTLM authentication and slows down password brute-force over SMB.' `
                'Set-SmbServerConfiguration -EnableAuthRateLimiter $true'
        }
        if ($hasShares -and -not ($srv -and $srv.EncryptData -eq $true)) {
            $unenc = @($MatrixShares | Where-Object { $_.EncryptData -ne $true })
            if ($unenc.Count) {
                Add-Finding Medium 'SMB' 'SMB encryption is not enabled' `
                    ('Share(s) without encryption: {0}. Data travels in clear text on the LAN (signing protects integrity, not confidentiality).' -f (Join-Limited @($unenc | ForEach-Object { $_.Name }))) `
                    'Set-SmbShare -Name <share> -EncryptData $true (all Windows 8+ clients support it). Keep an unencrypted dedicated share only for devices that cannot do SMB 3 (scanners).'
            }
        }
        $insecureGuest = ($cli -and $cli.EnableInsecureGuestLogons -eq $true) -or "$($reg.AllowInsecureGuestAuth)" -eq '1' -or "$($reg.AllowInsecureGuestAuthPolicy)" -eq '1'
        if ($insecureGuest) {
            Add-Finding High 'SMB' 'Insecure guest logons are allowed (SMB client)' `
                'This PC accepts to connect to SMB shares as an unauthenticated guest. A rogue server on the LAN can then serve malicious content without any authentication, and signing cannot be used.' `
                'Set-SmbClientConfiguration -EnableInsecureGuestLogons $false (and remove the AllowInsecureGuestAuth policy). Give the NAS/device real accounts.'
        }
        if ($cli -and $cli.PSObject.Properties['RequireSecuritySignature'] -and $cli.RequireSecuritySignature -ne $true) {
            Add-Finding Low 'SMB' 'SMB signing is not required by the client' `
                'Outbound SMB connections from this PC may be unsigned.' 'Set-SmbClientConfiguration -RequireSecuritySignature $true (default on Windows 11 24H2).'
        }
        $lm = $reg.LmCompatibilityLevel
        $lmEff = $(if ($null -eq $lm) { 3 } else { [int]$lm })
        if ($lmEff -lt 3) {
            Add-Finding High 'Authentication' "LAN Manager authentication level is $lmEff (LM/NTLMv1 sent)" `
                'LM and NTLMv1 responses can be cracked or relayed trivially.' 'Set "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (LmCompatibilityLevel = 5) after checking old devices.'
        } elseif ($lmEff -lt 5) {
            Add-Finding Medium 'Authentication' ("LAN Manager authentication level is {0}{1}: LM/NTLMv1 still accepted" -f $lmEff, $(if ($null -eq $lm) { ' (default)' } else { '' })) `
                'Below level 5 this PC, acting as a server, still accepts LM and NTLMv1 responses from clients. In a workgroup all SMB authentication is NTLM, so this matters.' `
                'Set LmCompatibilityLevel = 5 (secpol.msc > Local Policies > Security Options > Network security: LAN Manager authentication level).'
        }
        if ("$($reg.NoLmHash)" -eq '0') {
            Add-Finding Medium 'Authentication' 'LM hashes may be stored' 'NoLmHash = 0: LM password hashes are stored at next password change.' 'Set "Network security: Do not store LAN Manager hash value on next password change" = Enabled.'
        }
        if ("$($reg.EveryoneIncludesAnonymous)" -eq '1') {
            Add-Finding High 'Authentication' 'Anonymous users are members of Everyone' 'EveryoneIncludesAnonymous = 1: every permission granted to Everyone also applies to anonymous (null session) connections.' 'Set "Network access: Let Everyone permissions apply to anonymous users" = Disabled.'
        }
        if ("$($reg.RestrictNullSessAccess)" -eq '0' -or ($reg.NullSessionShares -and $reg.NullSessionShares.Trim())) {
            Add-Finding High 'Authentication' 'Null-session (anonymous) access to shares is allowed' ("RestrictNullSessAccess = $($reg.RestrictNullSessAccess); NullSessionShares = '$($reg.NullSessionShares)'.") 'Set "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled and empty "Shares that can be accessed anonymously".'
        }
        if ("$($reg.RestrictAnonymousSAM)" -eq '0') {
            Add-Finding Medium 'Authentication' 'Anonymous enumeration of SAM accounts is allowed' 'RestrictAnonymousSAM = 0: anyone on the LAN can list local accounts, which helps password attacks.' 'Set "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled.'
        }
        if ("$($reg.ForceGuest)" -eq '1') {
            Add-Finding High 'Authentication' 'Network logons are mapped to Guest (Guest-only sharing model)' 'ForceGuest = 1: all network users authenticate as Guest, so permissions cannot distinguish people and nothing is traceable.' 'Set "Network access: Sharing and security model for local accounts" = Classic, and grant access to real accounts/groups.'
        }
        if ("$($reg.LimitBlankPasswordUse)" -eq '0') {
            Add-Finding High 'Authentication' 'Accounts with a blank password can be used over the network' 'LimitBlankPasswordUse = 0.' 'Set "Accounts: Limit local account use of blank passwords to console logon only" = Enabled, and give every account a password.'
        }
        if ("$($reg.LocalAccountTokenFilterPolicy)" -eq '1') {
            Add-Finding Medium 'Authentication' 'Remote UAC filtering is disabled (LocalAccountTokenFilterPolicy = 1)' 'Any local administrator account gets full admin rights over the network (C$, ADMIN$, remote services). With identical local admin passwords on several PCs this enables lateral movement (pass-the-hash).' 'Remove LocalAccountTokenFilterPolicy (or set 0) unless a management tool really requires it; use unique local admin passwords (Windows LAPS).'
        }
        if ($srv -and ($srv.AutoShareWorkstation -eq $true -or $srv.AutoShareServer -eq $true)) {
            Add-Finding Info 'SMB' 'Administrative shares (C$, ADMIN$) are enabled' 'Default behaviour, used by management and backup tools. Reachable only by administrators.' 'Keep few administrator accounts, with unique strong passwords, and keep remote UAC filtering enabled.'
        }
    } catch { Add-CollectionError ('SMB rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- firewall
    try {
        foreach ($fp in @($Data.FirewallProfiles | Where-Object { -not $_.Enabled })) {
            $active = @($Data.NetProfiles | Where-Object { $_.NetworkCategory -eq $fp.Profile -or ($fp.Profile -eq 'Domain' -and $_.NetworkCategory -eq 'DomainAuthenticated') }).Count
            Add-Finding $(if ($active) { 'High' } else { 'Medium' }) 'Firewall' "Windows Firewall is disabled on the $($fp.Profile) profile" `
                $(if ($active) { 'This profile is currently active: every listening service, including SMB, is reachable.' } else { 'The profile is not active now but will be as soon as the PC joins such a network.' }) `
                "Set-NetFirewallProfile -Profile $($fp.Profile) -Enabled True"
        }
        $smbRules = @($Data.FirewallRules | Where-Object { $_.Enabled -and $_.Action -eq 'Allow' -and ($_.LocalPort -match '(^|, )(445|139)(,|$)' -or $_.Name -match 'SMB|NB-Session') })
        $pub = @($smbRules | Where-Object { $_.Profile -match 'Public|Any' })
        if ($pub.Count) {
            Add-Finding High 'Firewall' 'SMB is allowed inbound on the Public profile' `
                ('Rule(s): {0}. The PC accepts SMB connections even on hotel/cafe/guest networks.' -f (Join-Limited @($pub | ForEach-Object { "$($_.DisplayName) [$($_.Profile)]" }) 6)) `
                'Disable these rules on the Public profile and keep File and Printer Sharing enabled on Private only.'
        }
        $any = @($smbRules | Where-Object { $_.RemoteAddress -match '^(Any|\*)?$' })
        if ($any.Count) {
            Add-Finding Medium 'Firewall' 'SMB inbound rules accept any source address' `
                ('Rule(s): {0}.' -f (Join-Limited @($any | ForEach-Object { $_.DisplayName }) 6)) `
                'Restrict the remote address to the office subnet: Set-NetFirewallRule -Name <rule> -RemoteAddress LocalSubnet (or 192.168.x.0/24).'
        }
        if ($hasShares -and $Data.FirewallRules -and -not $smbRules.Count) {
            Add-Finding Info 'Firewall' 'No enabled inbound SMB rule found' 'Shares exist but no enabled File and Printer Sharing / port 445 rule was found: clients may not be able to connect (or a third-party firewall is in use).' 'Enable "File and Printer Sharing (SMB-In)" on the Private profile only, restricted to the LAN.'
        }
    } catch { Add-CollectionError ('Firewall rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- shares
    try {
        if ($hasShares -and $h.IsClientOS) {
            Add-Finding Info 'Shares' 'Windows client edition: 20 concurrent inbound SMB connections maximum' `
                "This PC runs $($h.OS). Client editions accept at most 20 simultaneous inbound connections (PCs, laptops, scanners, NAS...). Beyond that, connections fail randomly." `
                'Fine for a handful of users. Beyond ~10-15 devices, move the data to a NAS, a Windows Server or SharePoint/OneDrive.'
        }
        $guestUser = @($Data.Users | Where-Object { $_.SID -match '-501$' -and $_.Enabled }) | Select-Object -First 1
        $anyUserSet = New-SidSet $AnyUserSids
        $guestSet = $null
        if ($guestUser) { $guestSet = New-SidSet @($guestUser.SID, $SID_EVERYONE, $SID_GUESTS, $SID_NETWORK) }

        foreach ($s in $DataShares) {
            $t = $s.Name
            if ($s.PathExists -eq $false) {
                Add-Finding High 'Shares' "Share '$t' points to a missing folder" "Path $($s.Path) does not exist (removed disk, renamed folder?)." 'Remove the share or fix its path.' $t
                continue
            }
            if (Test-DriveRoot $s.Path) {
                Add-Finding High 'Shares' "Share '$t' exposes an entire volume ($($s.Path))" 'Sharing a drive root exposes everything stored on it and inherits the very permissive default volume ACL.' 'Create a dedicated folder (e.g. D:\Shares\<Department>) and share that instead.' $t
            } elseif ($s.Path -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData)(\\|$)') {
                Add-Finding High 'Shares' "Share '$t' exposes a system folder ($($s.Path))" 'System folders must never be shared.' 'Remove the share.' $t
            } elseif ($s.Path -match '^[A-Za-z]:\\Users(\\|$)') {
                Add-Finding High 'Shares' "Share '$t' is inside user profiles ($($s.Path))" 'Profiles contain browser data, tokens and personal files; they are not designed to be shared and break backups/migrations.' 'Move shared data to a dedicated data folder (preferably on a separate volume).' $t
            }
            $drive = Get-DriveOf $s.Path
            $vol = $Data.Volumes | Where-Object { $_.Drive -eq $drive } | Select-Object -First 1

            $acesRoot = @($Data.NtfsRoot | Where-Object { $_.Share -eq $t })
            $parent = Get-ParentPath $s.Path
            if ($s.InheritanceBlocked -eq $false -and $parent -and (Test-DriveRoot $parent)) {
                $inh = @($acesRoot | Where-Object { $_.IsInherited -and $_.Type -eq 'Allow' -and $_.SID -in $AnyUserSids -and $_.Level -ge 1 })
                Add-Finding Medium 'Permissions' "Share '$t' inherits the permissions of the volume root ($parent)" `
                    ('The default ACL of a data volume root grants Authenticated Users "Modify" and Users "Read": every local account (including ones created later for any purpose) inherits it. Inherited broad entries found: {0}.' -f $(if ($inh.Count) { Join-Limited @($inh | ForEach-Object { '{0}:{1}' -f (Get-SidLabel $_.SID $_.Identity), $LevelNames[$_.Level] }) } else { 'none' })) `
                    "Disable inheritance on $($s.Path) (icacls `"$($s.Path)`" /inheritance:r) and grant explicit rights to SYSTEM, Administrators and the department groups only." $t
            }
            if ($acesRoot.Count) {
                $eAny = Get-Effective -ShareName $t -Sids $anyUserSet
                if ($eAny.Effective -ge 2) {
                    Add-Finding Medium 'Permissions' "Any local account can modify share '$t'" `
                        ('Share level for Everyone/Authenticated Users: {0}; NTFS for Everyone/Authenticated Users/Users: {1}. Any account on this PC (including service or scanner accounts) can create, change and delete files: one compromised account or infected client encrypts the whole share.' -f $LevelNames[$eAny.Share], $LevelNames[$eAny.Ntfs]) `
                        'Grant NTFS rights to dedicated local groups (GRP_<Dept>_RW / _RO) instead of Everyone/Users/Authenticated Users, even for a "common" share.' $t
                } elseif ($eAny.Effective -eq 1) {
                    Add-Finding Low 'Permissions' "Any local account can read share '$t'" ('Effective read access for Everyone/Authenticated Users/Users (share: {0}, NTFS: {1}).' -f $LevelNames[$eAny.Share], $LevelNames[$eAny.Ntfs]) 'Confirm that this is intended; otherwise use group-based permissions.' $t
                }
                if ($guestSet) {
                    $eG = Get-Effective -ShareName $t -Sids $guestSet
                    if ($eG.Effective -ge 1) {
                        Add-Finding $(if ($eG.Effective -ge 2) { 'Critical' } else { 'High' }) 'Permissions' "Share '$t' is reachable by the Guest account" `
                            ('The Guest account is enabled and gets effective {0} access (share: {1}, NTFS: {2}): anyone on the network can access the data without a password.' -f $LevelNames[$eG.Effective], $LevelNames[$eG.Share], $LevelNames[$eG.Ntfs]) `
                            'Disable the Guest account and remove Everyone/Guests permissions; give each person a named account.' $t
                    }
                }
                $fullOthers = @($acesRoot | Where-Object { $_.Type -eq 'Allow' -and $_.Level -eq 3 -and $_.SID -and $_.SID -notin $TrustedFullSids })
                if ($fullOthers.Count) {
                    Add-Finding Medium 'Permissions' "Non-admin identities have Full Control on share '$t'" `
                        ('Identities: {0}. Full Control allows changing permissions and taking ownership, i.e. undoing the access model.' -f (Join-Limited @($fullOthers | ForEach-Object { Get-SidLabel $_.SID $_.Identity } | Select-Object -Unique))) `
                        'Grant Modify (not Full Control) to user groups; keep Full Control for SYSTEM and Administrators.' $t
                }
                $userSids = @($Data.Users | ForEach-Object { $_.SID })
                $direct = @($acesRoot | Where-Object { -not $_.IsInherited -and $_.SID -in $userSids })
                if ($direct.Count) {
                    Add-Finding Low 'Permissions' "Permissions granted to individual users on share '$t'" `
                        ('User(s): {0}. Per-user entries become unmanageable when people join, leave or change roles.' -f (Join-Limited @($direct | ForEach-Object { Get-SidLabel $_.SID $_.Identity } | Select-Object -Unique))) `
                        'Put users in local groups and grant permissions to groups only.' $t
                }
                $orphans = @($acesRoot | Where-Object { $_.Identity -match '^S-1-5-21-' })
                if ($orphans.Count) {
                    Add-Finding Low 'Permissions' "Orphaned SIDs in the ACL of share '$t'" ('Unresolvable SID(s): {0} (deleted accounts).' -f (Join-Limited @($orphans | ForEach-Object { $_.Identity } | Select-Object -Unique))) 'Remove the entries of deleted accounts.' $t
                }
                $denies = @($acesRoot | Where-Object { $_.Type -eq 'Deny' })
                if ($denies.Count) {
                    Add-Finding Info 'Permissions' "Deny entries on share '$t'" ('Deny ACE(s) for: {0}. Deny entries make effective rights hard to predict.' -f (Join-Limited @($denies | ForEach-Object { Get-SidLabel $_.SID $_.Identity } | Select-Object -Unique))) 'Prefer not granting rather than denying.' $t
                }
            }
            $shareWorld = @($Data.ShareAccess | Where-Object { $_.Share -eq $t -and $_.AccessControlType -eq 'Allow' -and $_.SID -in $WorldSids -and $_.AccessRight -in @('Full', 'Change') })
            if ($shareWorld.Count) {
                Add-Finding Low 'Permissions' "Share-level permission grants Everyone/Guests '$($shareWorld[0].AccessRight)' on '$t'" `
                    'Security then depends only on NTFS permissions; if the Guest account or anonymous access is ever enabled, the share becomes open.' `
                    "Share permissions: Administrators = Full, Authenticated Users = Change; do the fine-grained control in NTFS. (Grant-SmbShareAccess / Revoke-SmbShareAccess)" $t
            }
            if ($s.ABE -and $s.ABE -ne 'AccessBased') {
                Add-Finding Low 'Shares' "Access-Based Enumeration is off on '$t'" 'Users see folders they cannot open, which reveals the structure and generates support calls.' "Set-SmbShare -Name '$t' -FolderEnumerationMode AccessBased" $t
            }
            if ($s.CachingMode -and $s.CachingMode -notin @('None', 'Manual')) {
                Add-Finding Info 'Shares' "Offline files caching '$($s.CachingMode)' on '$t'" 'Automatic caching copies share content on laptops and frequently creates sync conflicts.' "Set-SmbShare -Name '$t' -CachingMode None (or Manual) unless laptops really need offline access." $t
            }
            if ($vol) {
                if ($vol.FileSystem -and $vol.FileSystem -notin @('NTFS', 'ReFS')) {
                    Add-Finding High 'Volumes' "Share '$t' is on a $($vol.FileSystem) volume" 'FAT/exFAT have no NTFS permissions: anyone with share access has full access.' 'Move the data to an NTFS volume.' $t
                }
            }
            if ($Data.SubfolderStats -and -not $Data.SubfolderStats.Skipped) {
                $sub = @($Data.Subfolders | Where-Object { $_.Share -eq $t })
                $subBroad = @($sub | Where-Object { $_.BroadWrite })
                if ($subBroad.Count) {
                    Add-Finding Medium 'Permissions' "Sub-folders of '$t' explicitly grant write access to everyone" ('{0} folder(s), e.g. {1}.' -f $subBroad.Count, (Join-Limited @($subBroad | ForEach-Object { $_.Path }) 3)) 'Remove the Everyone/Users/Authenticated Users entries and use groups.' $t
                }
                if ($sub.Count -gt 10) {
                    Add-Finding Low 'Permissions' "Permission sprawl in '$t'" ('{0} sub-folders (depth <= {1}) have explicit permissions or blocked inheritance.' -f $sub.Count, $Depth) 'Define permissions on the first 1-2 levels only and let inheritance do the rest; document exceptions.' $t
                }
            }
            if ($s.SaclEntries -eq 0 -and @($Data.AuditPolicy | Where-Object { $_.Subcategory -eq 'File System' -and $_.Success -eq $true }).Count) {
                Add-Finding Medium 'Audit' "No audit entries (SACL) on share '$t'" 'File System auditing is enabled in the policy but nothing is audited on this folder.' "Folder properties > Security > Advanced > Auditing: Everyone, Success, 'Delete', 'Delete subfolders and files', 'Write data' (applies to this folder, subfolders and files)." $t
            }
        }
        foreach ($v in @($Data.Volumes | Where-Object { $_.HostsShares })) {
            if ($v.BitLocker -and $v.BitLocker -ne 'On') {
                $onVol = Join-Limited @($DataShares | Where-Object { (Get-DriveOf $_.Path) -eq $v.Drive } | ForEach-Object { $_.Name })
                Add-Finding Medium 'Volumes' "Volume $($v.Drive) hosting shares is not protected by BitLocker" "Share(s) on this volume: $onVol. A stolen PC or disk exposes all shared data." "Enable BitLocker on $($v.Drive) (and on the system drive) and store the recovery key outside the PC." $v.Drive
            }
            if ($null -ne $v.FreePct -and $v.FreePct -lt 10) {
                Add-Finding $(if ($v.FreePct -lt 5) { 'High' } else { 'Medium' }) 'Volumes' "Low free space on $($v.Drive) ($($v.FreePct)%)" "$($v.FreeGB) GB free of $($v.SizeGB) GB on a volume that hosts shares." 'Clean up or extend storage before users get write errors (and before shadow copies are purged).' $v.Drive
            }
            if ($v.ShadowCopies -eq 0) {
                Add-Finding Low 'Volumes' "No shadow copies on $($v.Drive)" '"Previous versions" cannot be used to restore a file deleted or overwritten by mistake.' "Enable System Protection on $($v.Drive) as a convenience layer. It is NOT a backup: ransomware deletes shadow copies." $v.Drive
            }
        }
        $sysDrive = "$env:SystemDrive".ToUpper(); if (-not $sysDrive) { $sysDrive = 'C:' }
        $onSys = @($DataShares | Where-Object { (Get-DriveOf $_.Path) -eq $sysDrive -and -not (Test-DriveRoot $_.Path) -and $_.Path -notmatch '^[A-Za-z]:\\Users(\\|$)' })
        if ($onSys.Count) {
            Add-Finding Low 'Shares' 'Shared data is stored on the system drive' ('Share(s): {0}. A full data folder can fill the system drive; reinstalling Windows puts the data at risk.' -f (Join-Limited @($onSys | ForEach-Object { $_.Name }))) 'Prefer a dedicated data volume/partition (e.g. D:\Shares).'
        }
    } catch { Add-CollectionError ('Share rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- sessions
    try {
        $clients = @($Data.Sessions | ForEach-Object { $_.ClientComputerName } | Where-Object { $_ } | Select-Object -Unique)
        if ($h.IsClientOS -and $clients.Count -ge 15) {
            Add-Finding High 'Sessions' "$($clients.Count) distinct clients connected (limit 20 on Windows client)" 'The PC is close to the 20 concurrent connections limit of Windows client editions.' 'Move the shares to a NAS / Windows Server / SharePoint before connections start failing.'
        }
        $old = @($Data.Sessions | Where-Object { $_.Dialect -and $_.Dialect -match '^(1|2)\.' })
        if ($old.Count) {
            Add-Finding Medium 'Sessions' 'Clients connected with an old SMB dialect (< 3.0)' ('Session(s): {0}. These clients cannot use SMB encryption.' -f (Join-Limited @($old | ForEach-Object { "$($_.ClientComputerName) ($($_.ClientUserName), SMB $($_.Dialect))" }) 6)) 'Identify the devices (often scanners/NAS/old PCs), update them or isolate them on a dedicated share.'
        }
        $guestS = @($Data.Sessions | Where-Object { -not $_.ClientUserName -or $_.ClientUserName -match '(\\|^)(Guest|Invit|Gast|Ospite|ANONYMOUS)' })
        if ($guestS.Count) {
            Add-Finding High 'Sessions' 'Guest or anonymous SMB sessions are active' ('Session(s): {0}.' -f (Join-Limited @($guestS | ForEach-Object { "$($_.ClientComputerName) ($($_.ClientUserName))" }) 6)) 'Find which device connects without credentials and give it a dedicated account; disable guest access.'
        }
    } catch { Add-CollectionError ('Session rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- accounts
    try {
        $enabled = @($Data.Users | Where-Object { $_.Enabled })
        $guest = @($enabled | Where-Object { $_.SID -match '-501$' })
        if ($guest.Count) {
            Add-Finding High 'Accounts' "The Guest account is enabled ('$($guest[0].Name)')" 'Anonymous users can authenticate as Guest and reach everything granted to Everyone/Guests.' "Disable-LocalUser -Name '$($guest[0].Name)'. Never turn off password protected sharing."
        }
        $noPwd = @($enabled | Where-Object { -not $_.PasswordRequired -and $_.SID -notmatch '-501$' })
        if ($noPwd.Count) {
            Add-Finding $(if ("$($reg.LimitBlankPasswordUse)" -eq '0') { 'Critical' } else { 'High' }) 'Accounts' 'Enabled accounts are allowed to have no password' `
                ('Account(s): {0}. (Over the network, blank passwords are refused only while "Limit local account use of blank passwords" is enabled.)' -f (Join-Limited @($noPwd | ForEach-Object { $_.Name }))) `
                'Set-LocalUser -Name <user> -PasswordRequired $true and set a strong password.'
        }
        $admins = @($Data.GroupMembers | Where-Object { $_.GroupSID -eq $SID_ADMINS })
        $adminUsers = @($enabled | Where-Object { $_.SID -in @($admins | ForEach-Object { $_.SID }) })
        $builtin = @($enabled | Where-Object { $_.SID -match '-500$' })
        if ($builtin.Count) {
            Add-Finding Medium 'Accounts' "The built-in Administrator account is enabled ('$($builtin[0].Name)')" 'Its name/SID is predictable, it is not subject to remote UAC filtering by default and is the first target of password attacks.' 'Disable it and use a named admin account; if it must stay, use a long unique password (Windows LAPS).'
        }
        if ($adminUsers.Count -gt 3) {
            Add-Finding Low 'Accounts' "$($adminUsers.Count) enabled local administrators" ('Administrators: {0}.' -f (Join-Limited @($adminUsers | ForEach-Object { $_.Name }))) 'Keep 1-2 admin accounts; daily users must be standard users.'
        }
        $cut = (Get-Date).AddDays(-90)
        $stale = @($enabled | Where-Object { $_.SID -notmatch '-50[0-3]$' -and (($_.LastLogon -and [datetime]$_.LastLogon -lt $cut) -or (-not $_.LastLogon -and $_.PasswordLastSet -and [datetime]$_.PasswordLastSet -lt $cut)) })
        if ($stale.Count) {
            Add-Finding Low 'Accounts' 'Enabled accounts not used for 90+ days' ('Account(s): {0} (based on the last logon recorded in the local SAM).' -f (Join-Limited @($stale | ForEach-Object { $_.Name }))) 'Disable accounts of people who left; review service/scanner accounts.'
        }
        $generic = @($enabled | Where-Object { $_.Name -match '^(user|users|utente|utenti|ufficio|office|bureau|accueil|reception|compta|share|partage|test|temp|demo|admin|administrateur|amministratore|comptabilite|segreteria|secretariat)\d*$' })
        if ($generic.Count) {
            Add-Finding Low 'Accounts' 'Generic / shared account names' ('Account(s): {0}. Shared accounts make actions untraceable and passwords are never changed when someone leaves.' -f (Join-Limited @($generic | ForEach-Object { $_.Name }))) 'One named account per person; dedicated, restricted accounts for devices (e.g. svc_scan).'
        }
        $pol = $Data.Policy
        if ($pol) {
            if ($null -ne $pol.LockoutBadCount -and $pol.LockoutBadCount -eq 0) {
                Add-Finding Medium 'Accounts' 'No account lockout policy' 'Passwords of local accounts can be brute-forced over SMB without limit.' 'secpol.msc > Account Policies > Account Lockout Policy: threshold 10 attempts, duration/reset 15 minutes.'
            }
            if ($null -ne $pol.MinimumPasswordLength -and $pol.MinimumPasswordLength -lt 12) {
                Add-Finding $(if ($pol.MinimumPasswordLength -lt 8) { 'Medium' } else { 'Low' }) 'Accounts' "Minimum password length is $($pol.MinimumPasswordLength)" 'Short passwords are cracked quickly from captured NTLM exchanges.' 'Set a minimum length of 12-14 characters (secpol.msc > Account Policies > Password Policy) and favour passphrases.'
            }
            $nonAdminUsers = @($enabled | Where-Object { $_.SID -notin @($admins | ForEach-Object { $_.SID }) -and $_.SID -notmatch '-50[0-3]$' })
            if ($hasShares -and $nonAdminUsers.Count) {
                $denied = @("$($pol.SeDenyInteractiveLogonRight)" -split ',\s*' | Where-Object { $_ })
                $notDenied = @($nonAdminUsers | Where-Object { $u = $_; -not ($denied -contains $u.SID -or $denied -contains $u.Name -or @($Data.GroupMembers | Where-Object { $_.SID -eq $u.SID -and ($denied -contains $_.GroupSID -or $denied -contains $_.Group) }).Count) })
                if ($notDenied.Count) {
                    Add-Finding Info 'Accounts' 'Share accounts can also log on locally' ('{0} non-admin account(s) can open a session on this PC: {1}.' -f $notDenied.Count, (Join-Limited @($notDenied | ForEach-Object { $_.Name }))) 'If this PC is a dedicated file server, put share-only accounts in a group and add it to "Deny log on locally" and "Deny log on through Remote Desktop Services" (secpol.msc).'
                }
            }
        }
    } catch { Add-CollectionError ('Account rules: {0}' -f $_.Exception.Message) }

    # ---------------------------------------------------------------- protection
    try {
        $pr = $Data.Protection
        if ($pr) {
            if ($pr.RealTimeProtection -eq $false -and -not ($pr.AntivirusProducts -match '\S' -and $pr.AntivirusProducts -notmatch '^(Windows Defender|Microsoft Defender Antivirus)$')) {
                Add-Finding High 'Protection' 'Real-time antivirus protection is off' "Defender real-time protection is disabled and no other antivirus was detected ($($pr.AntivirusProducts))." 'Enable Defender real-time protection or check the third-party antivirus.'
            }
            if ($null -ne $pr.SignatureAgeDays -and $pr.SignatureAgeDays -gt 7 -and $pr.RealTimeProtection) {
                Add-Finding Medium 'Protection' "Antivirus signatures are $($pr.SignatureAgeDays) days old" 'Outdated signatures miss recent threats.' 'Check Windows Update / Defender updates (Update-MpSignature).'
            }
            if ($hasShares -and $pr.ControlledFolderAccess -eq 'Disabled') {
                Add-Finding Low 'Protection' 'Controlled Folder Access (anti-ransomware) is disabled' 'CFA blocks untrusted processes from modifying protected folders on this PC (it does not protect against encryption performed by a remote client through SMB).' 'Test in Audit mode first, then enable it and add the share folders to the protected folders.'
            }
        }
        $fsAudit = $Data.AuditPolicy | Where-Object { $_.Subcategory -eq 'File System' } | Select-Object -First 1
        if ($hasShares -and $fsAudit -and $fsAudit.Source -eq 'API' -and -not $fsAudit.Success) {
            Add-Finding Medium 'Audit' 'Deletions and changes on shared files are not audited' 'The "File System" audit subcategory is disabled: the day a folder disappears, nothing tells who deleted it.' 'auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable, add a SACL (Delete / Write data) on share roots and enlarge the Security log (e.g. 512 MB). Look for events 4663/4660.'
        }
        $logonAudit = $Data.AuditPolicy | Where-Object { $_.Subcategory -eq 'Logon' } | Select-Object -First 1
        if ($logonAudit -and $logonAudit.Source -eq 'API' -and -not $logonAudit.Failure) {
            Add-Finding Low 'Audit' 'Failed logons are not audited' 'Password guessing against the shares would go unnoticed (event 4625).' 'auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable'
        }
        if (@($Data.AuditPolicy | Where-Object { $_.Source -eq 'auditpol' }).Count) {
            Add-Finding Info 'Audit' 'Audit policy read through auditpol' ('Values (localized): {0}.' -f (Join-Limited @($Data.AuditPolicy | ForEach-Object { "$($_.Subcategory)=$($_.Raw)" }))) 'Check that File System (Success) and Logon (Failure) are enabled.'
        }
        $pw = $Data.Power
        if ($hasShares -and $pw -and $pw.SleepAfterSecondsAC -gt 0) {
            Add-Finding Medium 'Availability' ("PC goes to sleep after {0} minutes on AC power" -f [Math]::Round($pw.SleepAfterSecondsAC / 60)) 'When it sleeps, shares disappear for every user, and open files may be corrupted.' 'powercfg /change standby-timeout-ac 0 (and use an UPS).'
        }
        if ($hasShares -and $pw -and $pw.HibernateAfterSecondsAC -gt 0) {
            Add-Finding Low 'Availability' ("PC hibernates after {0} minutes on AC power" -f [Math]::Round($pw.HibernateAfterSecondsAC / 60)) 'Same effect as sleep for the shares.' 'powercfg /change hibernate-timeout-ac 0'
        }
        if ($null -ne $h.UptimeDays -and $h.UptimeDays -gt 35) {
            Add-Finding Low 'Availability' "No reboot for $($h.UptimeDays) days" 'Monthly security updates usually need a reboot: updates are probably pending.' 'Check Windows Update and schedule restarts outside office hours (active hours).'
        }
        if ($hasShares) {
            if (@($Data.BackupAgents).Count) {
                Add-Finding Info 'Backup' 'Backup agent(s) detected' ('Service(s): {0}. The script cannot verify what is backed up, where, or whether restores work.' -f (Join-Limited @($Data.BackupAgents | ForEach-Object { "$($_.DisplayName) [$($_.Status)]" }))) 'Check that the share folders are included, that one copy is offline/immutable (3-2-1) and test a restore every quarter.'
            } else {
                Add-Finding Medium 'Backup' 'No known backup agent detected' 'No backup software service was found on this PC. The shares may be backed up from elsewhere (e.g. pulled by a NAS) - verify it.' 'Implement 3-2-1 backups with an offline or immutable copy (NAS snapshots, rotated USB disks, cloud with object lock) and test restores.'
            }
        }
    } catch { Add-CollectionError ('Protection rules: {0}' -f $_.Exception.Message) }

    if (-not $hasShares) {
        Add-Finding Info 'Shares' 'No user data share on this PC' 'Only administrative/system shares were found.' 'Nothing to do if this PC is not supposed to share folders.'
    }
}

#endregion

#region ---------------------------------------------------------------- verdict and outputs

$Findings = @($script:Findings | Sort-Object @{ Expression = { $SeverityOrder[$_.Severity] } }, Category, Target, Title)
$Counts = [ordered]@{}
foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) { $Counts[$sev] = @($Findings | Where-Object { $_.Severity -eq $sev }).Count }
$Score = [Math]::Max(0, 100 - (25 * $Counts.Critical + 10 * $Counts.High + 4 * $Counts.Medium + 1 * $Counts.Low))
$Verdict = if ($Counts.Critical) { 'At risk' } elseif ($Counts.High) { 'Needs attention' } elseif ($Counts.Medium) { 'Acceptable, improvements recommended' } else { 'Good' }
$VerdictClass = switch ($Verdict) { 'At risk' { 'v-crit' } 'Needs attention' { 'v-high' } 'Good' { 'v-good' } default { 'v-med' } }
$CollectionErrors = @($script:Sections | ForEach-Object { $s = $_; $_.Errors | ForEach-Object { [pscustomobject]@{ Section = $s.Name; Error = $_ } } })

Write-Log ('Findings: Critical {0}, High {1}, Medium {2}, Low {3}, Info {4}' -f $Counts.Critical, $Counts.High, $Counts.Medium, $Counts.Low, $Counts.Info)
Write-Log "Score: $Score/100 - Verdict : $Verdict"

# CSV
Export-CsvSafe $Findings 'findings.csv'
Export-CsvSafe $Data.Shares 'shares.csv'
Export-CsvSafe $Data.ShareAccess 'share_permissions.csv'
Export-CsvSafe ($Data.NtfsRoot | Select-Object Share, Path, Identity, SID, Type, Rights, @{ n = 'Level'; e = { $LevelNames[$_.Level] } }, IsInherited, Inheritance, Propagation) 'ntfs_share_roots.csv'
Export-CsvSafe ($Data.AccessMatrix | Select-Object User, Share, ShareLevel, NtfsLevel, Effective) 'access_matrix.csv'
Export-CsvSafe $Data.Subfolders 'subfolders_explicit_permissions.csv'
Export-CsvSafe $Data.Sessions 'smb_sessions.csv'
Export-CsvSafe $Data.OpenFiles 'smb_open_files.csv'
Export-CsvSafe $Data.Users 'local_users.csv'
Export-CsvSafe $Data.GroupMembers 'local_group_members.csv'
Export-CsvSafe $Data.FirewallRules 'firewall_smb_rules.csv'
Export-CsvSafe $Data.Volumes 'volumes.csv'

# JSON
$json = [ordered]@{
    Meta     = [ordered]@{ Host = $HostName; Date = $StartTime.ToString('s'); ScriptVersion = $ScriptVersion; Elevated = $IsAdmin; Parameters = [ordered]@{ Depth = $Depth; MaxFolders = $MaxFolders; Quick = [bool]$Quick; IncludeAdminShares = [bool]$IncludeAdminShares } }
    Summary  = [ordered]@{ Verdict = $Verdict; Score = $Score; Counts = $Counts }
    Findings = $Findings
    Data     = $Data
    Sections = @($script:Sections | ForEach-Object { [ordered]@{ Id = $_.Id; Name = $_.Name; DurationMs = $_.DurationMs; Errors = @($_.Errors) } })
}
$json | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $script:Folder 'audit.json') -Encoding UTF8

# HTML
$enc = { param($v) [System.Net.WebUtility]::HtmlEncode((Format-Value $v)) }
$sb = New-Object System.Text.StringBuilder
$css = @'
:root{--fg:#1f2937;--muted:#6b7280;--bd:#e5e7eb;--bg:#f9fafb;--acc:#1d4ed8}
*{box-sizing:border-box}body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--fg);margin:0;background:#fff;font-size:14px;line-height:1.45}
header{background:#0f172a;color:#fff;padding:22px 32px}header h1{margin:0 0 4px;font-size:22px}header .sub{color:#cbd5e1;font-size:13px}
main{padding:20px 32px;max-width:1500px}h2{font-size:18px;border-bottom:2px solid var(--bd);padding-bottom:6px;margin-top:34px}h3{font-size:15px;margin:18px 0 8px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}.card{border:1px solid var(--bd);border-radius:8px;padding:12px 16px;min-width:130px;background:var(--bg)}
.card .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.card .v{font-size:22px;font-weight:600}
.verdict{font-size:18px;font-weight:700;padding:10px 16px;border-radius:8px;display:inline-block}.v-crit{background:#7f1d1d;color:#fff}.v-high{background:#dc2626;color:#fff}.v-med{background:#f59e0b;color:#111}.v-good{background:#16a34a;color:#fff}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:8px 0 14px;font-size:13px}th,td{border:1px solid var(--bd);padding:5px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9;position:sticky;top:0}
tr:nth-child(even) td{background:#fcfcfd}.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-Critical{background:#7f1d1d;color:#fff}.sev-High{background:#dc2626;color:#fff}.sev-Medium{background:#f59e0b;color:#111}.sev-Low{background:#3b82f6;color:#fff}.sev-Info{background:#e5e7eb;color:#374151}
.muted{color:var(--muted)}.kv td:first-child{width:280px;color:var(--muted)}details{margin:6px 0 10px}summary{cursor:pointer;font-weight:600}
.lvl-0{background:#f3f4f6!important;color:#9ca3af}.lvl-1{background:#dcfce7!important}.lvl-2{background:#fef3c7!important}.lvl-3{background:#fee2e2!important;font-weight:600}
.note{background:#eff6ff;border-left:4px solid var(--acc);padding:8px 12px;margin:10px 0;font-size:13px}nav a{margin-right:14px;color:var(--acc);text-decoration:none;font-size:13px}
@media print{header{background:#fff;color:#000}th{position:static}details{display:block}}
'@
[void]$sb.Append("<!DOCTYPE html><html lang=`"en`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>SMB share audit - $(& $enc $HostName)</title><style>$css</style></head><body>")
[void]$sb.Append("<header><h1>SMB share audit - $(& $enc $HostName)</h1><div class=`"sub`">$(& $enc $Data.Host.OS) $(& $enc $Data.Host.DisplayVersion) (build $(& $enc $Data.Host.Build)) &middot; $(if ($Data.Host.PartOfDomain) { 'Domain' } else { 'Workgroup' }): $(& $enc $Data.Host.DomainOrWorkgroup) &middot; $(& $enc $StartTime) &middot; script v$ScriptVersion$(if (-not $IsAdmin) { ' &middot; <b>NOT ELEVATED: partial results</b>' })</div></header><main>")
[void]$sb.Append('<nav><a href="#summary">Summary</a><a href="#findings">Findings</a><a href="#shares">Shares</a><a href="#matrix">Access matrix</a><a href="#acl">Permissions</a><a href="#sessions">Sessions</a><a href="#accounts">Accounts</a><a href="#smb">SMB &amp; auth</a><a href="#network">Network &amp; firewall</a><a href="#host">Volumes &amp; protection</a><a href="#log">Collection</a></nav>')

# Summary
$activeProfiles = Join-Limited @($Data.NetProfiles | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory)" })
[void]$sb.Append("<h2 id=`"summary`">Summary</h2><div class=`"verdict $VerdictClass`">$(& $enc $Verdict) &middot; score $Score/100</div><div class=`"cards`">")
foreach ($sev in $Counts.Keys) { [void]$sb.Append("<div class=`"card`"><div class=`"k`"><span class=`"sev sev-$sev`">$sev</span></div><div class=`"v`">$($Counts[$sev])</div></div>") }
[void]$sb.Append("<div class=`"card`"><div class=`"k`">Data shares</div><div class=`"v`">$($DataShares.Count)</div></div><div class=`"card`"><div class=`"k`">SMB sessions</div><div class=`"v`">$(@($Data.Sessions).Count)</div></div><div class=`"card`"><div class=`"k`">Enabled local users</div><div class=`"v`">$(@($Data.Users | Where-Object Enabled).Count)</div></div></div>")
$keyFacts = @(
    [pscustomobject]@{ Item = 'Network profile(s)'; Value = $activeProfiles }
    [pscustomobject]@{ Item = 'IPv4'; Value = (Join-Limited @($Data.IPv4 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength) ($($_.PrefixOrigin))" })) }
    [pscustomobject]@{ Item = 'SMB1 (server / feature)'; Value = ('{0} / {1}' -f (Format-Value $Data.SmbServer.EnableSMB1Protocol), (Format-Value $Data.Smb1Feature)) }
    [pscustomobject]@{ Item = 'SMB signing required (server / client)'; Value = ('{0} / {1}' -f (Format-Value $Data.SmbServer.RequireSecuritySignature), (Format-Value $Data.SmbClient.RequireSecuritySignature)) }
    [pscustomobject]@{ Item = 'SMB encryption (server-wide)'; Value = (Format-Value $Data.SmbServer.EncryptData) }
    [pscustomobject]@{ Item = 'Guest account enabled'; Value = (Format-Value ([bool]@($Data.Users | Where-Object { $_.SID -match '-501$' -and $_.Enabled }).Count)) }
    [pscustomobject]@{ Item = 'Firewall profiles enabled'; Value = (Join-Limited @($Data.FirewallProfiles | ForEach-Object { "$($_.Profile)=$(Format-Value $_.Enabled)" })) }
    [pscustomobject]@{ Item = 'Uptime (days)'; Value = $Data.Host.UptimeDays }
)
[void]$sb.Append('<table class="kv"><tbody>')
foreach ($k in $keyFacts) { [void]$sb.Append("<tr><td>$(& $enc $k.Item)</td><td>$(& $enc $k.Value)</td></tr>") }
[void]$sb.Append('</tbody></table>')

# Findings
[void]$sb.Append('<h2 id="findings">Findings and recommendations</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $Findings @('Severity', 'Category', 'Target', 'Title', 'Detail', 'Recommendation') 'No finding.'))

# Shares
[void]$sb.Append('<h2 id="shares">Shares</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $Data.Shares @('Name', 'Path', 'Description', 'IsData', 'PathExists', 'ABE', 'EncryptData', 'CachingMode', 'CurrentUsers', 'Owner', 'InheritanceBlocked', 'SaclEntries')))

# Matrix
[void]$sb.Append('<h2 id="matrix">Who can access what (effective rights, approximate)</h2>')
[void]$sb.Append('<div class="note">Effective right = the most restrictive of the share-level and NTFS permissions of the share root, for a <b>network</b> logon of each enabled local account (Everyone, Authenticated Users and Users included; local administrators lose their admin rights over the network when remote UAC filtering is active). Sub-folders with explicit permissions may differ: see the next section. Domain accounts are not evaluated.</div>')
if (@($Data.AccessMatrix).Count) {
    $usersM = @($Data.AccessMatrix | ForEach-Object { $_.User } | Select-Object -Unique)
    [void]$sb.Append('<div class="tw"><table><thead><tr><th>User</th>')
    foreach ($s in $MatrixShares) { [void]$sb.Append("<th>$(& $enc $s.Name)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($u in $usersM) {
        [void]$sb.Append("<tr><td>$(& $enc $u)</td>")
        foreach ($s in $MatrixShares) {
            $c = $Data.AccessMatrix | Where-Object { $_.User -eq $u -and $_.Share -eq $s.Name } | Select-Object -First 1
            if ($c) { [void]$sb.Append("<td class=`"lvl-$($c.EffectiveLevel)`" title=`"share: $($c.ShareLevel) / NTFS: $($c.NtfsLevel)`">$($c.Effective)</td>") } else { [void]$sb.Append('<td></td>') }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div><p class="muted">Hover a cell to see share / NTFS levels. Legend: Full (can change permissions) &middot; Change (write/delete) &middot; Read &middot; None.</p>')
} else { [void]$sb.Append('<p class="muted">No data share or no enabled local account.</p>') }

# Permissions
[void]$sb.Append('<h2 id="acl">Permissions detail</h2>')
foreach ($s in @($Data.Shares | Where-Object { $_.Name -ne 'IPC$' })) {
    $sa = @($Data.ShareAccess | Where-Object { $_.Share -eq $s.Name })
    $na = @($Data.NtfsRoot | Where-Object { $_.Share -eq $s.Name } | Select-Object Identity, Type, Rights, @{ n = 'Level'; e = { $LevelNames[$_.Level] } }, IsInherited, Inheritance, Propagation)
    $open = if ($s.IsData) { ' open' } else { '' }
    [void]$sb.Append("<details$open><summary>$(& $enc $s.Name) &mdash; $(& $enc $s.Path)</summary><h3>Share permissions</h3>")
    [void]$sb.Append((ConvertTo-HtmlTable $sa @('AccountName', 'AccessControlType', 'AccessRight')))
    if ($na.Count) { [void]$sb.Append("<h3>NTFS permissions of the share root (inheritance blocked: $(Format-Value $s.InheritanceBlocked))</h3>"); [void]$sb.Append((ConvertTo-HtmlTable $na)) }
    [void]$sb.Append('</details>')
}
$st = $Data.SubfolderStats
[void]$sb.Append('<h3>Sub-folders with explicit permissions or blocked inheritance</h3>')
if ($st -and $st.Skipped) { [void]$sb.Append('<p class="muted">Scan skipped (-Quick or -Depth 0).</p>') }
else {
    if ($st) { [void]$sb.Append("<p class=`"muted`">$($st.Scanned) folder(s) scanned up to depth $($st.Depth)$(if ($st.Truncated) { " - <b>truncated at -MaxFolders $MaxFolders</b>" }).</p>") }
    [void]$sb.Append((ConvertTo-HtmlTable $Data.Subfolders @('Share', 'Path', 'RelativeDepth', 'InheritanceBlocked', 'ExplicitAces', 'Explicit', 'BroadWrite') 'None: all scanned sub-folders simply inherit from the share root.'))
}

# Sessions
[void]$sb.Append('<h2 id="sessions">Active sessions and open files</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $Data.Sessions $null 'No active session (or not elevated).'))
$ofAgg = @($Data.OpenFiles | Group-Object ClientUserName, ClientComputerName | ForEach-Object { [pscustomobject]@{ Client = $_.Name; OpenFiles = $_.Count; Example = ($_.Group | Select-Object -First 1).Path } })
[void]$sb.Append('<h3>Open files per client</h3>')
[void]$sb.Append((ConvertTo-HtmlTable $ofAgg $null 'No open file.'))

# Accounts
[void]$sb.Append('<h2 id="accounts">Local accounts and groups</h2>')
[void]$sb.Append((ConvertTo-HtmlTable $Data.Users @('Name', 'Enabled', 'PasswordRequired', 'PasswordExpires', 'PasswordLastSet', 'LastLogon', 'Description', 'Source')))
$gm = @($Data.GroupMembers | Group-Object Group | ForEach-Object { [pscustomobject]@{ Group = $_.Name; Members = (@($_.Group | ForEach-Object { $_.Name }) -join ', ') } })
[void]$sb.Append('<h3>Group membership (non-empty groups)</h3>')
[void]$sb.Append((ConvertTo-HtmlTable $gm))
if ($Data.Policy) { [void]$sb.Append('<h3>Password, lockout and logon rights policy</h3>'); [void]$sb.Append((ConvertTo-HtmlTable @($Data.Policy.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Setting = $_.Name; Value = $_.Value } }))) }

# SMB
[void]$sb.Append('<h2 id="smb">SMB configuration and authentication settings</h2>')
foreach ($blk in @(@{ T = 'SMB server'; O = $Data.SmbServer }, @{ T = 'SMB client'; O = $Data.SmbClient }, @{ T = 'Security registry values (empty = not set, Windows default applies)'; O = $Data.SecurityRegistry })) {
    [void]$sb.Append("<h3>$($blk.T)</h3>")
    if ($blk.O) { [void]$sb.Append((ConvertTo-HtmlTable @($blk.O.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Setting = $_.Name; Value = $_.Value } }))) } else { [void]$sb.Append('<p class="muted">Not available.</p>') }
}
[void]$sb.Append("<p class=`"muted`">SMB1Protocol optional feature: $(& $enc $Data.Smb1Feature)</p>")

# Network
[void]$sb.Append('<h2 id="network">Network and firewall</h2><h3>Network profiles</h3>')
[void]$sb.Append((ConvertTo-HtmlTable $Data.NetProfiles))
[void]$sb.Append('<h3>IPv4 addresses</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.IPv4))
[void]$sb.Append('<h3>NetBIOS / LLMNR</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.NetBios))
[void]$sb.Append("<p class=`"muted`">LLMNR policy EnableMulticast: $(if ($null -eq $Data.Llmnr) { 'not set (enabled)' } else { & $enc $Data.Llmnr })</p>")
[void]$sb.Append('<h3>Firewall profiles</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.FirewallProfiles))
[void]$sb.Append('<h3>Inbound SMB-related rules</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.FirewallRules @('Source', 'DisplayName', 'Enabled', 'Action', 'Profile', 'Protocol', 'LocalPort', 'RemoteAddress')))

# Host
[void]$sb.Append('<h2 id="host">Volumes and protection</h2><h3>Volumes</h3>')
[void]$sb.Append((ConvertTo-HtmlTable $Data.Volumes))
[void]$sb.Append('<h3>Antivirus and ransomware protection</h3>')
if ($Data.Protection) { [void]$sb.Append((ConvertTo-HtmlTable @($Data.Protection.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Setting = $_.Name; Value = $_.Value } }))) }
[void]$sb.Append('<h3>Audit policy</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.AuditPolicy))
[void]$sb.Append('<h3>Power</h3>')
if ($Data.Power) { [void]$sb.Append((ConvertTo-HtmlTable @($Data.Power.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Setting = $_.Name; Value = $(if ($null -eq $_.Value) { 'unknown' } elseif ($_.Value -eq 0) { 'Never' } else { '{0} min' -f [Math]::Round($_.Value / 60) }) } }))) }
[void]$sb.Append('<h3>Backup agents detected</h3>'); [void]$sb.Append((ConvertTo-HtmlTable $Data.BackupAgents $null 'None detected.'))
[void]$sb.Append('<h3>Host</h3>'); [void]$sb.Append((ConvertTo-HtmlTable @($Data.Host.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Item = $_.Name; Value = $_.Value } })))

# Log
[void]$sb.Append('<h2 id="log">Collection</h2>')
[void]$sb.Append((ConvertTo-HtmlTable @($script:Sections | ForEach-Object { [pscustomobject]@{ Section = $_.Name; DurationMs = $_.DurationMs; Errors = $_.Errors.Count } })))
[void]$sb.Append((ConvertTo-HtmlTable $CollectionErrors @('Section', 'Error') 'No collection error.'))
[void]$sb.Append("<p class=`"muted`">Generated by Invoke-ShareAudit.ps1 v$ScriptVersion (read-only). Raw data: audit.json and CSV files in the same folder. Treat this report as confidential: it describes the security posture of the machine.</p></main></body></html>")

$ReportPath = Join-Path $script:Folder 'report.html'
[System.IO.File]::WriteAllText($ReportPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Log "Report: $ReportPath"
$Elapsed = [Math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)
Write-Log "Completed in $Elapsed s"

$ZipPath = $null
if (-not $NoZip) {
    $ZipPath = "$($script:Folder).zip"
    try { New-ZipFromFolder -Folder $script:Folder -ZipPath $ZipPath; Write-Host "ZIP: $ZipPath" -ForegroundColor Gray }
    catch { Write-Host "ZIP creation failed: $($_.Exception.Message)" -ForegroundColor Yellow; $ZipPath = $null }
}

Write-Host ''
Write-Host ('  Verdict : {0}  (score {1}/100)' -f $Verdict, $Score) -ForegroundColor $(switch ($VerdictClass) { 'v-crit' { 'Red' } 'v-high' { 'Red' } 'v-med' { 'Yellow' } default { 'Green' } })
Write-Host ('  Critical {0} | High {1} | Medium {2} | Low {3} | Info {4}' -f $Counts.Critical, $Counts.High, $Counts.Medium, $Counts.Low, $Counts.Info)
foreach ($f in @($Findings | Where-Object { $_.Severity -in @('Critical', 'High') })) { Write-Host ('  [{0}] {1}' -f $f.Severity, $f.Title) -ForegroundColor $(if ($f.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }) }
Write-Host "  Report  : $ReportPath"
Write-Host ''

if ($OpenReport) { try { Start-Process $ReportPath } catch { Write-Verbose 'Cannot open report' } }

[pscustomobject][ordered]@{
    Folder   = $script:Folder
    Report   = $ReportPath
    Zip      = $ZipPath
    Verdict  = $Verdict
    Score    = $Score
    Critical = $Counts.Critical
    High     = $Counts.High
    Medium   = $Counts.Medium
    Low      = $Counts.Low
    Info     = $Counts.Info
}

#endregion
