# Simulated Windows cmdlets used by tests/Invoke-SmokeTest.ps1 (PowerShell 7, Linux/macOS/CI).
# Scenario: "PC-SRV01", a Windows 11 Pro PC used as file server in a small office workgroup,
# with a mix of good and bad practices.

$script:Dom = 'S-1-5-21-1111-2222-3333'
$script:Host_ = 'PC-SRV01'

function New-Ace {
    param([string]$Id, [string]$Rights, [string]$Type = 'Allow', [bool]$Inherited = $false, [string]$Inh = 'ContainerInherit, ObjectInherit', [string]$Prop = 'None')
    [pscustomobject]@{ IdentityReference = $Id; FileSystemRights = $Rights; AccessControlType = $Type; IsInherited = $Inherited; InheritanceFlags = $Inh; PropagationFlags = $Prop }
}

# Default ACL of a data volume root (D:\), as inherited by child folders
function Get-VolumeRootInherited {
    @(
        (New-Ace 'NT AUTHORITY\SYSTEM' 'FullControl' -Inherited $true)
        (New-Ace 'BUILTIN\Administrators' 'FullControl' -Inherited $true)
        (New-Ace 'CREATOR OWNER' '268435456' -Inherited $true -Prop 'InheritOnly')
        (New-Ace 'NT AUTHORITY\Authenticated Users' 'Modify, Synchronize' -Inherited $true)
        (New-Ace 'BUILTIN\Users' 'ReadAndExecute, Synchronize' -Inherited $true)
    )
}

$global:MockDirs = @('D:\Commun', 'D:\Partage\Compta', 'D:\Scan', 'C:\Users', 'C:\', 'D:\', 'C:\Windows',
    'D:\Partage\Compta\2024', 'D:\Partage\Compta\Paie', 'D:\Partage\Compta\Paie\Archives', 'D:\Commun\Photos', 'D:\Commun\Public')

$global:MockTree = @{
    'D:\Partage\Compta' = @('D:\Partage\Compta\2024', 'D:\Partage\Compta\Paie', 'D:\Partage\Compta\Paie\Archives')
    'D:\Commun'         = @('D:\Commun\Photos', 'D:\Commun\Public')
}

$protectedBase = @(
    (New-Ace 'NT AUTHORITY\SYSTEM' 'FullControl')
    (New-Ace 'BUILTIN\Administrators' 'FullControl')
)
$global:MockAcl = @{
    'D:\Commun'                       = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false; Access = (Get-VolumeRootInherited); Audit = @() }
    'D:\Commun\Photos'                = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false; Access = (Get-VolumeRootInherited); Audit = @() }
    'D:\Commun\Public'                = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false; Access = @((Get-VolumeRootInherited) + (New-Ace 'Everyone' 'Modify, Synchronize')); Audit = @() }
    'D:\Partage\Compta'               = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $true; Access = @($protectedBase + (New-Ace "$script:Host_\GRP_Compta_RW" 'Modify, Synchronize') + (New-Ace "$script:Host_\GRP_Compta_RO" 'ReadAndExecute, Synchronize') + (New-Ace "$script:Host_\l.bianchi" 'Modify, Synchronize') + (New-Ace "$script:Dom-1999" 'ReadAndExecute, Synchronize')); Audit = @([pscustomobject]@{ IdentityReference = 'Everyone'; AuditFlags = 'Success' }) }
    'D:\Partage\Compta\2024'          = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false; Access = @((New-Ace 'NT AUTHORITY\SYSTEM' 'FullControl' -Inherited $true), (New-Ace "$script:Host_\GRP_Compta_RW" 'Modify, Synchronize' -Inherited $true)); Audit = @() }
    'D:\Partage\Compta\Paie'          = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $true; Access = @($protectedBase + (New-Ace "$script:Host_\GRP_Direzione" 'Modify, Synchronize')); Audit = @() }
    'D:\Partage\Compta\Paie\Archives' = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $false; Access = @((New-Ace 'NT AUTHORITY\SYSTEM' 'FullControl' -Inherited $true), (New-Ace "$script:Host_\GRP_Direzione" 'Modify, Synchronize' -Inherited $true), (New-Ace "$script:Host_\m.rossi" 'FullControl')); Audit = @() }
    'D:\Scan'                         = [pscustomobject]@{ Owner = 'BUILTIN\Administrators'; AreAccessRulesProtected = $true; Access = @($protectedBase + (New-Ace 'Everyone' 'Modify, Synchronize')); Audit = @() }
    'C:\Users'                        = [pscustomobject]@{ Owner = 'NT AUTHORITY\SYSTEM'; AreAccessRulesProtected = $true; Access = @($protectedBase + (New-Ace 'BUILTIN\Users' 'ReadAndExecute, Synchronize') + (New-Ace 'Everyone' 'ReadAndExecute, Synchronize')); Audit = @() }
}

$global:MockRegistry = @{
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion|DisplayVersion'                       = '24H2'
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion|UBR'                                  = 2314
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion|EditionID'                            = 'Professional'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous'                             = 0
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM'                          = 1
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|EveryoneIncludesAnonymous'                     = 0
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|ForceGuest'                                    = 0
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LimitBlankPasswordUse'                         = 1
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|NoLmHash'                                      = 1
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters|RestrictNullSessAccess'   = 1
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|AllowInsecureGuestAuth' = 1
}

function Get-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [Parameter(Position = 1)][string[]]$Name, [string[]]$LiteralPath)
    $p = "$($Path)"
    if ($p -like 'HKLM:*') {
        $k = "$p|$($Name)"
        if ($global:MockRegistry.ContainsKey($k)) { return [pscustomobject]@{ "$($Name)" = $global:MockRegistry[$k] } }
        throw "Property $Name does not exist at path $p"
    }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}

function Test-Path {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, $PathType)
    $p = "$($LiteralPath)$($Path)"
    if ($p -match '^[A-Z]:\\') { return [bool]($global:MockDirs -contains $p.TrimEnd('\') -or $global:MockDirs -contains $p) }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}

function Get-ChildItem {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, [switch]$Directory, [switch]$File, [switch]$Recurse, [uint32]$Depth, [switch]$Force, [string]$Filter)
    $p = "$($LiteralPath)$($Path)"
    if ($p -match '^[A-Z]:\\') {
        if ($global:MockTree.ContainsKey($p)) { return @($global:MockTree[$p] | ForEach-Object { [pscustomobject]@{ FullName = $_; Name = ($_ -split '\\')[-1]; PSIsContainer = $true } }) }
        return @()
    }
    Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}

function Get-Acl {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, [switch]$Audit)
    $p = "$($LiteralPath)$($Path)"
    if ($global:MockAcl.ContainsKey($p)) { return $global:MockAcl[$p] }
    throw "Cannot find path '$p'"
}

function Get-CimInstance {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$ClassName, [string]$Namespace, [string]$Filter)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; BuildNumber = '26100'; ProductType = 1; OSArchitecture = '64-bit'; LastBootUpTime = (Get-Date).AddDays(-50) } }
        'Win32_ComputerSystem' { [pscustomobject]@{ PartOfDomain = $false; Domain = 'WORKGROUP'; Workgroup = 'WORKGROUP'; Manufacturer = 'Dell Inc.'; Model = 'OptiPlex 7010' } }
        'Win32_NetworkAdapterConfiguration' { [pscustomobject]@{ Description = 'Intel(R) Ethernet Connection I219-LM'; TcpipNetbiosOptions = 0 } }
        'Win32_LogicalDisk' {
            [pscustomobject]@{ DeviceID = 'C:'; VolumeName = 'System'; FileSystem = 'NTFS'; Size = 255GB; FreeSpace = 120GB }
            [pscustomobject]@{ DeviceID = 'D:'; VolumeName = 'Data'; FileSystem = 'NTFS'; Size = 931GB; FreeSpace = 40GB }
        }
        'Win32_Volume' {
            [pscustomobject]@{ DeviceID = '\\?\Volume{c0000000-0000-0000-0000-000000000000}\'; DriveLetter = 'C:' }
            [pscustomobject]@{ DeviceID = '\\?\Volume{d0000000-0000-0000-0000-000000000000}\'; DriveLetter = 'D:' }
        }
        'Win32_ShadowCopy' { [pscustomobject]@{ VolumeName = '\\?\Volume{c0000000-0000-0000-0000-000000000000}\' } }
        'AntiVirusProduct' { [pscustomobject]@{ displayName = 'Windows Defender' } }
        default { throw "Mock: class $ClassName not simulated" }
    }
}

function Get-LocalUser {
    [CmdletBinding()] param()
    $old = (Get-Date).AddDays(-200)
    @(
        [pscustomobject]@{ Name = 'Administrator'; SID = "$script:Dom-500"; Enabled = $false; PasswordRequired = $true; PasswordExpires = $null; PasswordLastSet = $null; LastLogon = $null; Description = 'Built-in account for administering the computer/domain'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'Guest'; SID = "$script:Dom-501"; Enabled = $true; PasswordRequired = $false; PasswordExpires = $null; PasswordLastSet = $null; LastLogon = $null; Description = 'Built-in account for guest access'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'DefaultAccount'; SID = "$script:Dom-503"; Enabled = $false; PasswordRequired = $false; PasswordExpires = $null; PasswordLastSet = $null; LastLogon = $null; Description = ''; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'pietro'; SID = "$script:Dom-1001"; Enabled = $true; PasswordRequired = $true; PasswordExpires = $null; PasswordLastSet = (Get-Date).AddDays(-20); LastLogon = (Get-Date).AddDays(-1); Description = 'IT admin'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'm.rossi'; SID = "$script:Dom-1002"; Enabled = $true; PasswordRequired = $true; PasswordExpires = $null; PasswordLastSet = (Get-Date).AddDays(-30); LastLogon = (Get-Date).AddDays(-1); Description = 'Mario Rossi'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'l.bianchi'; SID = "$script:Dom-1003"; Enabled = $true; PasswordRequired = $true; PasswordExpires = $null; PasswordLastSet = (Get-Date).AddDays(-30); LastLogon = (Get-Date).AddDays(-2); Description = 'Laura Bianchi'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'ufficio'; SID = "$script:Dom-1004"; Enabled = $true; PasswordRequired = $false; PasswordExpires = $null; PasswordLastSet = $old; LastLogon = (Get-Date).AddDays(-3); Description = 'Shared office account'; PrincipalSource = 'Local' }
        [pscustomobject]@{ Name = 'svc_scan'; SID = "$script:Dom-1005"; Enabled = $true; PasswordRequired = $true; PasswordExpires = $null; PasswordLastSet = $old; LastLogon = $old; Description = 'MFP scan to folder'; PrincipalSource = 'Local' }
    )
}

function Get-LocalGroup {
    [CmdletBinding()] param()
    @(
        [pscustomobject]@{ Name = 'Administrators'; SID = 'S-1-5-32-544'; Description = '' }
        [pscustomobject]@{ Name = 'Users'; SID = 'S-1-5-32-545'; Description = '' }
        [pscustomobject]@{ Name = 'Guests'; SID = 'S-1-5-32-546'; Description = '' }
        [pscustomobject]@{ Name = 'GRP_Compta_RW'; SID = "$script:Dom-1010"; Description = 'Accounting read/write' }
        [pscustomobject]@{ Name = 'GRP_Compta_RO'; SID = "$script:Dom-1011"; Description = 'Accounting read only' }
        [pscustomobject]@{ Name = 'GRP_Direzione'; SID = "$script:Dom-1012"; Description = 'Management' }
    )
}

function Get-LocalGroupMember {
    [CmdletBinding()] param([string]$Group)
    $m = { param($n, $s, $c = 'User') [pscustomobject]@{ Name = $n; SID = $s; ObjectClass = $c; PrincipalSource = 'Local' } }
    switch ($Group) {
        'Administrators' { & $m "$script:Host_\Administrator" "$script:Dom-500"; & $m "$script:Host_\pietro" "$script:Dom-1001" }
        'Users' { & $m 'NT AUTHORITY\Authenticated Users' 'S-1-5-11' 'Group'; & $m 'NT AUTHORITY\INTERACTIVE' 'S-1-5-4' 'Group'; & $m "$script:Host_\m.rossi" "$script:Dom-1002" }
        'Guests' { & $m "$script:Host_\Guest" "$script:Dom-501" }
        'GRP_Compta_RW' { & $m "$script:Host_\m.rossi" "$script:Dom-1002" }
        'GRP_Compta_RO' { & $m "$script:Host_\ufficio" "$script:Dom-1004" }
        'GRP_Direzione' { & $m "$script:Host_\pietro" "$script:Dom-1001" }
        default { }
    }
}

function secedit {
    $cfg = $null
    for ($i = 0; $i -lt $args.Count; $i++) { if ("$($args[$i])" -eq '/cfg') { $cfg = "$($args[$i + 1])" } }
    if ($cfg) {
        @(
            '[Unicode]', 'Unicode=yes', '[System Access]', 'MinimumPasswordAge = 0', 'MaximumPasswordAge = 42', 'MinimumPasswordLength = 0',
            'PasswordComplexity = 0', 'LockoutBadCount = 0', 'EnableGuestAccount = 1', 'LSAAnonymousNameLookup = 0',
            '[Privilege Rights]', 'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551',
            'SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551', 'SeDenyInteractiveLogonRight = Guest'
        ) | Set-Content -LiteralPath $cfg -Encoding Unicode
    }
    'The task has completed successfully.'
}

function auditpol {
    $g = ("$args" -replace '.*\{([0-9A-Fa-f-]+)\}.*', '$1')
    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
    "PC-SRV01,System,Mock subcategory,{$g},No Auditing,"
}

function powercfg {
    $setting = "$($args[3])"
    $ac = if ($setting -eq 'STANDBYIDLE') { '0x00000708' } else { '0x00000000' }
    @(
        'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)'
        '  Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)'
        '    Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  (Sleep after)'
        '      Minimum Possible Setting: 0x00000000'
        '      Maximum Possible Setting: 0xffffffff'
        '      Possible Settings increment: 0x00000001'
        '      Possible Settings units: Seconds'
        "    Current AC Power Setting Index: $ac"
        '    Current DC Power Setting Index: 0x00000384'
    )
}

function Get-NetConnectionProfile { [CmdletBinding()] param() [pscustomobject]@{ Name = 'Network 2'; InterfaceAlias = 'Ethernet'; InterfaceIndex = 12; NetworkCategory = 'Public'; IPv4Connectivity = 'Internet' } }
function Get-NetIPAddress { [CmdletBinding()] param($AddressFamily) @([pscustomobject]@{ InterfaceAlias = 'Ethernet'; InterfaceIndex = 12; IPAddress = '192.168.1.20'; PrefixLength = 24; PrefixOrigin = 'Dhcp' }, [pscustomobject]@{ InterfaceAlias = 'Loopback Pseudo-Interface 1'; InterfaceIndex = 1; IPAddress = '127.0.0.1'; PrefixLength = 8; PrefixOrigin = 'WellKnown' }) }

function Get-SmbServerConfiguration {
    [CmdletBinding()] param()
    [pscustomobject]@{ EnableSMB1Protocol = $false; EnableSMB2Protocol = $true; RequireSecuritySignature = $false; EnableSecuritySignature = $true; EncryptData = $false; RejectUnencryptedAccess = $true
        EnableAuthRateLimiter = $true; InvalidAuthenticationDelayTimeInMs = 2000; AutoShareServer = $true; AutoShareWorkstation = $true; AnnounceServer = $false; AuditSmb1Access = $false; NullSessionPipes = ''; NullSessionShares = '' }
}
function Get-SmbClientConfiguration { [CmdletBinding()] param() [pscustomobject]@{ EnableInsecureGuestLogons = $true; RequireSecuritySignature = $true; EnableSecuritySignature = $true; RequireEncryption = $false; BlockNTLM = $false } }
function Get-WindowsOptionalFeature { [CmdletBinding()] param([switch]$Online, [string]$FeatureName) [pscustomobject]@{ FeatureName = $FeatureName; State = 'Disabled' } }

function Get-NetFirewallProfile {
    [CmdletBinding()] param($PolicyStore)
    @('Domain', 'Private', 'Public') | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = 'True'; DefaultInboundAction = 'NotConfigured'; LogBlocked = 'False' } }
}

$global:MockFwRules = @(
    [pscustomobject]@{ Name = 'FPS-SMB-In-TCP'; DisplayName = 'File and Printer Sharing (SMB-In)'; Group = '@FirewallAPI.dll,-28502'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Public'; _Port = '445'; _Proto = 'TCP'; _Remote = 'Any' }
    [pscustomobject]@{ Name = 'FPS-SMB-In-TCP-Private'; DisplayName = 'File and Printer Sharing (SMB-In)'; Group = '@FirewallAPI.dll,-28502'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; _Port = '445'; _Proto = 'TCP'; _Remote = 'LocalSubnet' }
    [pscustomobject]@{ Name = 'FPS-NB_Session-In-TCP'; DisplayName = 'File and Printer Sharing (NB-Session-In)'; Group = '@FirewallAPI.dll,-28502'; Enabled = 'False'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; _Port = '139'; _Proto = 'TCP'; _Remote = 'LocalSubnet' }
    [pscustomobject]@{ Name = 'FPS-SMB-Out-TCP'; DisplayName = 'File and Printer Sharing (SMB-Out)'; Group = '@FirewallAPI.dll,-28502'; Enabled = 'True'; Direction = 'Outbound'; Action = 'Allow'; Profile = 'Private'; _Port = '445'; _Proto = 'TCP'; _Remote = 'LocalSubnet' }
    [pscustomobject]@{ Name = '{CUSTOM-1}'; DisplayName = 'Old NAS SMB access'; Group = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; _Port = '445'; _Proto = 'TCP'; _Remote = 'Any' }
    [pscustomobject]@{ Name = 'RemoteDesktop-UserMode-In-TCP'; DisplayName = 'Remote Desktop - User Mode (TCP-In)'; Group = '@FirewallAPI.dll,-28752'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Private'; _Port = '3389'; _Proto = 'TCP'; _Remote = 'Any' }
)

function Get-NetFirewallRule {
    [CmdletBinding()] param($Group, $Direction, $Enabled, $Action, $PolicyStore)
    $r = $global:MockFwRules
    if ($Group) { $r = $r | Where-Object { $_.Group -eq $Group } }
    if ($Direction) { $r = $r | Where-Object { $_.Direction -eq "$Direction" } }
    if ($Enabled) { $r = $r | Where-Object { $_.Enabled -eq "$Enabled" } }
    if ($Action) { $r = $r | Where-Object { $_.Action -eq "$Action" } }
    @($r)
}
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$AssociatedNetFirewallRule) process { [pscustomobject]@{ RemoteAddress = $AssociatedNetFirewallRule._Remote } } }
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$AssociatedNetFirewallRule) process { [pscustomobject]@{ LocalPort = $AssociatedNetFirewallRule._Port; Protocol = $AssociatedNetFirewallRule._Proto } } }

function Get-SmbShare {
    [CmdletBinding()] param()
    $s = { param($n, $p, $d, $sp = $false, $abe = 'Unrestricted', $enc = $false, $cache = 'Manual', $type = 'FileSystemDirectory') [pscustomobject]@{ Name = $n; Path = $p; Description = $d; Special = $sp; ShareType = $type; FolderEnumerationMode = $abe; EncryptData = $enc; CachingMode = $cache; ConcurrentUserLimit = 0; CurrentUsers = 3; ScopeName = '*' } }
    & $s 'ADMIN$' 'C:\Windows' 'Remote Admin' $true
    & $s 'C$' 'C:\' 'Default share' $true
    & $s 'D$' 'D:\' 'Default share' $true
    & $s 'IPC$' '' 'Remote IPC' $true 'Unrestricted' $false 'Manual' 'FileSystemDirectory'
    & $s 'Commun' 'D:\Commun' 'Common folder' $false 'Unrestricted' $false 'Programs'
    & $s 'Compta' 'D:\Partage\Compta' 'Accounting' $false 'AccessBased' $true 'None'
    & $s 'Scan' 'D:\Scan' 'Scan to folder' $false
    & $s 'Utenti' 'C:\Users' 'Profiles' $false
    & $s 'Old' 'D:\OldStuff' 'Removed folder' $false
}

function Get-SmbShareAccess {
    [CmdletBinding()] param([string]$Name)
    $a = { param($acc, $right, $type = 'Allow') [pscustomobject]@{ Name = $Name; AccountName = $acc; AccessControlType = $type; AccessRight = $right } }
    switch ($Name) {
        'Commun' { & $a 'Everyone' 'Full' }
        'Compta' { & $a 'BUILTIN\Administrators' 'Full'; & $a 'NT AUTHORITY\Authenticated Users' 'Change' }
        'Scan' { & $a 'Everyone' 'Change' }
        'Utenti' { & $a 'Everyone' 'Read' }
        'Old' { & $a 'Everyone' 'Read' }
        default { & $a 'BUILTIN\Administrators' 'Full' }
    }
}

function Get-SmbSession {
    [CmdletBinding()] param()
    $list = foreach ($i in 1..15) { [pscustomobject]@{ ClientComputerName = "192.168.1.$(100 + $i)"; ClientUserName = "$script:Host_\m.rossi"; Dialect = '3.1.1'; NumOpens = 2; SecondsExists = 3600; SecondsIdle = 10 } }
    @($list) + [pscustomobject]@{ ClientComputerName = '192.168.1.250'; ClientUserName = "$script:Host_\Guest"; Dialect = '2.1'; NumOpens = 1; SecondsExists = 120; SecondsIdle = 60 }
}
function Get-SmbOpenFile { [CmdletBinding()] param() [pscustomobject]@{ ClientComputerName = '192.168.1.101'; ClientUserName = "$script:Host_\m.rossi"; Path = 'D:\Partage\Compta\2024\bilan.xlsx'; ShareRelativePath = '2024\bilan.xlsx' } }

function Get-BitLockerVolume {
    [CmdletBinding()] param([string]$MountPoint)
    [pscustomobject]@{ MountPoint = $MountPoint; ProtectionStatus = $(if ($MountPoint -eq 'C:') { 'On' } else { 'Off' }) }
}
function Get-MpComputerStatus { [CmdletBinding()] param() [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureLastUpdated = (Get-Date).AddDays(-1) } }
function Get-MpPreference { [CmdletBinding()] param() [pscustomobject]@{ EnableControlledFolderAccess = 0; ControlledFolderAccessProtectedFolders = @() } }
function Get-Service {
    [CmdletBinding()] param()
    @(
        [pscustomobject]@{ Name = 'LanmanServer'; DisplayName = 'Server'; Status = 'Running'; StartType = 'Automatic' }
        [pscustomobject]@{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; Status = 'Running'; StartType = 'Automatic' }
    )
}

Export-ModuleMember -Function *
