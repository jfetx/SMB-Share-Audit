# Hardening checklist: file sharing from a Windows PC in a workgroup

Target configuration that `Invoke-ShareAudit.ps1` checks against, with the commands to get there.
Run them **as Administrator**, test on one share first, and keep a note of what you change.

## 1. Architecture

- [ ] **One dedicated PC** hosts all shares (no folders shared from every workstation).
- [ ] Stable host name, **DHCP reservation or static IP**, drives mapped by name (`\\PC-SRV01\...`).
- [ ] Never sleeps on AC power, ideally on a UPS:
  ```powershell
  powercfg /change standby-timeout-ac 0
  powercfg /change hibernate-timeout-ac 0
  ```
- [ ] Data on a **dedicated volume** (e.g. `D:\Shares`), never `C:\`, `C:\Users` or a drive root.
- [ ] **BitLocker** on system and data volumes, recovery key stored outside the PC.
- [ ] Windows client editions accept **20 concurrent inbound connections** maximum: beyond ~10-15
      devices, move to a NAS, a Windows Server or SharePoint/OneDrive.

## 2. Accounts

- [ ] One **named local account per person** on the file-server PC (no shared "office" account).
- [ ] Dedicated, restricted accounts for devices (e.g. `svc_scan` for the multifunction printer).
- [ ] **Guest disabled**, password-protected sharing **on**.
- [ ] Lockout policy and minimum password length:
  ```powershell
  net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 /minpwlen:12
  ```
- [ ] Share-only accounts denied local / RDP logon if the PC is dedicated (secpol.msc > User Rights Assignment).

## 3. Permissions model

Share permissions wide, NTFS permissions precise, **groups only**:

```
User (m.rossi) -> local group (GRP_Compta_RW) -> NTFS ACE on D:\Shares\Compta
```

```powershell
# Groups and membership
"GRP_All", "GRP_Compta_RW", "GRP_Compta_RO", "GRP_Management" | ForEach-Object { New-LocalGroup -Name $_ -ErrorAction SilentlyContinue }
Add-LocalGroupMember -Group "GRP_Compta_RW" -Member "m.rossi"

# Folder tree with inheritance REMOVED at the root (avoid the volume default "Authenticated Users: Modify")
$root = "D:\Shares"
"Common", "Compta", "Management", "Scan" | ForEach-Object { New-Item "$root\$_" -ItemType Directory -Force | Out-Null }
icacls $root /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "GRP_All:RX"
icacls "$root\Common"     /grant:r "GRP_All:(OI)(CI)M"
icacls "$root\Compta"     /grant:r "GRP_Compta_RW:(OI)(CI)M" "GRP_Compta_RO:(OI)(CI)RX" "GRP_Management:(OI)(CI)M"
icacls "$root\Management" /grant:r "GRP_Management:(OI)(CI)M"

# Share: Administrators Full, Authenticated Users Change, ABE, encryption, no offline cache
New-SmbShare -Name "Shares" -Path $root -FullAccess "*S-1-5-32-544" -ChangeAccess "*S-1-5-11" `
    -FolderEnumerationMode AccessBased -EncryptData $true -CachingMode None
```

- [ ] No `Everyone` / `Users` / `Authenticated Users` with Modify in NTFS (use `GRP_All` for a common folder).
- [ ] Full Control only for SYSTEM and Administrators.
- [ ] Permissions defined on the first 1-2 levels only; archives read-only.

## 4. SMB and authentication

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -RequireSecuritySignature $true -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5
```

- [ ] Remote UAC filtering kept (`LocalAccountTokenFilterPolicy` absent or 0); unique local admin passwords (Windows LAPS).
- [ ] Old scanners: update firmware, use scan-to-email, or a **dedicated share + dedicated account**;
      never re-enable SMB1 or disable signing globally for one device.

## 5. Network and firewall

- [ ] Office LAN = **Private** profile on the file-server PC; guest/untrusted networks = Public.
  ```powershell
  Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
  ```
- [ ] File and Printer Sharing enabled **on Private only**, restricted to the LAN:
  ```powershell
  Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502" | Where-Object Profile -match "Private" |
      Set-NetFirewallRule -Enabled True -RemoteAddress LocalSubnet
  Get-NetFirewallRule -Group "@FirewallAPI.dll,-28502" | Where-Object Profile -match "Public" |
      Set-NetFirewallRule -Enabled False
  ```
- [ ] LLMNR and NetBIOS over TCP/IP disabled when no legacy device needs them.
- [ ] Guest Wi-Fi on a separate network/VLAN that cannot reach the PC.

## 6. Backup and ransomware

- [ ] **3-2-1** backups with one **offline or immutable** copy (NAS snapshots, rotated USB disks, cloud object lock).
- [ ] Restore tested every quarter.
- [ ] Backup target not writable by users and not mapped as a drive on clients.
- [ ] Shadow copies (System Protection) on the data volume as a convenience, not as a backup.
- [ ] Defender real-time protection on; Controlled Folder Access tested in Audit mode.

## 7. Traceability

```powershell
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable           # File System
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Logon
wevtutil sl Security /ms:536870912                                                                  # 512 MB Security log
```

- [ ] SACL on share roots: *Everyone* - Success - *Delete*, *Delete subfolders and files*, *Write data*.
- [ ] Look for events **4663 / 4660** (deletions) and **4625** (failed logons).

## 8. Operations

- [ ] Permission matrix documented (who is in which group).
- [ ] Joiner/leaver procedure: disable the account the day someone leaves.
- [ ] Updates installed outside office hours (active hours), monthly reboot.
- [ ] Re-run `Invoke-ShareAudit.ps1` after every change and at least once a quarter.
