# SMB-Share-Audit

![CI](https://github.com/jfetx/SMB-Share-Audit/actions/workflows/ci.yml/badge.svg)

**Read-only** audit of the SMB file shares of a Windows PC, with an HTML summary report.

Built for small businesses **without a server or a domain**, where "the file server" is a
Windows 10/11 Pro PC sharing folders in a workgroup. It also works on domain members and
Windows Server.

Run one script on the PC that shares the folders. It collects everything that matters for
share security and availability, then produces an **HTML report** with a verdict and a score,
**findings ranked by severity** with a concrete recommendation for each one, a
**"who can access what" matrix**, and the raw data (CSV, JSON) for your documentation.

```
┌──────────────────────────────┐
│  PC-SRV01 (Win 11 Pro)       │      Invoke-ShareAudit.ps1  (read-only)
│  \\PC-SRV01\Commun           │ ───►
│  \\PC-SRV01\Compta           │      C:\ShareAudit\ShareAudit_PC-SRV01_<date>\
│  \\PC-SRV01\Scan             │        report.html   findings.csv   access_matrix.csv
└──────────────────────────────┘        audit.json    *.csv          audit.log      (+ .zip)
```

## What it checks

| Area | Checks |
|---|---|
| **Shares** | Every share, path, missing folders, drive roots / system folders / user profiles shared, data on the system drive, Access-Based Enumeration, SMB encryption, offline caching, client-OS 20-connection limit |
| **Permissions** | Share-level permissions, NTFS permissions of each share root, inheritance from the volume root (the classic *Authenticated Users: Modify* trap), write access for any local account, Guest reachability, non-admin Full Control, per-user ACEs, orphaned SIDs, Deny entries, sub-folders with explicit or blocked permissions (bounded scan) |
| **Effective access** | Approximate effective right (share ∩ NTFS) for each enabled local account on each share, including group membership and remote UAC filtering of local admins |
| **SMB protocol** | SMBv1 (server setting + optional feature), signing (server/client), encryption, authentication rate limiter, insecure guest logons, admin shares |
| **Authentication** | LAN Manager level (NTLMv1/LM), LM hash storage, anonymous access (null sessions, SAM enumeration, Everyone includes Anonymous), Guest-only model (ForceGuest), blank passwords over the network, LocalAccountTokenFilterPolicy |
| **Accounts** | Guest enabled, accounts without required password, built-in Administrator, number of admins, stale accounts, generic/shared account names, lockout policy, minimum password length, local logon rights of share-only accounts |
| **Network & firewall** | Network profile (Private/Public), DHCP vs static, firewall profiles, File and Printer Sharing / port 445-139 rules on the Public profile or open to any address, LLMNR, NetBIOS over TCP/IP |
| **Sessions** | Active SMB sessions and open files, number of distinct clients vs the 20-connection limit, old SMB dialects (< 3.0), guest/anonymous sessions |
| **Volumes** | File system (FAT/exFAT = no ACL), free space, BitLocker, shadow copies |
| **Protection** | Defender / antivirus state and signature age, Controlled Folder Access, audit policy (File System, File Share, Logon...) and SACLs on share roots, sleep/hibernation on AC power, uptime, known backup agents |

Severities: **Critical** › **High** › **Medium** › **Low** › **Info**.
Verdict: *At risk* (any Critical) · *Needs attention* (any High) · *Acceptable, improvements recommended* · *Good*.
Score: 100 − 25×Critical − 10×High − 4×Medium − 1×Low (minimum 0).

## Quick start

1. Copy the folder to the PC that shares the folders (e.g. `C:\Temp\SMB-Share-Audit`).
2. Unblock the files downloaded from GitHub:
   ```powershell
   Get-ChildItem C:\Temp\SMB-Share-Audit -Recurse | Unblock-File
   ```
3. Run **as Administrator**:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   C:\Temp\SMB-Share-Audit\Invoke-ShareAudit.ps1 -OpenReport
   ```
   or double-click `Run-Audit.cmd` (asks for elevation and opens the report at the end).
4. Results: `C:\ShareAudit\ShareAudit_<HOST>_<timestamp>\report.html` and `ShareAudit_<HOST>_<timestamp>.zip`.

Without elevation the script still runs, but sessions, SMB1 feature state, BitLocker,
security/audit policy and SACLs may be missing (the report says so).

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | `C:\ShareAudit` | Root folder for the results |
| `-Depth` | `2` | Levels of sub-folders scanned below each share root for explicit permissions (`0` = roots only) |
| `-MaxFolders` | `3000` | Upper bound on scanned sub-folders (across all shares) |
| `-IncludeAdminShares` | off | Also analyse NTFS permissions of `C$`, `D$`, `ADMIN$` |
| `-Quick` | off | Skip the sub-folder scan and the scan of all firewall rules for ports 445/139 |
| `-NoZip` | off | Do not create the ZIP archive |
| `-OpenReport` | off | Open the HTML report at the end |

The script returns an object (`Folder`, `Report`, `Zip`, `Verdict`, `Score`, counts per severity),
so it can be used in automation:

```powershell
$r = .\Invoke-ShareAudit.ps1 -Quick
if ($r.Critical -or $r.High) { Send-MailMessage ... }
```

## Outputs

| File | Content |
|---|---|
| `report.html` | Self-contained report (no script, no external resource), printable |
| `findings.csv` | Findings with severity, category, target, detail, recommendation |
| `access_matrix.csv` | User × share: share level, NTFS level, effective level |
| `shares.csv`, `share_permissions.csv`, `ntfs_share_roots.csv` | Shares and their permissions |
| `subfolders_explicit_permissions.csv` | Sub-folders with explicit ACEs or blocked inheritance |
| `smb_sessions.csv`, `smb_open_files.csv` | Active sessions and open files |
| `local_users.csv`, `local_group_members.csv` | Local accounts and group membership |
| `firewall_smb_rules.csv`, `volumes.csv` | Firewall rules related to SMB, volumes |
| `audit.json` | Everything above + raw configuration, for diffing or tooling |
| `audit.log` | Collection log (with per-section errors) |

CSV files use the list separator of the current culture (`;` on French/Italian systems), so
they open directly in Excel.

> The results describe the security posture of the machine (accounts, permissions,
> weaknesses): treat them as **confidential**. `.gitignore` excludes them from the repository.

## Read-only guarantee

The script never changes the system: it only uses `Get-*` cmdlets, CIM queries, registry reads,
`secedit /export`, `auditpol /get`, `powercfg /query` and the `AuditQuerySystemPolicy` API.
The only writes are the result files in `-OutputPath` and a temporary export of the local security
policy (deleted immediately). The smoke test enforces this with a static analysis of the script
(no `Set-*`, `Grant-*`, `Remove-*`, `New-Smb*`, `icacls`, `net`, `reg`... calls).

## How the access matrix is computed

For each **enabled local account**, the script builds an approximation of its **network logon
token**: the user SID, *Everyone*, *Authenticated Users*, *Users*, *NETWORK* and every local group
it belongs to (directly or through a well-known identity). Members of *Administrators* lose that
group when **remote UAC filtering** applies (the default for local accounts other than the
built-in Administrator, unless `LocalAccountTokenFilterPolicy = 1`): this is why a local admin
often shows *None* on a share that only grants `Administrators`.

Effective right = **min(share-level right, NTFS right on the share root)**, with Deny entries
taken into account. Levels: *Full* (can change permissions / take ownership), *Change*
(write/delete), *Read*, *None*.

Limits: sub-folders with explicit permissions can differ (they are listed separately), domain or
Entra ID accounts are not evaluated, and complex/special NTFS rights are mapped to the closest level.

## Requirements

- Windows 10/11 or Windows Server 2016+ (SmbShare, NetSecurity, NetTCPIP, LocalAccounts modules)
- Windows PowerShell 5.1 or PowerShell 7
- Administrator rights for a complete audit

## Repository content

| Path | Role |
|---|---|
| `Invoke-ShareAudit.ps1` | The audit script |
| `Run-Audit.cmd` | Double-click launcher (UAC elevation + ExecutionPolicy Bypass for the process) |
| `docs/HARDENING-CHECKLIST.md` | Target configuration and remediation commands for a workgroup file-sharing PC |
| `tests/Invoke-SmokeTest.ps1` | Smoke test with simulated Windows cmdlets (runs on Linux/CI) |
| `tests/mocks/WinStubs/` | Simulated "PC-SRV01" office file server with good and bad practices |
| `.github/workflows/ci.yml` | CI: smoke test, PSScriptAnalyzer, Windows PowerShell 5.1 parsing, real run on a Windows runner |

## Tests

```powershell
pwsh ./tests/Invoke-SmokeTest.ps1
```

The smoke test parses every script, checks the read-only guarantee, runs the audit against the
simulated environment and verifies ~70 expectations (findings, absence of false positives on the
well-configured share, effective access matrix, report and ZIP structure, `-Quick` mode).
The CI also runs the script for real on a GitHub-hosted Windows runner against a temporary share.

## License

MIT
