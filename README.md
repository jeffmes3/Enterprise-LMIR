Enterprise IR: Lateral Movement Visibility (Enterprise-LMIR)
Open-source, single-file PowerShell collector that improves forensic visibility for suspected lateral movement across Windows endpoints and servers. Designed for enterprise IR teams, but safe to run on any Windows 10/11 and Server 2016/2019/2022 system with Windows PowerShell 5.1.
This project focuses on high-signal artifacts from common lateral movement channels (WinRM, RDP, SMB admin shares, service-based remote exec like PsExec/PDQ), plus correlation and scoring to quickly prioritize what to investigate.

What it detects
Remote access and lateral movement signals
Security 4624: inbound logons with LogonType 3/9/10 (network, new credentials, RDP)
ecurity 4624: inbound logons with LogonType 3/9/10 (network, new credentials, RDP)
Security 5140: admin share usage (\\C$, \\ADMIN$, \\IPC$)
WinRM Operational 91: WSMan shell/session activity
PowerShell Operational 4103/4104: PowerShell activity, including encoded/obfuscated patterns
Security 4688: process creation signals, including:
wsmprovhost.exe → cmd.exe/powershell.exe spawning
EncodedCommand / -enc / base64 patterns
System 7045: new service installs (PsExec-like, PDQ-like, UNC image paths)
Anti-evasion: Security 1102 and System 104 (event log cleared)

Registry forensics
HKLM: ...\WSMAN\SafeClientList (WinRM client IPs, typically up to ~10)
HKCU: ...\Terminal Server Client\Servers (RDP saved targets + username hints)
Active Directory correlation (best-effort)
On Domain Controllers, surfaces:
4768 / 4769 / 4776 (Kerberos TGT/TGS and NTLM auth) into the unified timeline for correlation with host activity.

Correlation and scoring
Normalizes artifacts into a unified timeline
Generates cases within a configurable time window (default ±10 min)
Computes a suspicion score and assigns severity:
LOW / MEDIUM / HIGH
Boosts scores for common combinations (e.g., 4624 + WinRM + process spawn)

Diagnostics (non-fatal)
The script includes a diagnostics pack that explains common “why did I miss data?” issues without breaking collection:
Missing/disabled/denied logs:
Security, System, WinRM Operational, PowerShell Operational
4688 coverage check (process creation auditing)
auditpol parsing (best-effort)
PowerShell logging policy indicators (registry)
Defender status awareness (best-effort)
EDR “presence” awareness (common service names)
UNC write test with SYSTEM/computer account guidance

Requirements
Windows PowerShell 5.1
Windows 10/11, Server 2016/2019/2022
For remote collection: WinRM enabled + firewall rules
For scheduling: local admin rights (and remote admin for remote scheduling)

Quick start
1) Download / place script
Put Enterprise-LMIR.ps1 on the machine you’ll use as the collector.

Example
mkdir C:\ProgramData\Lateralmovement -Force
copy .\Enterprise-LMIR.ps1 C:\ProgramData\Lateralmovement\
cd C:\ProgramData\Lateralmovement

Run interactively (wizard)
<powershell>
.\Enterprise-LMIR.ps1

The wizard will prompt you for:
Run mode (Standalone vs Remote)
Investigator mode (Quick vs Deep)
Output location (Local vs UNC)
Run once vs Schedule (Daily/Weekly/Monthly)
Start date/time for scheduling
Optional CredSSP for remoting
Optional “View current schedule” or “Run diagnostics only”

Usage examples (non-interactive)
Standalone quick triage (local output)
<powershell>
.\Enterprise-LMIR.ps1 -Mode Quick -OutputPath C:\ForensicReports -NonInteractive

Standalone deep forensic
<powershell>
.\Enterprise-LMIR.ps1 -Mode Deep -OutputPath C:\ForensicReports -NonInteractive

Remote collection (Kerberos, current credentials)
<powershell>
.\Enterprise-LMIR.ps1 -ComputerName PC01,SRV01 -Mode Quick -OutputPath \\IRSERVER\Share\LMReports -NonInteractive

Remote collection with alternate credentials
<powershell>
$cred = Get-Credential
.\Enterprise-LMIR.ps1 -ComputerName PC01,SRV01 -Credential $cred -Mode Deep -OutputPath \\IRSERVER\Share\LMReports -NonInteractive

Remote collection using CredSSP:Use only where your environment requires it and you understand the security implications
<powershell>
$cred = Get-Credential
.\Enterprise-LMIR.ps1 -ComputerName PC01,SRV01 -Credential $cred -UseCredSSP -Mode Quick -OutputPath \\IRSERVER\Share\LMReports -NonInteractive

Scheduling
Scheduling uses the Task Scheduler COM API and runs as SYSTEM (enterprise standard for IR collection).

Wizard path:
Run / Schedule → Daily/Weekly/Monthly
Prompts for Start Date and Start Time
Then choose:
schedule locally, or deploy + schedule on remote targets
View current schedule
In the wizard select:
“View current schedule”
This works for local schedules and remote schedules (if your account has access).

UNC output and SYSTEM permissions (important)
When a scheduled task runs as SYSTEM, it accesses network resources using the computer account:
Domain joined: DOMAIN\HOSTNAME$
Workgroup: local machine account (often cannot auth to remote shares without additional configuration)
If you write reports to a UNC share from scheduled tasks, grant both Share permissions and NTFS permissions to:
a group containing computer accounts, or
specific computer accounts DOMAIN\PC01$, DOMAIN\SRV01$, etc.
Recommended approach:
Create an AD group like IR-ReportWriters-Computers
Add endpoints/servers (computer objects) to the group
Grant Share + NTFS Modify to that group on the report share
The script also runs a best-effort UNC write test and reports failures in diagnostics.

Output structure
Each run creates a root folder like:
<OutputPath>\EnterpriseLMIR_YYYYMMDD_HHMMSS\

Inside, per-host folders:
...\EnterpriseLMIR_...\PC01\
...\EnterpriseLMIR_...\SRV01\

Each host folder includes:
Report.xls (Excel-readable HTML workbook)
EXECUTIVE_REPORT.txt
Many CSV/TXT files (timeline, cases, logs, registry artifacts, etc.)

Enterprise roll-up:
...\EnterpriseLMIR_...\_EnterpriseSummary\
  Enterprise_Report.xls
  EXECUTIVE_REPORT.txt
  Enterprise_Host_Summary.csv/.txt
  Enterprise_All_Cases.csv/.txt

Collector diagnostics:
...\EnterpriseLMIR_...\_Diagnostics_CollectorHost\
  Diagnostics_LogAccess.*
  Diagnostics_AuditPol.*
  Diagnostics_PSLoggingGPO.*
  Diagnostics_Defender_EDR_Awareness.*

  Interpreting results
Start here:
EXECUTIVE_REPORT.txt (per host)
_EnterpriseSummary\EXECUTIVE_REPORT.txt (overall)
Then review:
Correlated_Cases.csv (cases with severity + score)
Unified_Timeline.csv (high-signal event stream)
Common patterns that strongly suggest lateral movement:
4624 (type 3/9/10) + WinRM 91 + 4688 spawn from wsmprovhost
4624 + 5140 admin share access + 7045 service install
PowerShell 4104 with encoded hints around the time of remote logons

Recommended Windows auditing baseline (high value)
For best results, enable:
Security auditing for:
Logon (4624)
Object access for shares (5140)
Process creation (4688)
Include command line in 4688 (GPO: “Include command line in process creation events”)
PowerShell Operational logging:
Script Block Logging (4104)
Module Logging (4103)
WinRM Operational logging enabled
The script detects common gaps and reports them in diagnostics

OpSec and safety
This tool is designed for defensive incident response and forensics.It does not exploit, scan, or modify endpoint security settings. It collects telemetry from event logs and registry to increase IR visibility.

contributing
PRs and issues welcome. Helpful contributions include:
Additional event IDs and normalized fields
Improved correlation heuristics (keeping false positives low)
Additional enterprise diagnostics (GPO/audit settings)
Test matrix across Windows versions and configurations

Enterprise executive report
Machines: 12
Cases: 6 (HIGH=2, MEDIUM=3)
Top Cases
CASE-004 | HIGH | Score 15 | MachineName=SRV-APP01 | Logon4624, WinRM91, ProcSpawn4688, PowerShell
CASE-001 | HIGH | Score 13 | MachineName=PC-019   | Logon4624, AdminShare5140, Service7045
...

Host executive report
MachineName: SRV-APP01
Mode: Quick  DaysBack: 7
Cases: 2 (HIGH=1, MEDIUM=1)
CASE-002 | HIGH | Score 15 | WinRM91, Logon4624, ProcSpawn4688, PowerShell

FAQ

Why no RDP client event IDs 1024/1102?
Those are client-side RDP log channels that vary by configuration and aren’t consistently enabled across all environments. This project focuses on high-coverage logs by default. You can add them as an optional module if your environment collects them consistently.

Why are some logs empty?
You might be missing auditing policy, the log may be disabled, or you may not have permissions. The Diagnostics section explains what is missing and why.

Does it work in workgroups?
Standalone collection works. Remote collection and UNC writing from SYSTEM may require additional configuration because workgroup machines don’t authenticate to shares using a domain computer account.

