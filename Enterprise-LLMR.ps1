#Requires -Version 5.1
<#
===============================================================================
Enterprise IR: Lateral Movement Visibility (Open Source)
Script: Enterprise-LMIR.ps1
Version: 6.0
License: MIT
Compatibility: Windows PowerShell 5.1 (Windows 10/11, Server 2016/2019/2022)
Targets: Workgroup + Domain-joined environments
Remoting: WinRM/PowerShell Remoting (Kerberos preferred), optional CredSSP
Outputs: Per-endpoint local + optional UNC central share

===============================================================================
FEATURES (what this script does)

RUN MODES
- Standalone: collect on this machine
- Remote: collect from this machine via WinRM (Invoke-Command)
- Remote scheduling: deploy script + create scheduled task on targets

INVESTIGATOR MODES
- Quick triage: 7 days, reduced volume
- Deep forensic: 30 days, higher volume

SCHEDULING (HARDENED)
- Run once now
- Schedule Daily / Weekly / Monthly
- Prompts for Start Date + Start Time
- Uses Task Scheduler COM API (no schtasks fragility)
- Runs task as SYSTEM (for enterprise IR)
- View current schedule (local or remote)

DIAGNOSTICS (NON-FATAL, DOES NOT BREAK COLLECTION)
- Log checks: missing vs disabled vs access denied:
  Security, System, WinRM Operational, PowerShell Operational
- 4688 coverage check + audit policy parsing (auditpol)
- PowerShell logging GPO indicators (registry)
- UNC write test + enterprise guidance for computer account permissions
- Defender status awareness (Get-MpComputerStatus if present)
- EDR awareness: checks common EDR services (best-effort)

DETECTION ENGINE (FORENSIC VISIBILITY)
- Security 4624 remote-ish logons: LogonType 3/9/10
- Security 5140 admin share usage: \\C$, \\ADMIN$, \\IPC$
- WinRM Operational 91
- PowerShell Operational 4103/4104 + encoded/obfuscation hints
- System 7045 service installs (PsExec/PDQ/UNC hints)
- Security 4688 process creation: wsmprovhost -> cmd/powershell; encoded hints
- Anti-evasion: Security 1102, System 104 (log cleared)
- Registry forensics:
  HKLM WSMAN SafeClientList (WinRM client IPs; up to ~10)
  HKCU RDP Servers list
- Active Directory lateral movement correlation (best-effort):
  On DCs: 4768/4769/4776 surfaced into timeline for correlation

CORRELATION + SCORING
- Unified timeline with score increments per indicator
- Case generation within a time window (default +/- 10 minutes)
- Severity LOW/MEDIUM/HIGH

REPORTING
- Per host: CSV + TXT + Excel-readable XLS (HTML)
- Enterprise roll-up: host summary, all cases, executive report
===============================================================================

SECURITY / ENTERPRISE NOTES
- Remote scheduled tasks run as SYSTEM. If writing to UNC, grant SHARE+NTFS write to:
  DOMAIN\COMPUTER$ accounts or a group containing computer accounts.
- 4688 requires audit policy: "Process Creation" (and ideally command line inclusion).
- Some logs may be unavailable by policy. Diagnostics will explain why without failing.

===============================================================================
#>

param(
    [ValidateSet("Quick","Deep")]
    [string]$Mode = "Quick",

    [int]$DaysBack = 7,
    [int]$MaxEventsPerLog = 5000,
    [int]$CaseWindowMinutes = 10,

    [string]$OutputPath = "C:\ForensicReports",

    [string[]]$ComputerName,
    [pscredential]$Credential,

    [switch]$UseCredSSP,
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================== Globals ==============================
$ScriptVersion = "6.0"
$TaskName      = "EnterpriseIR_LateralMovementCollector"
$RunStamp      = Get-Date -Format "yyyyMMdd_HHmmss"

# ============================== Safe helpers ==============================
function Count-Safe { param($o) if ($null -eq $o) { 0 } else { @($o).Count } }
function Safe-Date  { param($d) if ($null -eq $d) { Get-Date } else { try { [datetime]$d } catch { Get-Date } } }

function Safe-MkDir {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    } catch {}
}

function Is-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Html-Encode {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    $Text = $Text -replace '&','&amp;'
    $Text = $Text -replace '<','&lt;'
    $Text = $Text -replace '>','&gt;'
    $Text = $Text -replace '"','&quot;'
    $Text = $Text -replace "'","&#39;"
    return $Text
}

function Export-CsvTxt {
    param([string]$OutDir,[string]$Name,$Rows)
    $csv = Join-Path $OutDir ($Name + ".csv")
    $txt = Join-Path $OutDir ($Name + ".txt")
    $arr = @($Rows)
    try {
        if ((Count-Safe $arr) -gt 0) {
            $arr | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
            $arr | Format-List * | Out-String -Width 4096 | Out-File -Encoding UTF8 -FilePath $txt
        } else {
            "" | Out-File -Encoding UTF8 -FilePath $csv
            "No data." | Out-File -Encoding UTF8 -FilePath $txt
        }
    } catch {
        try { ("Report write failed: " + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $txt } catch {}
    }
}

function ConvertTo-HtmlTable {
    param($Rows,[string]$Title)
    $safeTitle = Html-Encode $Title
    $arr = @($Rows)
    if ((Count-Safe $arr) -eq 0) { return "<h2>$safeTitle</h2><p>No data.</p>" }
    return ($arr | Select-Object * | ConvertTo-Html -Fragment -PreContent "<h2>$safeTitle</h2>")
}

function Export-XlsHtmlReport {
    param([string]$OutDir,[string]$FileName,[hashtable]$Sections)
    $path = Join-Path $OutDir $FileName

    $head = @"
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
body { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }
h1 { font-size: 18px; }
h2 { font-size: 14px; margin-top: 18px; }
table { border-collapse: collapse; margin: 8px 0; width: 100%; }
th, td { border: 1px solid #ccc; padding: 4px 6px; vertical-align: top; }
th { background: #f3f3f3; }
</style>
</head>
<body>
<h1>Enterprise IR Lateral Movement Report</h1>
"@

    $body = ""
    foreach ($k in $Sections.Keys) { $body += (ConvertTo-HtmlTable -Rows $Sections[$k] -Title $k) }
    $tail = "</body></html>"

    try { ($head + $body + $tail) | Out-File -Encoding UTF8 -FilePath $path } catch {}
    return $path
}

# ============================== XML safe parsing ==============================
function Get-XmlNodeText {
    param($Node)
    if ($null -eq $Node) { return "" }
    try {
        $t = $Node.InnerText
        if (-not [string]::IsNullOrWhiteSpace($t)) { return $t }
    } catch {}
    try {
        $p = $Node.PSObject.Properties["#text"]
        if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
    } catch {}
    try { return [string]$Node } catch { return "" }
}

function Convert-EventToHashtable {
    param($Event)
    $result = @{}
    try {
        $xml = [xml]$Event.ToXml()
        if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
            foreach ($node in $xml.Event.EventData.Data) {
                if ($node -and $node.Name) { $result[$node.Name] = (Get-XmlNodeText $node) }
            }
        }
        if ($xml.Event.UserData) {
            foreach ($node in $xml.Event.UserData.SelectNodes(".//*")) {
                if ($node -and $node.Name -and -not $result.ContainsKey($node.Name)) {
                    $result[$node.Name] = (Get-XmlNodeText $node)
                }
            }
        }
    } catch {}
    return $result
}

function Get-WinEventsFast {
    param([string]$LogName,[int[]]$Ids,[datetime]$StartTime,[int]$MaxEvents)
    try {
        $fh = @{ LogName=$LogName; Id=$Ids; StartTime=$StartTime }
        $ev = Get-WinEvent -FilterHashtable $fh -ErrorAction Stop
        if ((Count-Safe $ev) -gt $MaxEvents) { $ev = $ev | Select-Object -First $MaxEvents }
        return @($ev)
    } catch { return @() }
}

# ============================== Detection helpers ==============================
function Detect-EncodedPowerShell {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $patterns = @(
        "(?i)\s-enc(\s|$)",
        "(?i)\s-encodedcommand(\s|$)",
        "(?i)frombase64string\(",
        "(?i)\biex\s*\(",
        "(?i)invoke-expression",
        "(?i)downloadstring\(",
        "(?i)new-object\s+net\.webclient",
        "(?i)invoke-webrequest",
        "(?i)start-bitstransfer"
    )
    foreach ($p in $patterns) { if ($Text -match $p) { return $true } }
    return $false
}

function Add-TimelineRow {
    param(
        $Timeline,$Time,
        [string]$Type,[string]$User,[string]$SourceIP,[string]$Destination,
        [string]$Details,[int]$ScoreAdd,[string]$Evidence
    )
    $Timeline += [pscustomobject]@{
        Timestamp   = (Safe-Date $Time)
        MachineName = $env:COMPUTERNAME
        Type        = $Type
        User        = $User
        SourceIP    = $SourceIP
        Destination = $Destination
        Details     = $Details
        ScoreAdd    = [int]$ScoreAdd
        Evidence    = $Evidence
    }
    return ,$Timeline
}

# ============================== Diagnostics ==============================
function Test-EventLogAccess {
    param([string]$LogName)
    $status = "OK"
    $note = ""

    try {
        $l = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        if (-not $l.IsEnabled) {
            return [pscustomobject]@{ Log=$LogName; Status="DISABLED"; Note="Log exists but disabled." }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "(?i)cannot find.*log|requested log does not exist|no such file") {
            $status = "MISSING"
        } elseif ($msg -match "(?i)access is denied|unauthorized|permission") {
            $status = "DENIED"
        } else {
            $status = "ERROR"
        }
        return [pscustomobject]@{ Log=$LogName; Status=$status; Note=$msg }
    }

    try {
        Get-WinEvent -FilterHashtable @{ LogName=$LogName } -MaxEvents 1 -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ Log=$LogName; Status="OK"; Note="" }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "(?i)access is denied|unauthorized|permission") {
            return [pscustomobject]@{ Log=$LogName; Status="DENIED"; Note=$msg }
        }
        return [pscustomobject]@{ Log=$LogName; Status="ERROR"; Note=$msg }
    }
}

function Get-AuditPolicySummary {
    $rows = @()
    try {
        $out = auditpol /get /subcategory:* 2>$null
        foreach ($line in $out) {
            if ($line -match "^\s*([A-Za-z0-9 \-\(\)\/]+?)\s{2,}(No Auditing|Success|Failure|Success and Failure)\s*$") {
                $rows += [pscustomobject]@{ Subcategory=$matches[1].Trim(); Setting=$matches[2].Trim() }
            }
        }
    } catch {}
    return $rows
}

function Get-PSLoggingGpoSummary {
    $rows = @()
    $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    try {
        if (Test-Path $base) {
            $sbk = Join-Path $base "ScriptBlockLogging"
            $mlk = Join-Path $base "ModuleLogging"
            $trk = Join-Path $base "Transcription"

            if (Test-Path $sbk) {
                $p = Get-ItemProperty -Path $sbk -ErrorAction SilentlyContinue
                $rows += [pscustomobject]@{ Setting="ScriptBlockLogging.EnableScriptBlockLogging"; Value=$p.EnableScriptBlockLogging }
                $rows += [pscustomobject]@{ Setting="ScriptBlockLogging.EnableScriptBlockInvocationLogging"; Value=$p.EnableScriptBlockInvocationLogging }
            } else { $rows += [pscustomobject]@{ Setting="ScriptBlockLogging"; Value="NotConfigured" } }

            if (Test-Path $mlk) {
                $p = Get-ItemProperty -Path $mlk -ErrorAction SilentlyContinue
                $rows += [pscustomobject]@{ Setting="ModuleLogging.EnableModuleLogging"; Value=$p.EnableModuleLogging }
            } else { $rows += [pscustomobject]@{ Setting="ModuleLogging"; Value="NotConfigured" } }

            if (Test-Path $trk) {
                $p = Get-ItemProperty -Path $trk -ErrorAction SilentlyContinue
                $rows += [pscustomobject]@{ Setting="Transcription.EnableTranscripting"; Value=$p.EnableTranscripting }
                $rows += [pscustomobject]@{ Setting="Transcription.OutputDirectory"; Value=$p.OutputDirectory }
            } else { $rows += [pscustomobject]@{ Setting="Transcription"; Value="NotConfigured" } }
        } else {
            $rows += [pscustomobject]@{ Setting="PowerShellPolicyBase"; Value="NotConfigured" }
        }
    } catch {}
    return $rows
}

function Get-DefenderEdrAwareness {
    $rows = @()

    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        if ($svc) { $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="Service"; Value=($svc.Status.ToString()) } }
        else { $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="Service"; Value="NotFound" } }
    } catch {}

    try {
        $cmd = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($cmd) {
            $s = Get-MpComputerStatus
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="AMServiceEnabled"; Value=$s.AMServiceEnabled }
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="RealTimeProtectionEnabled"; Value=$s.RealTimeProtectionEnabled }
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="AntispywareEnabled"; Value=$s.AntispywareEnabled }
        } else {
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="Get-MpComputerStatus"; Value="Unavailable" }
        }
    } catch {}

    try {
        $tp = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        if (Test-Path $tp) {
            $p = Get-ItemProperty -Path $tp -ErrorAction SilentlyContinue
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="TamperProtectionValue"; Value=$p.TamperProtection }
        } else {
            $rows += [pscustomobject]@{ Product="Microsoft Defender"; Signal="TamperProtectionValue"; Value="Unknown" }
        }
    } catch {}

    $edrCandidates = @(
        "CSFalconService","SentinelAgent","CylanceSvc","CbDefense","CarbonBlack",
        "TaniumClient","xagt","ElasticAgent"
    )
    foreach ($n in $edrCandidates) {
        try {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            if ($s) { $rows += [pscustomobject]@{ Product="EDR"; Signal="ServiceDetected"; Value=($n + " (" + $s.Status + ")") } }
        } catch {}
    }
    if ((Count-Safe $rows) -eq 0) { $rows += [pscustomobject]@{ Product="EDR"; Signal="ServiceDetected"; Value="NoneDetected" } }
    return $rows
}

function Invoke-DiagnosticsPack {
    param([string]$OutDir,[string]$OutputPathForUNCCheck)

    $logs = @(
        "Security",
        "System",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-PowerShell/Operational"
    )

    $logAccess = @()
    foreach ($l in $logs) { $logAccess += (Test-EventLogAccess -LogName $l) }

    $has4688 = $false
    try { Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4688 } -MaxEvents 1 -ErrorAction Stop | Out-Null; $has4688 = $true } catch { $has4688 = $false }
    $logAccess += [pscustomobject]@{
        Log="Security/4688"
        Status=(if ($has4688) { "OK" } else { "MISSING_OR_DISABLED" })
        Note="If missing: enable Audit Process Creation + include command line."
    }

    # UNC test + guidance
    if ($OutputPathForUNCCheck -match "^(?i)\\\\") {
        $ok = $false
        $note = ""
        try {
            $testFile = Join-Path $OutputPathForUNCCheck ("_lmtest_" + [guid]::NewGuid().ToString() + ".tmp")
            "test" | Out-File -Encoding ASCII -FilePath $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            $ok = $true
        } catch {
            $ok = $false
            $note = $_.Exception.Message
        }
        if ($ok) {
            $logAccess += [pscustomobject]@{ Log="UNC"; Status="OK"; Note="Write test succeeded." }
        } else {
            $logAccess += [pscustomobject]@{
                Log="UNC"; Status="DENIED"
                Note=("Write test failed. If scheduled as SYSTEM, grant SHARE+NTFS write to computer accounts (DOMAIN\HOST$) or a group. Details: " + $note)
            }
        }
    }

    $auditpol = Get-AuditPolicySummary
    $psgpo    = Get-PSLoggingGpoSummary
    $defedr   = Get-DefenderEdrAwareness

    if ($OutDir) {
        Safe-MkDir $OutDir
        Export-CsvTxt $OutDir "Diagnostics_LogAccess" $logAccess
        Export-CsvTxt $OutDir "Diagnostics_AuditPol"  $auditpol
        Export-CsvTxt $OutDir "Diagnostics_PSLoggingGPO" $psgpo
        Export-CsvTxt $OutDir "Diagnostics_Defender_EDR_Awareness" $defedr
    }

    return @{
        LogAccess=$logAccess
        AuditPol=$auditpol
        PSLoggingGPO=$psgpo
        DefenderEDR=$defedr
    }
}

# ============================== Task Scheduler COM (PS 5.1 safe) ==============================
function Get-TaskServiceCom {
    param([string]$Target = $null)
    $svc = New-Object -ComObject "Schedule.Service"
    if ([string]::IsNullOrWhiteSpace($Target)) { $svc.Connect() } else { $svc.Connect($Target) }
    return $svc
}

function Remove-TaskIfExistsCom {
    param($RootFolder,[string]$Name)
    try { $RootFolder.DeleteTask($Name, 0) } catch { }
}

function Convert-WeekdayToMask {
    param([string]$Dow)
    switch ($Dow.ToUpper()) {
        "SUN" { 1 } "MON" { 2 } "TUE" { 4 } "WED" { 8 } "THU" { 16 } "FRI" { 32 } "SAT" { 64 }
        default { 0 }
    }
}

function Read-StartDateTime {
    while ($true) {
        $dateInput = Read-Host "Enter START DATE (YYYY-MM-DD)"
        $timeInput = Read-Host "Enter START TIME (HH:mm 24-hour format, e.g., 02:00)"
        try {
            $d  = [datetime]::ParseExact($dateInput, "yyyy-MM-dd", $null)
            $t  = [datetime]::ParseExact($timeInput, "HH:mm", $null)
            $dt = Get-Date -Year $d.Year -Month $d.Month -Day $d.Day -Hour $t.Hour -Minute $t.Minute -Second 0
            Write-Host ("StartBoundary: {0}" -f $dt.ToString("yyyy-MM-dd HH:mm:ss"))
            $ok = Read-Host "Confirm? (y/n)"
            if ($ok -match "^(y|yes)$") { return $dt }
        } catch {
            Write-Host "Invalid date/time format." -ForegroundColor Red
        }
    }
}

function Register-TaskCom {
    param(
        [string]$Target,
        [string]$TaskName,
        [ValidateSet("Daily","Weekly","Monthly")] [string]$Frequency,
        [datetime]$StartDateTime,
        [string]$ScriptPathToRun,
        [string]$ScriptArgs
    )

    $svc  = Get-TaskServiceCom -Target $Target
    $root = $svc.GetFolder("\")

    Remove-TaskIfExistsCom -RootFolder $root -Name $TaskName

    $task = $svc.NewTask(0)
    $task.RegistrationInfo.Description = "Enterprise IR Lateral Movement Visibility"
    $task.Settings.Enabled = $true
    $task.Settings.StartWhenAvailable = $true
    $task.Settings.Hidden = $false
    $task.Settings.DisallowStartIfOnBatteries = $false
    $task.Settings.StopIfGoingOnBatteries = $false

    $task.Principal.UserId = "SYSTEM"
    $task.Principal.LogonType = 5
    $task.Principal.RunLevel = 1

    $triggerType = if ($Frequency -eq "Daily") { 2 } elseif ($Frequency -eq "Weekly") { 3 } else { 4 }
    $trigger = $task.Triggers.Create($triggerType)
    $trigger.StartBoundary = $StartDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss")

    if ($Frequency -eq "Daily") {
        $trigger.DaysInterval = 1
    } elseif ($Frequency -eq "Weekly") {
        $dow = Read-Host "Enter weekday (MON,TUE,WED,THU,FRI,SAT,SUN)"
        $mask = Convert-WeekdayToMask $dow
        if ($mask -eq 0) { throw "Invalid weekday." }
        $trigger.WeeksInterval = 1
        $trigger.DaysOfWeek = $mask
    } else {
        $dom = Read-Host "Enter day of month (1-31)"
        if (-not ($dom -match "^(?:[1-9]|[12][0-9]|3[01])$")) { throw "Invalid day of month." }
        $trigger.DaysOfMonth = @([int]$dom)
        $trigger.MonthsOfYear = 4095
    }

    $action = $task.Actions.Create(0)
    $action.Path = "powershell.exe"
    $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPathToRun`" $ScriptArgs"

    $root.RegisterTaskDefinition($TaskName, $task, 6, "SYSTEM", $null, 5) | Out-Null
}

function Get-TaskInfoCom {
    param([string]$Target, [string]$TaskName)

    $svc = Get-TaskServiceCom -Target $Target
    $root = $svc.GetFolder("\")

    $t = $null
    try { $t = $root.GetTask($TaskName) } catch { return $null }

    $def = $t.Definition
    $triggers = @($def.Triggers)
    $first = if ((Count-Safe $triggers) -gt 0) { $triggers[0] } else { $null }

    $freq = ""
    $startBoundary = ""
    if ($first) {
        $startBoundary = $first.StartBoundary
        switch ($first.Type) {
            2 { $freq="Daily" }
            3 { $freq="Weekly" }
            4 { $freq="Monthly" }
            default { $freq="Other" }
        }
    }

    # PS 5.1 safe: compute outside object literal
    $lastRun = $null
    $nextRun = $null
    $lastResult = $null
    try { $lastRun = $t.LastRunTime } catch {}
    try { $nextRun = $t.NextRunTime } catch {}
    try { $lastResult = $t.LastTaskResult } catch {}

    return [pscustomobject]@{
        Target        = (if ([string]::IsNullOrWhiteSpace($Target)) { $env:COMPUTERNAME } else { $Target })
        TaskName      = $TaskName
        Enabled       = $def.Settings.Enabled
        Frequency     = $freq
        StartBoundary = $startBoundary
        LastRunTime   = $lastRun
        NextRunTime   = $nextRun
        LastResult    = $lastResult
    }
}

function View-Schedule {
    param([string[]]$Targets)
    $rows = @()

    if ((Count-Safe $Targets) -eq 0) {
        $i = Get-TaskInfoCom -Target $null -TaskName $TaskName
        if ($i) { $rows += $i }
    } else {
        foreach ($t in $Targets) {
            try {
                $i = Get-TaskInfoCom -Target $t -TaskName $TaskName
                if ($i) { $rows += $i }
                else { $rows += [pscustomobject]@{ Target=$t; TaskName=$TaskName; Enabled=$false; Frequency="NotFound"; StartBoundary=""; LastRunTime=$null; NextRunTime=$null; LastResult=$null } }
            } catch {
                $rows += [pscustomobject]@{ Target=$t; TaskName=$TaskName; Enabled=$false; Frequency="ERROR"; StartBoundary=$_.Exception.Message; LastRunTime=$null; NextRunTime=$null; LastResult=$null }
            }
        }
    }

    if ((Count-Safe $rows) -eq 0) { Write-Host "No schedule found." -ForegroundColor Yellow; return }

    Write-Host ""
    Write-Host "Current Schedule"
    Write-Host "----------------"
    $rows | Sort-Object Target | Format-Table -AutoSize
}

function Deploy-ScriptToRemote {
    param([string]$Target,[pscredential]$Credential,[string]$LocalScriptPath,[string]$RemoteScriptPath,[switch]$UseCredSSP)

    $remoteDir = Split-Path -Parent $RemoteScriptPath
    $sess = $null
    try {
        $sessParams = @{ ComputerName=$Target; ErrorAction="Stop" }
        if ($Credential) { $sessParams.Credential = $Credential }
        if ($UseCredSSP) { $sessParams.Authentication = "CredSSP" }
        $sess = New-PSSession @sessParams

        Invoke-Command -Session $sess -ScriptBlock {
            param($d)
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        } -ArgumentList $remoteDir -ErrorAction Stop

        Copy-Item -ToSession $sess -Path $LocalScriptPath -Destination $RemoteScriptPath -Force -ErrorAction Stop
    } finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }
}

# ============================== AD correlation (best-effort) ==============================
function Get-ADCorrelationSignals {
    param([datetime]$StartTime,[int]$MaxEvents)
    $rows = @()
    $ids = @(4768,4769,4776)
    $ev = @()
    try { $ev = Get-WinEventsFast -LogName "Security" -Ids $ids -StartTime $StartTime -MaxEvents $MaxEvents } catch { $ev = @() }
    foreach ($e in $ev) {
        $d = Convert-EventToHashtable $e
        $rows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            EventId     = $e.Id
            TargetUser  = $d["TargetUserName"]
            ServiceName = $d["ServiceName"]
            IpAddress   = $d["IpAddress"]
            Workstation = $d["Workstation"]
            Notes       = "AD auth event (likely DC-side if this host is a DC)"
        }
    }
    return $rows
}

# ============================== Core collection engine ==============================
function Invoke-LMCollectionCore {
    param(
        [ValidateSet("Quick","Deep")] [string]$Mode,
        [int]$DaysBack,
        [int]$MaxEventsPerLog,
        [int]$CaseWindowMinutes
    )

    if ($Mode -eq "Deep") {
        $DaysBack = 30
        $MaxEventsPerLog = [Math]::Max($MaxEventsPerLog, 20000)
    } else {
        $DaysBack = 7
        $MaxEventsPerLog = [Math]::Min($MaxEventsPerLog, 3000)
    }

    $startTime = (Get-Date).AddDays(-$DaysBack)

    $Timeline = @()
    $Findings = @()

    $sec4624Rows = @()
    $share5140Rows = @()
    $winrmRows = @()
    $psRows = @()
    $svc7045Rows = @()
    $proc4688Rows = @()
    $regRows = @()
    $adRows = @()

    # Anti-evasion
    foreach ($e in @(Get-WinEventsFast "Security" @(1102) $startTime $MaxEventsPerLog)) {
        $Findings += [pscustomobject]@{ Category="AntiEvasion"; Indicator="Security log cleared (1102)"; TimeCreated=$e.TimeCreated; Severity="High" }
        $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "AntiEvasion" "" "" "" "Security log cleared (1102)" 6 "Security/1102"
    }
    foreach ($e in @(Get-WinEventsFast "System" @(104) $startTime $MaxEventsPerLog)) {
        $Findings += [pscustomobject]@{ Category="AntiEvasion"; Indicator="Event log cleared (System 104)"; TimeCreated=$e.TimeCreated; Severity="Medium" }
        $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "AntiEvasion" "" "" "" "Event log cleared (System 104)" 4 "System/104"
    }

    # 4624
    foreach ($e in @(Get-WinEventsFast "Security" @(4624) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $lt = $d["LogonType"]
        if ($lt -notin @("3","9","10")) { continue }

        $user = ("{0}\{1}" -f $d["TargetDomainName"], $d["TargetUserName"]).Trim("\")
        $ip   = $d["IpAddress"]

        $score = 2
        if ($lt -eq "10") { $score += 2 }
        if ($lt -eq "9")  { $score += 2 }
        if ($ip -and $ip -notin @("-","::1","127.0.0.1","0.0.0.0")) { $score += 1 }

        $sec4624Rows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            LogonType   = $lt
            User        = $user
            SourceIP    = $ip
            Workstation = $d["WorkstationName"]
            AuthPackage = $d["AuthenticationPackageName"]
            ProcessName = $d["ProcessName"]
        }

        $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "Logon4624" $user $ip "" ("4624 LT={0}" -f $lt) $score "Security/4624"
    }

    # 5140 admin shares
    $adminShareRegex = '(?i)\\\\(c\$|admin\$|ipc\$)$'
    foreach ($e in @(Get-WinEventsFast "Security" @(5140) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $shareName = $d["ShareName"]
        if ([string]::IsNullOrWhiteSpace($shareName)) { continue }
        if ($shareName -notmatch $adminShareRegex) { continue }

        $subject = ("{0}\{1}" -f $d["SubjectDomainName"], $d["SubjectUserName"]).Trim("\")
        $ip = $d["IpAddress"]

        $share5140Rows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            Subject     = $subject
            SourceIP    = $ip
            ShareName   = $shareName
            Target      = $d["RelativeTargetName"]
        }

        $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "AdminShare5140" $subject $ip "" ("Share={0}" -f $shareName) 3 "Security/5140"
    }

    # WinRM 91
    foreach ($e in @(Get-WinEventsFast "Microsoft-Windows-WinRM/Operational" @(91) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $ip = $d["IpAddress"]
        $user = $d["User"]

        $winrmRows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            User        = $user
            SourceIP    = $ip
            Message     = (($e.Message -replace "`r`n"," ") | Select-Object -First 1)
        }

        $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "WinRM91" $user $ip "" "WinRM WSMan session/shell" 3 "WinRM/91"
    }

    # PowerShell 4103/4104
    foreach ($e in @(Get-WinEventsFast "Microsoft-Windows-PowerShell/Operational" @(4103,4104) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $sb = $d["ScriptBlockText"]
        $cl = $d["CommandLine"]
        $msg = ($e.Message -replace "`r`n"," ")

        $enc = Detect-EncodedPowerShell ($sb + " " + $cl + " " + $msg)

        $score = 0
        if ($e.Id -eq 4104) { $score += 2 }
        if ($enc) { $score += 4 }

        $short = $sb
        if ($short -and $short.Length -gt 1500) { $short = $short.Substring(0,1500) + "…" }

        $psRows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            EventId     = $e.Id
            EncodedHints= $enc
            Path        = $d["Path"]
            ScriptBlockText_Short = $short
        }

        if ($score -gt 0) {
            $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "PowerShell" "" "" "" ("PS {0} EncodedHints={1}" -f $e.Id, $enc) $score "PS/4103,4104"
        }
    }

    # System 7045
    foreach ($e in @(Get-WinEventsFast "System" @(7045) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $svcName = $d["ServiceName"]
        $imgPath = $d["ImagePath"]

        $hints = @()
        $score = 0
        if ($svcName -match "(?i)psexesvc|psexec|paexec") { $hints += "PsExec-like"; $score += 6 }
        if ($imgPath -match "(?i)psexec|psexesvc|paexec") { $hints += "ImagePath mentions PsExec"; $score += 4 }
        if ($svcName -match "(?i)pdq") { $hints += "PDQ-like"; $score += 3 }
        if ($imgPath -match "\\\\") { $hints += "UNC in ImagePath"; $score += 2 }

        $svc7045Rows += [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            ServiceName = $svcName
            DisplayName = $d["DisplayName"]
            ImagePath   = $imgPath
            AccountName = $d["AccountName"]
            Hints       = ($hints -join "; ")
        }

        if ($score -gt 0) {
            $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "Service7045" "" "" "" ("New service: {0} ({1})" -f $svcName, ($hints -join ", ")) $score "System/7045"
        }
    }

    # Security 4688
    foreach ($e in @(Get-WinEventsFast "Security" @(4688) $startTime $MaxEventsPerLog)) {
        $d = Convert-EventToHashtable $e
        $new    = $d["NewProcessName"]
        $parent = $d["ParentProcessName"]
        $cmd    = $d["CommandLine"]
        $usr    = ("{0}\{1}" -f $d["SubjectDomainName"], $d["SubjectUserName"]).Trim("\")

        $match = $false
        $score = 0
        $hints = @()

        if ($parent -match "(?i)wsmprovhost\.exe" -and $new -match "(?i)powershell\.exe|cmd\.exe") {
            $match = $true; $score += 6; $hints += "wsmprovhost -> cmd/powershell"
        }
        if (Detect-EncodedPowerShell $cmd) {
            $match = $true; $score += 4; $hints += "encoded/LOLBAS hints"
        }

        if ($match) {
            $proc4688Rows += [pscustomobject]@{
                TimeCreated = $e.TimeCreated
                User        = $usr
                Parent      = $parent
                NewProcess  = $new
                CommandLine = $cmd
                Hints       = ($hints -join "; ")
            }
            $Timeline = Add-TimelineRow $Timeline $e.TimeCreated "ProcSpawn4688" $usr "" "" ("{0} -> {1}" -f $parent, $new) $score "Security/4688"
        }
    }

    # Registry: WinRM SafeClientList
    $wsmanKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\SafeClientList"
    if (Test-Path -LiteralPath $wsmanKey) {
        $item = $null
        try { $item = Get-Item -LiteralPath $wsmanKey -ErrorAction SilentlyContinue } catch { $item = $null }
        if ($item) {
            $names = @()
            try { $names = @($item.GetValueNames()) } catch { $names = @() }
            foreach ($vn in $names) {
                $val = $null
                try { $val = $item.GetValue($vn) } catch { $val = $null }
                $regRows += [pscustomobject]@{ Artifact="WinRM SafeClientList"; KeyPath=$wsmanKey; ValueName=$vn; ValueData=$val }
                $Timeline = Add-TimelineRow $Timeline (Get-Date) "Registry" "" (($val|Out-String).Trim()) "" "SafeClientList client IP" 2 "Registry/SafeClientList"
            }
        }
    } else {
        $regRows += [pscustomobject]@{ Artifact="WinRM SafeClientList"; Note="Key not present." }
    }

    # Registry: RDP Servers
    $rdpKey = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers"
    if (Test-Path -LiteralPath $rdpKey) {
        $kids = @()
        try { $kids = @(Get-ChildItem -LiteralPath $rdpKey -ErrorAction SilentlyContinue) } catch { $kids = @() }
        foreach ($sk in $kids) {
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue } catch { $p = $null }
            $hint = $null
            if ($p) {
                try { $hint = $p.UsernameHint } catch { $hint = $null }
            }
            $regRows += [pscustomobject]@{ Artifact="RDP Saved Server"; KeyPath=$sk.PSPath; Server=$sk.PSChildName; UsernameHint=$hint }
        }
    }

    # AD correlation signals (DC-side best-effort)
    $adRows = Get-ADCorrelationSignals -StartTime $startTime -MaxEvents $MaxEventsPerLog
    foreach ($r in @($adRows)) {
        $Timeline = Add-TimelineRow $Timeline $r.TimeCreated ("AD-" + $r.EventId) ($r.TargetUser) ($r.IpAddress) ($r.ServiceName) "AD auth event" 2 ("Security/" + $r.EventId)
    }

    # Correlation cases
    $timelineSorted = @($Timeline | Sort-Object Timestamp)
    $cases = @()
    $caseId = 0

    $seedTypes = @("Logon4624","WinRM91","AdminShare5140","Service7045","ProcSpawn4688","PowerShell","AntiEvasion","Registry")
    $seeds = @($timelineSorted | Where-Object { $seedTypes -contains $_.Type })

    foreach ($s in $seeds) {
        $seedTime = Safe-Date $s.Timestamp
        $wStart = $seedTime.AddMinutes(-$CaseWindowMinutes)
        $wEnd   = $seedTime.AddMinutes($CaseWindowMinutes)

        $windowEvents = @($timelineSorted | Where-Object {
            $t = Safe-Date $_.Timestamp
            $t -ge $wStart -and $t -le $wEnd
        })

        if ((Count-Safe $windowEvents) -lt 2) { continue }

        $caseId++
        $sumObj = ($windowEvents | Measure-Object -Property ScoreAdd -Sum)
        $score = 0
        if ($sumObj -and $null -ne $sumObj.Sum) { $score = [int]$sumObj.Sum }

        $types = @($windowEvents.Type | Select-Object -Unique)

        # boosts
        if ($types -contains "WinRM91" -and $types -contains "Logon4624") { $score += 3 }
        if ($types -contains "AdminShare5140" -and $types -contains "Logon4624") { $score += 2 }
        if ($types -contains "Service7045" -and $types -contains "Logon4624") { $score += 4 }
        if ($types -contains "ProcSpawn4688" -and $types -contains "WinRM91") { $score += 3 }
        if ($types -contains "AntiEvasion") { $score += 2 }
        foreach ($t in $types) { if ($t -like "AD-*") { $score += 1; break } }

        $severity = "LOW"
        if ($score -ge 12) { $severity = "HIGH" }
        elseif ($score -ge 7) { $severity = "MEDIUM" }

        $cases += [pscustomobject]@{
            CaseId      = ("CASE-{0:000}" -f $caseId)
            WindowStart = $wStart
            WindowEnd   = $wEnd
            Score       = [int]$score
            Severity    = $severity
            Indicators  = ($types -join ", ")
            Notes       = ("Correlated within +/- {0} minutes" -f $CaseWindowMinutes)
        }
    }

    return @{
        Meta = [pscustomobject]@{
            MachineName = $env:COMPUTERNAME
            CollectedAt = Get-Date
            Mode        = $Mode
            DaysBack    = $DaysBack
            StartTime   = $startTime
            MaxEvents   = $MaxEventsPerLog
            Version     = $ScriptVersion
        }
        Findings = @($Findings)
        Security_4624 = @($sec4624Rows)
        Security_5140 = @($share5140Rows)
        WinRM_91 = @($winrmRows)
        PowerShell_4103_4104 = @($psRows)
        System_7045 = @($svc7045Rows)
        Proc_4688 = @($proc4688Rows)
        Registry = @($regRows)
        ADCorrelation = @($adRows)
        Timeline = @($timelineSorted)
        Cases = @($cases)
    }
}

# ============================== Remote collection block ==============================
function Get-RemoteCollectorScriptBlock {
    return {
        param($Mode,$DaysBack,$MaxEventsPerLog,$CaseWindowMinutes)

        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        function Count-Safe { param($o) if ($null -eq $o) { 0 } else { @($o).Count } }
        function Safe-Date  { param($d) if ($null -eq $d) { Get-Date } else { try { [datetime]$d } catch { Get-Date } } }

        function Get-XmlNodeText {
            param($Node)
            if ($null -eq $Node) { return "" }
            try { $t=$Node.InnerText; if (-not [string]::IsNullOrWhiteSpace($t)) { return $t } } catch {}
            try { $p=$Node.PSObject.Properties["#text"]; if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value } } catch {}
            try { return [string]$Node } catch { return "" }
        }

        function Convert-EventToHashtable {
            param($Event)
            $result=@{}
            try {
                $xml=[xml]$Event.ToXml()
                if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
                    foreach ($node in $xml.Event.EventData.Data) {
                        if ($node -and $node.Name) { $result[$node.Name]=(Get-XmlNodeText $node) }
                    }
                }
                if ($xml.Event.UserData) {
                    foreach ($node in $xml.Event.UserData.SelectNodes(".//*")) {
                        if ($node -and $node.Name -and -not $result.ContainsKey($node.Name)) { $result[$node.Name]=(Get-XmlNodeText $node) }
                    }
                }
            } catch {}
            return $result
        }

        function Get-WinEventsFast {
            param([string]$LogName,[int[]]$Ids,[datetime]$StartTime,[int]$MaxEvents)
            try {
                $fh=@{LogName=$LogName;Id=$Ids;StartTime=$StartTime}
                $ev=Get-WinEvent -FilterHashtable $fh -ErrorAction Stop
                if ((Count-Safe $ev) -gt $MaxEvents) { $ev=$ev | Select-Object -First $MaxEvents }
                return @($ev)
            } catch { return @() }
        }

        function Detect-EncodedPowerShell {
            param([string]$Text)
            if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
            $patterns=@(
                "(?i)\s-enc(\s|$)","(?i)\s-encodedcommand(\s|$)","(?i)frombase64string\(",
                "(?i)\biex\s*\(","(?i)invoke-expression","(?i)downloadstring\(",
                "(?i)new-object\s+net\.webclient","(?i)invoke-webrequest","(?i)start-bitstransfer"
            )
            foreach ($p in $patterns) { if ($Text -match $p) { return $true } }
            return $false
        }

        function Add-TimelineRow {
            param($Timeline,$Time,[string]$Type,[string]$User,[string]$SourceIP,[string]$Destination,[string]$Details,[int]$ScoreAdd,[string]$Evidence)
            $Timeline += [pscustomobject]@{
                Timestamp   = (Safe-Date $Time)
                MachineName = $env:COMPUTERNAME
                Type        = $Type
                User        = $User
                SourceIP    = $SourceIP
                Destination = $Destination
                Details     = $Details
                ScoreAdd    = [int]$ScoreAdd
                Evidence    = $Evidence
            }
            return ,$Timeline
        }

        function Get-ADCorrelationSignals {
            param([datetime]$StartTime,[int]$MaxEvents)
            $rows=@()
            $ids=@(4768,4769,4776)
            $ev=@()
            try { $ev = Get-WinEventsFast -LogName "Security" -Ids $ids -StartTime $StartTime -MaxEvents $MaxEvents } catch { $ev=@() }
            foreach ($e in $ev) {
                $d = Convert-EventToHashtable $e
                $rows += [pscustomobject]@{
                    TimeCreated = $e.TimeCreated
                    EventId     = $e.Id
                    TargetUser  = $d["TargetUserName"]
                    ServiceName = $d["ServiceName"]
                    IpAddress   = $d["IpAddress"]
                    Workstation = $d["Workstation"]
                    Notes       = "AD auth event"
                }
            }
            return $rows
        }

        function Invoke-LMCollectionCore_Embedded {
            param([ValidateSet("Quick","Deep")] [string]$Mode,[int]$DaysBack,[int]$MaxEventsPerLog,[int]$CaseWindowMinutes)

            $ScriptVersion="6.0"
            if ($Mode -eq "Deep") { $DaysBack=30; $MaxEventsPerLog=[Math]::Max($MaxEventsPerLog,20000) }
            else { $DaysBack=7; $MaxEventsPerLog=[Math]::Min($MaxEventsPerLog,3000) }

            $startTime=(Get-Date).AddDays(-$DaysBack)

            $Timeline=@(); $Findings=@()
            $sec4624Rows=@(); $share5140Rows=@(); $winrmRows=@(); $psRows=@()
            $svc7045Rows=@(); $proc4688Rows=@(); $regRows=@(); $adRows=@()

            foreach ($e in @(Get-WinEventsFast "Security" @(1102) $startTime $MaxEventsPerLog)) { $Findings += [pscustomobject]@{ Category="AntiEvasion"; Indicator="Security log cleared (1102)"; TimeCreated=$e.TimeCreated; Severity="High" }; $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "AntiEvasion" "" "" "" "Security log cleared (1102)" 6 "Security/1102" }
            foreach ($e in @(Get-WinEventsFast "System" @(104) $startTime $MaxEventsPerLog)) { $Findings += [pscustomobject]@{ Category="AntiEvasion"; Indicator="Event log cleared (System 104)"; TimeCreated=$e.TimeCreated; Severity="Medium" }; $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "AntiEvasion" "" "" "" "Event log cleared (System 104)" 4 "System/104" }

            foreach ($e in @(Get-WinEventsFast "Security" @(4624) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $lt=$d["LogonType"]; if ($lt -notin @("3","9","10")) { continue }
                $user=("{0}\{1}" -f $d["TargetDomainName"],$d["TargetUserName"]).Trim("\"); $ip=$d["IpAddress"]
                $score=2; if ($lt -eq "10") { $score+=2 }; if ($lt -eq "9") { $score+=2 }; if ($ip -and $ip -notin @("-","::1","127.0.0.1","0.0.0.0")) { $score+=1 }
                $sec4624Rows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; LogonType=$lt; User=$user; SourceIP=$ip; Workstation=$d["WorkstationName"]; AuthPackage=$d["AuthenticationPackageName"]; ProcessName=$d["ProcessName"] }
                $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "Logon4624" $user $ip "" ("4624 LT={0}" -f $lt) $score "Security/4624"
            }

            $adminShareRegex='(?i)\\\\(c\$|admin\$|ipc\$)$'
            foreach ($e in @(Get-WinEventsFast "Security" @(5140) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $shareName=$d["ShareName"]; if ([string]::IsNullOrWhiteSpace($shareName)) { continue }
                if ($shareName -notmatch $adminShareRegex) { continue }
                $subject=("{0}\{1}" -f $d["SubjectDomainName"],$d["SubjectUserName"]).Trim("\"); $ip=$d["IpAddress"]
                $share5140Rows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; Subject=$subject; SourceIP=$ip; ShareName=$shareName; Target=$d["RelativeTargetName"] }
                $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "AdminShare5140" $subject $ip "" ("Share={0}" -f $shareName) 3 "Security/5140"
            }

            foreach ($e in @(Get-WinEventsFast "Microsoft-Windows-WinRM/Operational" @(91) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $ip=$d["IpAddress"]; $user=$d["User"]
                $winrmRows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; User=$user; SourceIP=$ip; Message=(($e.Message -replace "`r`n"," ") | Select-Object -First 1) }
                $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "WinRM91" $user $ip "" "WinRM WSMan session/shell" 3 "WinRM/91"
            }

            foreach ($e in @(Get-WinEventsFast "Microsoft-Windows-PowerShell/Operational" @(4103,4104) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $sb=$d["ScriptBlockText"]; $cl=$d["CommandLine"]; $msg=($e.Message -replace "`r`n"," ")
                $enc=Detect-EncodedPowerShell ($sb+" "+$cl+" "+$msg)
                $score=0; if ($e.Id -eq 4104) { $score+=2 }; if ($enc) { $score+=4 }
                $short=$sb; if ($short -and $short.Length -gt 1500) { $short=$short.Substring(0,1500)+"…" }
                $psRows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; EventId=$e.Id; EncodedHints=$enc; Path=$d["Path"]; ScriptBlockText_Short=$short }
                if ($score -gt 0) { $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "PowerShell" "" "" "" ("PS {0} EncodedHints={1}" -f $e.Id,$enc) $score "PS/4103,4104" }
            }

            foreach ($e in @(Get-WinEventsFast "System" @(7045) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $svcName=$d["ServiceName"]; $imgPath=$d["ImagePath"]
                $hints=@(); $score=0
                if ($svcName -match "(?i)psexesvc|psexec|paexec") { $hints+="PsExec-like"; $score+=6 }
                if ($imgPath -match "(?i)psexec|psexesvc|paexec") { $hints+="ImagePath mentions PsExec"; $score+=4 }
                if ($svcName -match "(?i)pdq") { $hints+="PDQ-like"; $score+=3 }
                if ($imgPath -match "\\\\") { $hints+="UNC in ImagePath"; $score+=2 }
                $svc7045Rows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; ServiceName=$svcName; DisplayName=$d["DisplayName"]; ImagePath=$imgPath; AccountName=$d["AccountName"]; Hints=($hints -join "; ") }
                if ($score -gt 0) { $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "Service7045" "" "" "" ("New service: {0} ({1})" -f $svcName, ($hints -join ", ")) $score "System/7045" }
            }

            foreach ($e in @(Get-WinEventsFast "Security" @(4688) $startTime $MaxEventsPerLog)) {
                $d=Convert-EventToHashtable $e; $new=$d["NewProcessName"]; $parent=$d["ParentProcessName"]; $cmd=$d["CommandLine"]
                $usr=("{0}\{1}" -f $d["SubjectDomainName"],$d["SubjectUserName"]).Trim("\")
                $match=$false; $score=0; $hints=@()
                if ($parent -match "(?i)wsmprovhost\.exe" -and $new -match "(?i)powershell\.exe|cmd\.exe") { $match=$true; $score+=6; $hints+="wsmprovhost -> cmd/powershell" }
                if (Detect-EncodedPowerShell $cmd) { $match=$true; $score+=4; $hints+="encoded/LOLBAS hints" }
                if ($match) {
                    $proc4688Rows += [pscustomobject]@{ TimeCreated=$e.TimeCreated; User=$usr; Parent=$parent; NewProcess=$new; CommandLine=$cmd; Hints=($hints -join "; ") }
                    $Timeline=Add-TimelineRow $Timeline $e.TimeCreated "ProcSpawn4688" $usr "" "" ("{0} -> {1}" -f $parent, $new) $score "Security/4688"
                }
            }

            $wsmanKey="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\SafeClientList"
            if (Test-Path -LiteralPath $wsmanKey) {
                $item=$null; try { $item=Get-Item -LiteralPath $wsmanKey -ErrorAction SilentlyContinue } catch { $item=$null }
                if ($item) {
                    $names=@(); try { $names=@($item.GetValueNames()) } catch { $names=@() }
                    foreach ($vn in $names) {
                        $val=$null; try { $val=$item.GetValue($vn) } catch { $val=$null }
                        $regRows += [pscustomobject]@{ Artifact="WinRM SafeClientList"; KeyPath=$wsmanKey; ValueName=$vn; ValueData=$val }
                        $Timeline=Add-TimelineRow $Timeline (Get-Date) "Registry" "" (($val|Out-String).Trim()) "" "SafeClientList client IP" 2 "Registry/SafeClientList"
                    }
                }
            } else { $regRows += [pscustomobject]@{ Artifact="WinRM SafeClientList"; Note="Key not present." } }

            $adRows = Get-ADCorrelationSignals -StartTime $startTime -MaxEvents $MaxEventsPerLog
            foreach ($r in @($adRows)) { $Timeline = Add-TimelineRow $Timeline $r.TimeCreated ("AD-" + $r.EventId) ($r.TargetUser) ($r.IpAddress) ($r.ServiceName) "AD auth event" 2 ("Security/" + $r.EventId) }

            $timelineSorted=@($Timeline|Sort-Object Timestamp)
            $cases=@(); $caseId=0
            $seedTypes=@("Logon4624","WinRM91","AdminShare5140","Service7045","ProcSpawn4688","PowerShell","AntiEvasion","Registry")
            $seeds=@($timelineSorted|Where-Object{ $seedTypes -contains $_.Type })

            foreach ($s in $seeds) {
                $seedTime=Safe-Date $s.Timestamp
                $wStart=$seedTime.AddMinutes(-$CaseWindowMinutes)
                $wEnd=$seedTime.AddMinutes($CaseWindowMinutes)
                $windowEvents=@($timelineSorted|Where-Object{ $t=Safe-Date $_.Timestamp; $t -ge $wStart -and $t -le $wEnd })
                if (@($windowEvents).Count -lt 2) { continue }
                $caseId++
                $sumObj=($windowEvents|Measure-Object -Property ScoreAdd -Sum)
                $score=0; if ($sumObj -and $null -ne $sumObj.Sum) { $score=[int]$sumObj.Sum }
                $types=@($windowEvents.Type|Select-Object -Unique)
                if ($types -contains "WinRM91" -and $types -contains "Logon4624") { $score += 3 }
                if ($types -contains "AdminShare5140" -and $types -contains "Logon4624") { $score += 2 }
                if ($types -contains "Service7045" -and $types -contains "Logon4624") { $score += 4 }
                if ($types -contains "ProcSpawn4688" -and $types -contains "WinRM91") { $score += 3 }
                if ($types -contains "AntiEvasion") { $score += 2 }
                foreach ($t in $types) { if ($t -like "AD-*") { $score += 1; break } }
                $severity="LOW"; if ($score -ge 12) { $severity="HIGH" } elseif ($score -ge 7) { $severity="MEDIUM" }
                $cases += [pscustomobject]@{ CaseId=("CASE-{0:000}" -f $caseId); WindowStart=$wStart; WindowEnd=$wEnd; Score=[int]$score; Severity=$severity; Indicators=($types -join ", "); Notes=("Correlated within +/- {0} minutes" -f $CaseWindowMinutes) }
            }

            return @{
                Meta=[pscustomobject]@{ MachineName=$env:COMPUTERNAME; CollectedAt=(Get-Date); Mode=$Mode; DaysBack=$DaysBack; StartTime=$startTime; MaxEvents=$MaxEventsPerLog; Version=$ScriptVersion }
                Findings=@($Findings)
                Security_4624=@($sec4624Rows)
                Security_5140=@($share5140Rows)
                WinRM_91=@($winrmRows)
                PowerShell_4103_4104=@($psRows)
                System_7045=@($svc7045Rows)
                Proc_4688=@($proc4688Rows)
                Registry=@($regRows)
                ADCorrelation=@($adRows)
                Timeline=@($timelineSorted)
                Cases=@($cases)
            }
        }

        Invoke-LMCollectionCore_Embedded -Mode $Mode -DaysBack $DaysBack -MaxEventsPerLog $MaxEventsPerLog -CaseWindowMinutes $CaseWindowMinutes
    }
}

# ============================== Reporting ==============================
function Export-HostReport {
    param([string]$RunRoot,[hashtable]$Data,[hashtable]$DiagPack)

    $meta = $Data.Meta
    $machineName = $meta.MachineName
    $machineDir = Join-Path $RunRoot $machineName
    Safe-MkDir $machineDir

    if ($DiagPack) {
        Export-CsvTxt $machineDir "Diagnostics_LogAccess" $DiagPack.LogAccess
        Export-CsvTxt $machineDir "Diagnostics_AuditPol"  $DiagPack.AuditPol
        Export-CsvTxt $machineDir "Diagnostics_PSLoggingGPO" $DiagPack.PSLoggingGPO
        Export-CsvTxt $machineDir "Diagnostics_Defender_EDR_Awareness" $DiagPack.DefenderEDR
    }

    Export-CsvTxt $machineDir "Findings_AntiEvasion" $Data.Findings
    Export-CsvTxt $machineDir "Security_4624_RemoteLogons" $Data.Security_4624
    Export-CsvTxt $machineDir "Security_5140_AdminShares" $Data.Security_5140
    Export-CsvTxt $machineDir "WinRM_91" $Data.WinRM_91
    Export-CsvTxt $machineDir "PowerShell_4103_4104" $Data.PowerShell_4103_4104
    Export-CsvTxt $machineDir "System_7045_ServiceInstalls" $Data.System_7045
    Export-CsvTxt $machineDir "Security_4688_ProcCreation" $Data.Proc_4688
    Export-CsvTxt $machineDir "Registry_Artifacts" $Data.Registry
    Export-CsvTxt $machineDir "AD_Correlation" $Data.ADCorrelation
    Export-CsvTxt $machineDir "Unified_Timeline" $Data.Timeline
    Export-CsvTxt $machineDir "Correlated_Cases" $Data.Cases

    $sections = @{
        "Executive - Cases (Top 50)" = @($Data.Cases | Sort-Object Score -Descending | Select-Object -First 50)
        "Unified Timeline (Top 5000)"= @($Data.Timeline | Select-Object -First 5000)
        "4624 Remote Logons"         = $Data.Security_4624
        "5140 Admin Shares"          = $Data.Security_5140
        "WinRM 91"                   = $Data.WinRM_91
        "PowerShell 4103/4104"       = $Data.PowerShell_4103_4104
        "Service Installs 7045"      = $Data.System_7045
        "Process Creation 4688"      = $Data.Proc_4688
        "Registry Artifacts"         = $Data.Registry
        "AD Correlation"             = $Data.ADCorrelation
        "Diagnostics - Log Access"   = (if($DiagPack){$DiagPack.LogAccess}else{@()})
        "Diagnostics - auditpol"     = (if($DiagPack){$DiagPack.AuditPol}else{@()})
        "Diagnostics - PS Logging"   = (if($DiagPack){$DiagPack.PSLoggingGPO}else{@()})
        "Diagnostics - Defender/EDR" = (if($DiagPack){$DiagPack.DefenderEDR}else{@()})
    }
    Export-XlsHtmlReport -OutDir $machineDir -FileName "Report.xls" -Sections $sections | Out-Null

    $cases = @($Data.Cases)
    $top = @($cases | Sort-Object Score -Descending | Select-Object -First 10)
    $hi = @($cases | Where-Object { $_.Severity -eq "HIGH" }).Count
    $med = @($cases | Where-Object { $_.Severity -eq "MEDIUM" }).Count

    $lines = @()
    $lines += "Executive Report (Host)"
    $lines += "======================="
    $lines += ("MachineName: {0}" -f $machineName)
    $lines += ("CollectedAt: {0}" -f $meta.CollectedAt)
    $lines += ("Version: {0}" -f $meta.Version)
    $lines += ("Mode: {0}  DaysBack: {1}" -f $meta.Mode, $meta.DaysBack)
    $lines += ""
    $lines += ("Cases: {0} (HIGH={1}, MEDIUM={2})" -f (Count-Safe $cases), $hi, $med)
    $lines += ""
    $lines += "Top Cases"
    $lines += "---------"
    if ((Count-Safe $top) -eq 0) { $lines += "No cases generated." }
    else { foreach ($c in $top) { $lines += ("{0} | {1} | Score {2} | {3}" -f $c.CaseId, $c.Severity, $c.Score, $c.Indicators) } }
    $lines | Out-File -Encoding UTF8 -FilePath (Join-Path $machineDir "EXECUTIVE_REPORT.txt")
}

function Export-EnterpriseSummary {
    param([string]$RunRoot,[hashtable[]]$AllData)

    $sumDir = Join-Path $RunRoot "_EnterpriseSummary"
    Safe-MkDir $sumDir

    $hostRows = @()
    $caseRows = @()

    foreach ($d in @($AllData)) {
        if ($null -eq $d -or $null -eq $d.Meta) { continue }
        $meta = $d.Meta
        $machineName = $meta.MachineName
        $cases = @($d.Cases)

        $hi = @($cases | Where-Object { $_.Severity -eq "HIGH" }).Count
        $med = @($cases | Where-Object { $_.Severity -eq "MEDIUM" }).Count
        $low = @($cases | Where-Object { $_.Severity -eq "LOW" }).Count

        $hostRows += [pscustomobject]@{
            MachineName = $machineName
            CollectedAt = $meta.CollectedAt
            Mode        = $meta.Mode
            DaysBack    = $meta.DaysBack
            Version     = $meta.Version
            Count_4624  = (Count-Safe $d.Security_4624)
            Count_5140  = (Count-Safe $d.Security_5140)
            Count_WinRM91 = (Count-Safe $d.WinRM_91)
            Count_PS    = (Count-Safe $d.PowerShell_4103_4104)
            Count_7045  = (Count-Safe $d.System_7045)
            Count_4688  = (Count-Safe $d.Proc_4688)
            Count_AD    = (Count-Safe $d.ADCorrelation)
            CasesTotal  = (Count-Safe $cases)
            CasesHigh   = $hi
            CasesMedium = $med
            CasesLow    = $low
        }

        foreach ($c in $cases) {
            $caseRows += [pscustomobject]@{
                MachineName = $machineName
                CaseId      = $c.CaseId
                Severity    = $c.Severity
                Score       = $c.Score
                WindowStart = $c.WindowStart
                WindowEnd   = $c.WindowEnd
                Indicators  = $c.Indicators
                Notes       = $c.Notes
            }
        }
    }

    Export-CsvTxt $sumDir "Enterprise_Host_Summary" $hostRows
    Export-CsvTxt $sumDir "Enterprise_All_Cases" ($caseRows | Sort-Object Score -Descending)

    $xlsSections = @{
        "Enterprise Host Summary" = $hostRows
        "Enterprise All Cases"    = ($caseRows | Sort-Object Score -Descending)
    }
    Export-XlsHtmlReport -OutDir $sumDir -FileName "Enterprise_Report.xls" -Sections $xlsSections | Out-Null

    $top = @($caseRows | Sort-Object Score -Descending | Select-Object -First 20)
    $lines = @()
    $lines += "Executive Report (Enterprise Roll-up)"
    $lines += "===================================="
    $lines += ("Generated: {0}" -f (Get-Date))
    $lines += ("Version: {0}" -f $ScriptVersion)
    $lines += ("Run Root: {0}" -f $RunRoot)
    $lines += ("Machines: {0}" -f (Count-Safe $hostRows))
    $lines += ""
    $lines += "Top Cases"
    $lines += "---------"
    if ((Count-Safe $top) -eq 0) { $lines += "No cases generated across machines." }
    else { foreach ($c in $top) { $lines += ("{0} | {1} | Score {2} | MachineName={3} | {4}" -f $c.CaseId, $c.Severity, $c.Score, $c.MachineName, $c.Indicators) } }
    $lines | Out-File -Encoding UTF8 -FilePath (Join-Path $sumDir "EXECUTIVE_REPORT.txt")
}

# ============================== Scheduling orchestration ==============================
function Schedule-LocalOrRemote {
    param(
        [ValidateSet("Daily","Weekly","Monthly")] [string]$Frequency,
        [ValidateSet("Quick","Deep")] [string]$Mode,
        [int]$DaysBack,[int]$MaxEventsPerLog,[int]$CaseWindowMinutes,
        [string]$OutputPath,
        [string[]]$Targets,
        [pscredential]$Credential,
        [switch]$UseCredSSP
    )

    $dt = Read-StartDateTime
    $localScriptPath = $MyInvocation.MyCommand.Definition
    $scriptArgs = "-Mode $Mode -DaysBack $DaysBack -MaxEventsPerLog $MaxEventsPerLog -CaseWindowMinutes $CaseWindowMinutes -OutputPath `"$OutputPath`" -NonInteractive"
    if ($UseCredSSP) { $scriptArgs += " -UseCredSSP" }

    Write-Host ""
    Write-Host "Schedule scope:"
    Write-Host "  1) Schedule on THIS machine only"
    Write-Host "  2) Schedule on REMOTE targets (deploy script + create tasks)"
    $scope = Read-Host "Select (1/2)"

    if ($scope -eq "1") {
        Register-TaskCom -Target $null -TaskName $TaskName -Frequency $Frequency -StartDateTime $dt -ScriptPathToRun $localScriptPath -ScriptArgs $scriptArgs
        Write-Host ("Scheduled locally ({0}). Task: {1}" -f $Frequency, $TaskName) -ForegroundColor Green
        return
    }

    if ((Count-Safe $Targets) -eq 0) { Write-Host "No remote targets provided." -ForegroundColor Red; return }

    if ($OutputPath -notmatch "^(?i)\\\\") {
        Write-Host ""
        Write-Host "Enterprise UNC guidance" -ForegroundColor Yellow
        Write-Host "Remote scheduled tasks run as SYSTEM."
        Write-Host "For central IR reporting, use a UNC path and grant share+NTFS write to:"
        Write-Host "  - DOMAIN\COMPUTER$ accounts, or"
        Write-Host "  - a group containing computer accounts."
        Write-Host ""
    }

    $remotePath = Read-Host "Remote script path (default: C:\ProgramData\Lateralmovement\Enterprise-LMIR.ps1)"
    if ([string]::IsNullOrWhiteSpace($remotePath)) { $remotePath = "C:\ProgramData\Lateralmovement\Enterprise-LMIR.ps1" }

    foreach ($t in $Targets) {
        try {
            Write-Host ("Deploying script to {0} ..." -f $t)
            Deploy-ScriptToRemote -Target $t -Credential $Credential -LocalScriptPath $localScriptPath -RemoteScriptPath $remotePath -UseCredSSP:$UseCredSSP

            Write-Host ("Creating scheduled task on {0} ..." -f $t)
            Register-TaskCom -Target $t -TaskName $TaskName -Frequency $Frequency -StartDateTime $dt -ScriptPathToRun $remotePath -ScriptArgs $scriptArgs

            Write-Host ("OK: {0}" -f $t) -ForegroundColor Green
        } catch {
            Write-Host ("FAILED: {0} - {1}" -f $t, $_.Exception.Message) -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Remote scheduling complete."
}

# ============================== Interactive Wizard ==============================
if (-not $NonInteractive) {

    Clear-Host
    Write-Host "Enterprise IR: Lateral Movement Visibility"
    Write-Host ("Version {0}" -f $ScriptVersion)
    Write-Host "==============================================="
    Write-Host ""

    if (-not (Is-Admin)) {
        Write-Host "Note: Not running as Administrator. Some logs may be inaccessible." -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "Run mode:"
    Write-Host "  1) Standalone (this machine only)"
    Write-Host "  2) Remote collection (WinRM) from this machine"
    $runModeSel = Read-Host "Select (1/2)"

    if ($runModeSel -eq "2" -and (Count-Safe $ComputerName) -eq 0) {
        $raw = Read-Host "Enter machine names (comma-separated) or a path to a .txt list"
        if (Test-Path $raw) {
            $ComputerName = @(Get-Content -Path $raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        } else {
            $ComputerName = @($raw.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }

        $useCred = Read-Host "Use alternate credentials for remoting? (y/n)"
        if ($useCred -match "^(y|yes)$") { $Credential = Get-Credential }

        $useC = Read-Host "Use CredSSP for remoting? (y/n)"
        if ($useC -match "^(y|yes)$") { $UseCredSSP = $true }
    }

    Write-Host ""
    Write-Host "Investigator mode:"
    Write-Host "  1) Quick triage (7 days)"
    Write-Host "  2) Deep forensic (30 days)"
    $invSel = Read-Host "Select (1/2)"
    if ($invSel -eq "2") { $Mode = "Deep"; $DaysBack = 30; $MaxEventsPerLog = 20000 }
    else { $Mode = "Quick"; $DaysBack = 7; $MaxEventsPerLog = 3000 }

    Write-Host ""
    Write-Host "Output location:"
    Write-Host "  1) Local (C:\ForensicReports)"
    Write-Host "  2) Network Share (UNC path)"
    $outSel = Read-Host "Select (1/2)"
    if ($outSel -eq "2") {
        $unc = Read-Host "Enter UNC path (example: \\IRSERVER\Share\LMReports)"
        if (-not [string]::IsNullOrWhiteSpace($unc)) { $OutputPath = $unc }
    }

    Write-Host ""
    Write-Host "Run / Schedule:"
    Write-Host "  1) Run once now"
    Write-Host "  2) Schedule Daily"
    Write-Host "  3) Schedule Weekly"
    Write-Host "  4) Schedule Monthly"
    Write-Host "  5) View current schedule"
    Write-Host "  6) Run diagnostics only"
    $schedSel = Read-Host "Select (1/2/3/4/5/6)"

    if ($schedSel -eq "5") {
        if ($runModeSel -eq "2") { View-Schedule -Targets $ComputerName } else { View-Schedule -Targets @() }
        return
    }

    if ($schedSel -eq "6") {
        $tmp = Join-Path $OutputPath ("EnterpriseLMIR_Diagnostics_" + $RunStamp)
        Safe-MkDir $tmp
        Invoke-DiagnosticsPack -OutDir $tmp -OutputPathForUNCCheck $OutputPath | Out-Null
        Write-Host ("Diagnostics saved to: {0}" -f $tmp)
        return
    }

    if ($schedSel -in @("2","3","4")) {
        $freq = if ($schedSel -eq "2") { "Daily" } elseif ($schedSel -eq "3") { "Weekly" } else { "Monthly" }
        $targetsForSchedule = @()
        if ($runModeSel -eq "2") { $targetsForSchedule = $ComputerName }
        Schedule-LocalOrRemote -Frequency $freq -Mode $Mode -DaysBack $DaysBack -MaxEventsPerLog $MaxEventsPerLog -CaseWindowMinutes $CaseWindowMinutes -OutputPath $OutputPath -Targets $targetsForSchedule -Credential $Credential -UseCredSSP:$UseCredSSP
        return
    }
}

# ============================== Collection Execution ==============================
$RunRoot = Join-Path $OutputPath ("EnterpriseLMIR_{0}" -f $RunStamp)
Safe-MkDir $RunRoot

$allResults = @()

if ((Count-Safe $ComputerName) -gt 0) {
    $sb = Get-RemoteCollectorScriptBlock

    foreach ($machine in $ComputerName) {
        try {
            Write-Host ("Collecting remotely: {0}" -f $machine)

            $icm = @{
                ComputerName = $machine
                ScriptBlock  = $sb
                ArgumentList = @($Mode,$DaysBack,$MaxEventsPerLog,$CaseWindowMinutes)
                ErrorAction  = "Stop"
            }
            if ($Credential) { $icm.Credential = $Credential }
            if ($UseCredSSP) { $icm.Authentication = "CredSSP" }

            $res = Invoke-Command @icm
            $r = if (@($res).Count -eq 1) { @($res)[0] } else { $res }

            if ($r -and $r.Meta -and $r.Meta.MachineName) {
                $allResults += $r
            } else {
                Write-Host ("No usable data returned from {0}" -f $machine) -ForegroundColor Yellow
            }
        } catch {
            Write-Host ("FAILED {0}: {1}" -f $machine, $_.Exception.Message) -ForegroundColor Red
        }
    }
} else {
    Write-Host "Collecting locally..."
    $allResults += (Invoke-LMCollectionCore -Mode $Mode -DaysBack $DaysBack -MaxEventsPerLog $MaxEventsPerLog -CaseWindowMinutes $CaseWindowMinutes)
}

# Local diagnostics pack (collector host)
$localDiag = $null
try {
    $diagDir = Join-Path $RunRoot "_Diagnostics_CollectorHost"
    $localDiag = Invoke-DiagnosticsPack -OutDir $diagDir -OutputPathForUNCCheck $OutputPath
} catch { $localDiag = $null }

# Export per-host
foreach ($d in $allResults) {
    try {
        $attachDiag = $null
        if ($d.Meta -and $d.Meta.MachineName -eq $env:COMPUTERNAME) { $attachDiag = $localDiag }
        Export-HostReport -RunRoot $RunRoot -Data $d -DiagPack $attachDiag
    } catch {}
}

# Enterprise roll-up
Export-EnterpriseSummary -RunRoot $RunRoot -AllData @($allResults)

# Console executive summary
$hostCount = @($allResults).Count
$allCases = @()
foreach ($d in $allResults) {
    $mn = $null
    try { $mn = $d.Meta.MachineName } catch { $mn = "" }
    foreach ($c in @($d.Cases)) {
        $allCases += ($c | Add-Member -NotePropertyName MachineName -NotePropertyValue $mn -Force -PassThru)
    }
}

$high = @($allCases | Where-Object { $_.Severity -eq "HIGH" }).Count
$med  = @($allCases | Where-Object { $_.Severity -eq "MEDIUM" }).Count

Write-Host ""
Write-Host "==============================================="
Write-Host " Executive Report"
Write-Host "==============================================="
Write-Host ("Version:  {0}" -f $ScriptVersion)
Write-Host ("RunRoot:  {0}" -f $RunRoot)
Write-Host ("Machines: {0}" -f $hostCount)
Write-Host ("Cases:    {0} (HIGH={1}, MEDIUM={2})" -f @($allCases).Count, $high, $med)
Write-Host ""
Write-Host "Top 10 Cases"
Write-Host "------------"
$top10 = @($allCases | Sort-Object Score -Descending | Select-Object -First 10)
if (@($top10).Count -eq 0) { Write-Host "No cases generated." }
else {
    foreach ($c in $top10) {
        Write-Host ("{0} | {1} | Score {2} | MachineName={3} | {4}" -f $c.CaseId, $c.Severity, $c.Score, $c.MachineName, $c.Indicators)
    }
}
Write-Host ""
Write-Host "Outputs saved to:"
Write-Host ("  {0}" -f $RunRoot)
Write-Host "Done."