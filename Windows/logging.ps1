# Variables for different paths
[string]$currentFullPath = $MyInvocation.MyCommand.Path
[string]$scriptDir = ($currentFullPath.substring(0, $currentFullPath.IndexOf("logging.ps1")))
[string]$rootDir = ($scriptDir.substring(0, $scriptDir.IndexOf("scripts")))

function printSuccessOrError{
    param(
        [string]$name,
        $result,
        $desiredResult,
        [bool]$multiple
    )
    if($multiple){
        if($desiredResult -in $result){
            Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name
        }
        else{
            Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name -NoNewline; Write-Host " Failed: "
            Write-Host $result
        }
    }
    else{
        if($desiredResult -eq $result){
            Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name
        }
        else{
            Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name -NoNewline; Write-Host " Failed: "
            Write-Host $result
        }
    }
}

# Turn on Event log service if it's stopped
if (!((Get-Service -Name "EventLog").Status -eq "Running")) {
    Start-Service -Name EventLog

    if(((Get-Service -Name "EventLog").Status -eq "Running")){
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Windows Event Log Service Started" -ForegroundColor White
    }
    else{
        Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Green -NoNewline; Write-Host "] Windows Event Log Service Failed to start" -ForegroundColor White
    }
}

# setting up logging
WevtUtil sl Application /ms:256000
WevtUtil sl System /ms:256000
WevtUtil sl Security /ms:2048000
WevtUtil sl "Windows PowerShell" /ms:512000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Log Sizes Set" -ForegroundColor White

# Setting percentage threshold for security event log
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /t REG_DWORD /d 90 /f | Out-Null

# Enabling audit policy subcategories
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audit policy subcategories enabled" -ForegroundColor white 

# Powershell logging
$psLogFolder = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "powershellLogs"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d $psLogFolder /f | Out-Null
# Process Creation events (4688) include command line arguments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] PowerShell and CommandLine logging set" -ForegroundColor White

# Import audit policy
[string]$auditpolPath = (Join-Path -Path $scriptDir -ChildPath "\conf\auditpol.csv")
$result = auditpol /restore /file:$auditpolPath
printSuccessOrError -Name "System Audit Policy Set" -result $result -desiredResult "The command was successfully executed." -multiple $true

# TODO: x86 vs x64 sysmon setup
# Sysmon setup
[string]$sysmonPath = (Join-Path -Path $rootDir -ChildPath "tools\sys\sm\sysmon64.exe")
[string]$xmlPath = (Join-Path -Path $scriptDir -ChildPath "\conf\sysmon.xml")
$result = & $sysmonPath -accepteula -i $xmlPath
WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
if("The service Sysmon64 is already registered. Uninstall Sysmon before reinstalling." -in $result){
    Write-Host "[" -NoNewline; Write-Host "INFO" -ForegroundColor Yellow -NoNewline; Write-Host "] Sysmon already installed and configured" -ForegroundColor White
}
elseif ("sysmon64 started." -in $result) {
    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Sysmon installed and configured" -ForegroundColor White
}
else{
    Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] Sysmon install or configuration Failed: " -ForegroundColor White
    Write-Host $result
}

# DNS server logging
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $serverDiag1 = Set-DnsServerDiagnostics -EventLogLevel 2 -UseSystemEventLog $true
    $logFileResult = dnscmd /config /logfilemaxsize 0xC800000
    $ServerDiag2 = Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true -EnableLoggingForServerStartStopEvent $true -EnableLoggingForLocalLookupEvent $true -EnableLoggingForRecursiveLookupEvent $true -EnableLoggingForRemoteServerEvent $true -EnableLoggingForZoneDataWriteEvent $true -EnableLoggingForZoneLoadingEvent $true
    $stopDNS = net stop DNS
    $startDNS = net start DNS

    printSuccessOrError -name "Log file Max Size Set" -result $logFileResult -desiredResult "Registry property logfilemaxsize successfully reset." -multiple $true
    printSuccessOrError -name "DNS Server Logging to Event log set" -result $ServerDiag1 -desiredResult $Null -multiple $false
    printSuccessOrError -name "DNS Server Logging Settings set" -result $ServerDiag2 -desiredResult $Null -multiple $false
    printSuccessOrError -name "DNS Server Stopped" -result $stopDNS -desiredResult "The DNS Server service was stopped successfully." -multiple $true
    printSuccessOrError -name "DNS Server Started" -result $startDNS -desiredResult "The DNS Server service was started successfully." -multiple $true
}

wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] DNS Client logging enabled" -ForegroundColor White

# IIS logging
if (Get-Service -Name W3SVC 2>$null) {
    try {
        C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] IIS Logging Enabled" -ForegroundColor White
    }
    catch {
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] IIS Logging failed" -ForegroundColor White
    }
}

if (Get-Service -Name CertSvc 2>$null) {
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
    # Enabling ADCS auditing
    $domain = (Get-ADDomain).DistinguishedName
    $searchBase = "CN=Configuration,$domain"
    $caName = ((Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" -SearchBase $searchBase).Name | Out-String).Trim()
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" /v AuditFilter /t REG_DWORD /d 127 /f | Out-Null
    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] CA Logging Enabled" -ForegroundColor White
}

# Compile yara rules
& (Join-Path -Path $yaraDir -ChildPath "yarac64.exe") $rules (Join-Path -Path $yaraDir -ChildPath "compiled.windows")

#Chandi Fortnite