param (
    [Parameter(mandatory=$true)]
    [SecureString]$Password 
)

# ye olde secure script
# Author: Chandi Kanhai (@Chandi-95)
$Error.Clear()
$ErrorActionPreference = "Continue"

# DC detection
$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

# IIS detection
$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
}

$currentDir = (($MyInvocation.MyCommand.Path).Substring(0,($MyInvocation.MyCommand.Path).IndexOf("secure.ps1")))
$rootDir = $currentDir.substring(0,$currentDir.indexOf("scripts"))
$ConfPath = Join-Path -Path $currentDir -ChildPath "conf"
$ToolPath = Join-Path -Path $currentDir -ChildPath "tools"

# Disabling RDP (only if not needed)
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
# Write-Host "[INFO] RDP disabled"

# Uninstalling Windows capabilities
$capabilities = @("Browser.InternetExplorer~~~~0.0.11.0", "Media.WindowsMediaPlayer~~~~0.0.12.0", "RIP.Listener~~~~0.0.1.0", "XPS.Viewer~~~~0.0.1.0", "VBSCRIPT~~~~")
foreach ($capability in $capabilities) {
    if ((Get-WindowsCapability -Online -Name $capability | Select-Object -ExpandProperty "State") -eq "Installed") {
        Remove-WindowsCapability -Online -Name $capability | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; 
        Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
        Write-Host "] Uninstalled $capability" -ForegroundColor white 
    }
}

## Yeeting unneeded Windows features 
$features = @("MicrosoftWindowsPowerShellV2", "MicrosoftWindowsPowerShellV2Root", "SMB1Protocol", "MultiPoint-Connector", "MultiPoint-Connector-Services", "MultiPoint-Tools", "SimpleTCP")
foreach ($feature in $features) {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $feature | Select-Object -ExpandProperty "State") -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -norestart | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; 
        Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
        Write-Host "] Disabled $feature" -ForegroundColor white 
    }
}

## Uninstalling unnecessary Languages (Java, Rust, Go, Python)
# Uninstall everything for Java, Python, Go
$badapps = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match "Java" -or $_.Name -Match "Python" -or $_.Name -Match "Go"}

if($badapps){
    foreach($program in $badapps){
        Write-Host "[" -ForegroundColor white -NoNewLine;
        Write-Host "INFO" -ForegroundColor yellow -NoNewLine;
        Write-Host "] Uninstalling $($program.Name)" -ForegroundColor white
        $result = $program.Uninstall()
        if($result.ReturnValue -eq 0){
            Write-Host "[" -ForegroundColor white -NoNewLine; 
            Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
            Write-Host "] Uninstalled $($program.Name)" -ForegroundColor white 
        } else {
            Write-Host "[" -ForegroundColor white -NoNewLine; 
            Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
            Write-Host "] Could not Uninstall $($program.Name). Error Code - $($result.ReturnValue)" -ForegroundColor white 
        }
    }
}

# Uninstall Rust
# Get PATH Variables for cmd, powershell, and the system
$cmdPATH = (Get-ItemProperty -Path 'HKCU:\Environment' -Name PATH).PATH
$systemPATH = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
$powershellPATH = $env:PATH
$allPATHs = ($cmdPATH + ";" + $systemPATH + ";" + $powershellPATH).split(";")

# Iterate though each. .cargo\bin is the PATH variable for rust, so if exists, use it to uninstall itself
foreach($path in $allPATHs){
    if($path.contains(".cargo\bin")){
        # Rustup prints its own output, so theres no need to inform the user ouselves that we are doing it
        & (Join-Path -Path $path -ChildPath "rustup.exe") self uninstall -y
    }
}

# drop an eagle 500kg on chocolatey
Remove-Item -Recurse -Force "$env:ChocolateyInstall"
[System.Text.RegularExpressions.Regex]::Replace([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment').GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).ToString(), [System.Text.RegularExpressions.Regex]::Escape("$env:ChocolateyInstall\bin") + '(?>;)?', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | %{[System.Environment]::SetEnvironmentVariable('PATH', $_, 'User')}
[System.Text.RegularExpressions.Regex]::Replace([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment\').GetValue('PATH', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames).ToString(),  [System.Text.RegularExpressions.Regex]::Escape("$env:ChocolateyInstall\bin") + '(?>;)?', '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) | %{[System.Environment]::SetEnvironmentVariable('PATH', $_, 'Machine')}
if ($env:ChocolateyBinRoot -ne '' -and $env:ChocolateyBinRoot -ne $null) { Remove-Item -Recurse -Force "$env:ChocolateyBinRoot" }
if ($env:ChocolateyToolsRoot -ne '' -and $env:ChocolateyToolsRoot -ne $null) { Remove-Item -Recurse -Force "$env:ChocolateyToolsRoot" }
[System.Environment]::SetEnvironmentVariable("ChocolateyBinRoot", $null, 'User')
[System.Environment]::SetEnvironmentVariable("ChocolateyToolsLocation", $null, 'User')

# GPO stuff
## Resetting local group policy
$gp = (Join-Path -Path $currentDir -ChildPath "results\gp")
if(!(Test-Path -Path $gp)) {
    New-Item -Path (Join-Path -Path $currentDir -ChildPath "results\gp") -ItemType Directory
}
Copy-Item C:\Windows\System32\GroupPolicy* $gp -Recurse | Out-Null
Remove-Item C:\Windows\System32\GroupPolicy* -Recurse -Force | Out-Null
gpupdate /force
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Local group policy reset" -ForegroundColor white 
## Resetting domain GPOs
if ($DC) {
    ## Reset/rebuild default GPOs
    dcgpofix /ignoreschema

    $DomainGPO = Get-GPO -All
    foreach ($GPO in $DomainGPO) {
        ## Prompt user to decide which GPOs to disable
        $Ans = Read-Host "Reset $($GPO.DisplayName) (y/N)?"
        if ($Ans.ToLower() -eq "y") {
            $GPO.gpostatus = "AllSettingsDisabled"
        }
    }

    ## Importing domain GPOs
    Import-GPO -BackupId "78CE52B4-D6E0-41F6-BBCE-4990E5BF9D9A" -TargetName "wildcard-domain-policies" -CreateIfNeeded -Path $ConfPath
    Import-GPO -BackupId "EDE9AE23-42FC-452F-978A-2C9432FA191A" -TargetName "wildcard-dc-policies" -CreateIfNeeded -Path $ConfPath
    Import-GPO -BackupId "3650625F-02CB-4E30-BCD6-A2226F3549A9" -TargetName "wildcard-admin-templates" -CreateIfNeeded -Path $ConfPath
    
    $distinguishedName = (Get-ADDomain -Identity (Get-ADDomain -Current LocalComputer).DNSRoot).DistinguishedName
    New-GPLink -Name "wildcard-domain-policies" -Target $distinguishedName -Order 1
    New-GPLink -Name "wildcard-admin-templates" -Target $distinguishedName
    New-GPLink -Name "wildcard-dc-policies" -Target ("OU=Domain Controllers," + $distinguishedName) -Order 1

    gpupdate /force
} else {
    ## Applying client machine/member server security template
    secedit /configure /db $env:windir\security\local.sdb /cfg (Join-Path -Path $ConfPath -ChildPath 'msc-sec-template.inf')
    
    # Importing local GPO
    $LGPOPath = Join-Path -Path $rootDir -ChildPath "tools\LGPO_30\LGPO.exe"
    & $LGPOPath /g (Join-Path -Path $ConfPath -ChildPath "{3650625F-02CB-4E30-BCD6-A2226F3549A9}") 
    
    gpupdate /force
}

# Mitigating CVEs
# CVE-2021-36934 (HiveNightmare/SeriousSAM) - workaround (patch at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
icacls $env:windir\system32\config\*.* /inheritance:e | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] HiveNightmare mitigations in place" -ForegroundColor white 
## Mitigating CVE-2021-1675 and CVE 2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v CopyFilesPolicy /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v UpdatePromptSettings /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f | Out-Null
## Mitigating CVE-2021-1678
reg add "HKLM\System\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 1 /f | Out-Nulll
### Preventing regular users from installing printer drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured printer registry keys" -ForegroundColor white 

Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] PrintNightmare mitigations in place" -ForegroundColor white 

## Enabling Restricted Admin mode (disabling breaks auth via NTLM)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f | Out-Null
## Disabling Restricted Admin Outbound Creds
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Restricted Admin mode enabled" -ForegroundColor white 

# UAC token filtering
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] UAC restrictions applied to local accounts on network logons" -ForegroundColor white 

# LSASS Protections
## Enabling LSA protection mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
## Enabling LSASS audit mode
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
## Setting amount of time to clear logged-off users' credentials from memory (secs)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f | Out-Null
## Restricting remote calls to SAM to just Administrators
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] LSASS Protections in place" -ForegroundColor white 

# Disabling WDigest, removing storing plain text passwords in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] WDigest disabled" -ForegroundColor white 

## Setting screen saver grace period
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Screen saver grace period set to 0 seconds" -ForegroundColor white 

# Clear cached credentials
cmdkey /list | ForEach-Object{if($_ -like "*Target:*" -and $_ -like "*microsoft*"){cmdkey /del:($_ -replace " ","" -replace "Target:","")}}
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Cached credentials cleared" -ForegroundColor white 

# System security 
## Disable debug
bcdedit.exe /debug "{current}" off | Out-Null
bcdedit /bootdebug "{current}" off | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Boot and kernel debugging disabled" -ForegroundColor white
## Disable loading of test signed kernel-drivers, enable signature enforcement
bcdedit.exe /set "{current}" testsigning off | Out-Null
bcdedit.exe /set "{current}" nointegritychecks off | Out-Null
bcdedit.exe /set "{current}" loadoptions ENABLE_INTEGRITY_CHECKS | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Driver settings configured" -ForegroundColor white
## Make sure loading ELAM drivers isn't disabled
bcdedit.exe /set "{current}" disableelamdrivers no | Out-Null 
Write-Host "[" -ForegroundColor white -NoNewLine;
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] ELAM driver loading enabled" -ForegroundColor white 
## Enable DEP for all processes
bcdedit.exe /set "{current}" nx AlwaysOn | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled DEP for all processes" -ForegroundColor white 
## Disabling crash dump generation
reg add "HKLM\SYSTEM\CurrentControlSet\control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine;
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled Crash dump generation" -ForegroundColor white 
## Enabling automatic reboot after system crash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled automatic reboot after system crash" -ForegroundColor white 
## Requiring a password on wakeup
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled password required on wakeup" -ForegroundColor white 
## Disable WPBT (Windows Platform Binary Table) functionality
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled WPBT" -ForegroundColor white
## Enabling SEHOP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled SEHOP" -ForegroundColor white

# Explorer/file settings
## Changing file associations to make sure they have to be executed manually
cmd /c ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Set file associations" -ForegroundColor white
## Disabling 8.3 filename creation
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f | Out-Null
## Removing "Run As Different User" from context menus
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartBanner /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\mscfile\shell\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Removed 'Run As Different User' from context menus" -ForegroundColor white 
## Enabling visibility of hidden files, showing file extensions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "CheckedValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "CheckedValue" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled hidden file and file extension visibility" -ForegroundColor white 

# DLL funsies
## Enabling Safe DLL search mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f | Out-Null 
## Blocking DLL loading from remote folders
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled safe DLL search mode and blocked loading from unsafe folders" -ForegroundColor white
## Blocking AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled APPInit DLL loading" -ForegroundColor white

# ----------- Misc registry settings ------------
## Disabling remote access to registry paths
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled remote access to registry paths" -ForegroundColor white
## Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled processing of RunOnce keys" -ForegroundColor white

# ----------- Misc keyboard and language fixing ------------
## Setting font registry keys
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Emoji (TrueType)" /t REG_SZ /d "seguiemj.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "seguisli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Variable (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe MDL2 Assets (TrueType)" /t REG_SZ /d "segmdl2.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print (TrueType)" /t REG_SZ /d "segoepr.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print Bold (TrueType)" /t REG_SZ /d "segoeprb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script (TrueType)" /t REG_SZ /d "segoesc.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script Bold (TrueType)" /t REG_SZ /d "segoescb.ttf" /f | Out-Null
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Auto Activation Mode" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "InstallAsLink" /t REG_DWORD /d 0 /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Inactive Fonts" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Active Languages" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management\Auto Activation Languages" /f | Out-Null
## Set keyboard language to english
Remove-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload' -Name * -Force | Out-Null
reg add "HKCU\Keyboard Layout\Preload" /v 1 /t REG_SZ /d "00000409" /f | Out-Null
## Set default theme
Start-Process -Filepath "C:\Windows\Resources\Themes\aero.theme"
# Set UI lang to english
reg add "HKCU\Control Panel\Desktop" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\MUI\Settings" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Font, Themes, and Languages set to default" -ForegroundColor white

# ----------- Ease of access (T1546.008) ------------
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured Ease of Access registry keys" -ForegroundColor white

TAKEOWN /F C:\Windows\System32\sethc.exe /A | Out-Null
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\sethc.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Utilman.exe /A | Out-Null
ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Utilman.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\osk.exe /A | Out-Null
ICACLS C:\Windows\System32\osk.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\osk.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Narrator.exe /A | Out-Null
ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Narrator.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Magnify.exe /A | Out-Null
ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Magnify.exe -Force | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Removed vulnerable accessibility features" -ForegroundColor white

# Resetting service control manager (SCM) SDDL
sc.exe sdset scmanager "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)" | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Reset SCM SDDL" -ForegroundColor white 

# ----------- Subvert Trust Controls: Install Root Certificate (T1553.004) ------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" /v Flags /t REG_DWORD /d 1 /f | Out-Null

# ----------- WINDOWS DEFENDER/antimalware settings ------------
## Starting Windows Defender service
if(!(Get-MpComputerStatus | Select-Object AntivirusEnabled)) {
    Start-Service WinDefend
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Started Windows Defender service" -ForegroundColor white 
}
## Enabling Windows Defender sandboxing
cmd /c "setx /M MP_FORCE_USE_SANDBOX 1" | Out-Null
# Set a bunch of MpPreference settings
Set-MpPreference -AllowDatagramProcessingOnWinServer $true
Set-MpPreference -AllowNetworkProtectionDownLevel $true
Set-MpPreference -AllowNetworkProtectionOnWinServer $true
Set-MpPreference -AllowSwitchToAsyncInspection $true
Set-MpPreference -DisableDatagramProcessing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableFtpParsing $false
Set-MpPreference -DisableHttpParsing $false
Set-MpPreference -DisableInboundConnectionFiltering $false
Set-MpPreference -DisableRdpParsing $false
# important!!!
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableSmtpParsing 0
Set-MpPreference -DisableSshParsing $false
Set-MpPreference -DisableTlsParsing $false
Set-MpPreference -EnableDnsSinkhole $true
# also important!!!
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -OobeEnableRtpAndSigUpdate $true
# i think this is important
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -UILockdown $false

## Force Defender to be in active mode
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
## Enabling Windows Defender PUP protection (DEPRECATED, but why not leave it in just in case?)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured Windows Defender" -ForegroundColor white 
## Removing and updating Windows Defender signatures
& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All | Out-Null
Update-MpSignature
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Updated Windows Defender signatures" -ForegroundColor white 
## Setting exploit guard settings via config file
try {
    Set-ProcessMitigation -PolicyFilePath (Join-Path -Path $ConfPath -ChildPath "settings.xml") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Configured Windows Defender Exploit Guard" -ForegroundColor white 
} catch {
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
    Write-Host "] Detected old Defender version, skipping configuring Exploit Guard" -ForegroundColor white 
}
## Removing exclusions in Defender
try {
    ForEach ($ex_asr in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ex_asr | Out-Null
    }
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Removed ASR exceptions" -ForegroundColor white
} catch {
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
    Write-Host "] Detected old Defender version, skipping ASR" -ForegroundColor white 
}
ForEach ($ex_extension in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ex_extension | Out-Null
}
ForEach ($ex_dir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ex_dir | Out-Null
}
ForEach ($ex_proc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ex_proc | Out-Null
}
ForEach ($ex_ip in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ex_ip | Out-Null
}
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Removed Defender exclusions" -ForegroundColor white

# Set Defender UI profile
& "C:\Program Files\DefenderUI\DefenderUI.exe" -CustomProfile LYCME
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Defender UI profile set" -ForegroundColor white

# ----------- Service security ------------
## Stopping psexec with the power of svchost
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f | Out-Null
# Write-Host "[" -ForegroundColor white -NoNewLine;
# Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
# Write-Host "] Added psexec mitigation" -ForegroundColor white 
## Disabling offline files
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v Start /t REG_DWORD /d 4 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled offline files" -ForegroundColor white 
## Disabling UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled UPnP" -ForegroundColor white 
## Disabling DCOM cuz why not - TODO: Enable if on ADCS
# reg add "HKLM\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /f | Out-Null
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled DCOM" -ForegroundColor white 
## I hate print spooler
if ((Get-Service -Name spooler).Status -eq "Running") {
    Stop-Service -Name spooler -Force -PassThru | Set-Service -StartupType Disabled | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine;
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Shut down and disabled Print Spooler" -ForegroundColor white 
}

## Disabling weak encryption protocols
& (Join-Path -Path $ToolPath -ChildPath "IISCryptoCli.exe") /template (Join-Path -Path $ConfPath -ChildPath "ciphers.ictpl")
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured SChannel cipher suites" -ForegroundColor white

## SMB protections
### Disable SMB compression (CVE-2020-0796 - SMBGhost)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled SMB compression" -ForegroundColor white
### Disabling SMB1 server-side processing (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled SMB v1 server (Win 7 and below)" -ForegroundColor white
### Disabling SMB1 client driver
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10" /v Start /t REG_DWORD /d 4 /f | Out-Null
### Disabling client-side processing of SMBv1 protocol (pre-Win8.1/2012R2)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v DependOnService /t REG_MULTI_SZ /d "Bowser\0MRxSMB20\0NSI" /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled SMB v1 client (and driver)" -ForegroundColor white
### Enabling SMB2/3 and encryption (modern Windows)
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force | Out-Null
Set-SmbServerConfiguration -EncryptData $true -Force | Out-Null
## Microsoft-Windows-SMBServer\Audit event 3000 shows attempted connections
Set-SmbServerConfiguration -AuditSmb1Access $true -Force | Out-Null
### Enabling SMB2/3 (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine;
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Enabled SMB v2, v3, and data encryption" -ForegroundColor white
## Disabling SMB admin shares (Server)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
## Disabling SMB admin shares (Workstation)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled SMB administrative shares" -ForegroundColor white
## Hide computer from browse list
reg add "HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Hidden computer from share browse list" -ForegroundColor white

## RPC settings
### Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f | Out-Null
### Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Configured RPC settings" -ForegroundColor white

# Resetting BITS transfer (Windows Update needs this so don't throttle)
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 54000 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine;
Write-Host "INFO" -ForegroundColor yellow -NoNewLine;
Write-Host "] BITS transfer settings reset" -ForegroundColor white 

# ----------- Networking settings ------------
# T1557 - Countering poisoning via WPAD - Disabling WPAD
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DisableWpad /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f | Out-Null
# this disables the service - not recommended because it can break applications!
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHTTPAutoProxySvc" /v Start /t REG_DWORD /d 4 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled WPAD" -ForegroundColor white 
# T1557.001 - Countering poisoning via LLMNR/NBT-NS/MDNS
## Disabling LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /f | Out-Null
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled LLMNR" -ForegroundColor white 
## Disabling smart multi-homed name resolution
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled SMHNR" -ForegroundColor white 
## Disabling NBT-NS via registry for all interfaces (might break something)
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 | Out-Null }
## Disabling NetBIOS broadcast-based name resolution
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /t REG_DWORD /d 2 /f | Out-Null
## Enabling ability to ignore NetBIOS name release requests except from WINS servers
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled NBT-NS" -ForegroundColor white 
## Disabling mDNS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableMDNS /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled mDNS" -ForegroundColor white 
## Flushing DNS cache
ipconfig /flushdns | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Flushed DNS cache" -ForegroundColor white 
## Disabling ipv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f | Out-null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled IPv6" -ForegroundColor white 
## Disabling source routing for IPv4 and IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Disabled IP source routing" -ForegroundColor white 
## Disable password saving for dial-up (lol)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /t REG_DWORD /d 1 /f | Out-Null
## Disable automatic detection of dead network gateways
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled automatic detection of dead gateways" -ForegroundColor white 
## Enable ICMP redirect using OSPF
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
 Write-Host "] Enabled OSPF ICMP redirection" -ForegroundColor white 
## Setting how often keep-alive packets are sent (ms)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 300000 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured keep-alive packet interval" -ForegroundColor white 
## Disabling IRDP
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Disabled IRDP" -ForegroundColor white 
# Disabling IGMP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Disabled IGMP" -ForegroundColor white 
## Setting SYN attack protection level
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured SYN attack protection level" -ForegroundColor white 
## Setting SYN-ACK retransmissions when a connection request is not acknowledged
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Configured SYN-ACK retransmissions" -ForegroundColor white 
## Setting how many times unacknowledged data is retransmitted for IPv4 and IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
Write-Host "] Set maximum times data is retransmitted" -ForegroundColor white 
## Configuring IPSec exemptions (Only ISAKMP is exempt)
reg add "HKLM\System\CurrentControlSet\Services\IPSEC" /v NoDefaultExempt /t REG_DWORD /d 3 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Configured IPSec exemptions" -ForegroundColor white 

# Windows Update/Internet Communication
reg add "HKLM\SOFTWARE\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AllowMUUpdateService" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
Write-Host "] Windows Update settings configured" -ForegroundColor white

# ----------- Functions for AD security ------------
Function Write-Results {
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Path,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$Domain
    )
    
    $Acl = Get-Acl -Path $Path 
    Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
    Write-Host ($Path.Substring($Path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
    Write-Output -InputObject $Acl.Access
}
Function Set-Auditing {
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Domain,

        [Parameter(Position=1,Mandatory=$true)]
        [AllowEmptyString()]
        [String]$ObjectCN,

        [Parameter(Position=2,Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules 
    )
    
    $DN = (Get-ADDomain -Identity $Domain).DistinguishedName
    [String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name

    $TempDrive = "tempdrive"

    if ($Drives.Contains($TempDrive)) {
        Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
        $OldDrive = Get-PSDrive -Name $TempDrive
        Remove-PSDrive -Name $TempDrive
    }

    $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $Domain
    Push-Location -Path "$Drive`:\"
    
    if ($ObjectCN -eq "") {
        $ObjectDN = $DN
    } else {
        $ObjectDN = $ObjectCN + "," + $DN
    }
    
    $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $Domain
    $Path = $ObjectToChange.DistinguishedName

    try {
        $Acl = Get-Acl -Path $Path -Audit

        if ($Acl -ne $null) {
            foreach ($Rule in $Rules) {
                $Acl.AddAuditRule($Rule)
            }
            Set-Acl -Path $Path -AclObject $Acl
            # Write-Results -Path $Path -Domain $Domain
        } else {
            Write-Warning "Could not retrieve the ACL for $Path"
        }
    } catch [System.Exception] {
        Write-Warning $_.ToString()
    }
    Pop-Location
    
    Remove-PSDrive $Drive

    if ($OldDrive -ne $null) {
        Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
        New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
        $OldDrive = $null
    }
}
Function New-EveryoneAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll, 
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        
    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainControllersAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)

    Write-Output -InputObject $Rules
}
Function New-InfrastructureObjectAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    #$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-PolicyContainerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
Function New-DomainAuditRuleSet {
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$DomainSID    
    )

    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)
    $Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner), 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
        
Function New-RIDManagerAuditRuleSet {
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

    Write-Output -InputObject $Rules
}
# ----------- DC security ------------
if ($DC) {
    # CVE-2020-1472 - ZeroLogon
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v vulnerablechannelallowlist /f | Out-Null
    # Enable netlogon debug logging - %windir%\debug\netlogon.log - watch for event IDs 5827 & 5828
    nltest /DBFlag:2080FFFF | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] ZeroLogon mitigations in place" -ForegroundColor white
    
    # CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac)
    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] nopac mitigations in place" -ForegroundColor white

    # Only allowing DSRM Administrator account to be used when ADDS is stopped 
    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 1 /f | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Configured DSRM administator account usage" -ForegroundColor white

    # Disable unauthenticated LDAP 
    $RootDSE = Get-ADRootDSE
    $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
    Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1'}
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Disabled unauthenticated LDAP" -ForegroundColor white

    # Setting max connection time 
    [string]$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser -Server $env:COMPUTERNAME).RootDomain -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
    [System.Int32]$MaxConnIdleTime = 180
    [string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
	[Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
	$AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits

    for ($i = 0; $i -lt $AdminLimits.Count; $i++) {
		if ($AdminLimits[$i] -match "MaxConnIdleTime=*") {
			break
		}
	}   
    if ($i -lt $AdminLimits.Count) {
		$AdminLimits[$i] = "MaxConnIdleTime=$MaxConnIdleTime" 
	} else {
		$AdminLimits.Add("MaxConnIdleTime=$MaxConnIdleTime")
	}
    Set-ADObject -Identity $Policies -Clear lDAPAdminLimits
    foreach ($Limit in $AdminLimits) {
		Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
	}
    Write-Output -InputObject (Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"})
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Configured maximum time for LDAP connections" -ForegroundColor white

    # Setting dsHeuristics (disable anon LDAP)
    $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName)
    $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
    [string]$Heuristic = $DirectoryService.dsHeuristics

    [array]$Array = @()
    if (($Heuristic -ne $null) -and ($Heuristic -ne [System.String]::Empty) -and ($Heuristic.Length -ge 7)) {
        $Array = $Heuristic.ToCharArray()
        $Array[6] = "0";
    } else {
        $Array = "0000000"
    }

    [string]$Heuristic = "$Array".Replace(" ", [System.String]::Empty)
    if ($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty) {
        Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
    }
    $Result = Get-ADObject -Identity $DirectoryService -Properties dsHeuristics | Select-Object -ExpandProperty dsHeuristics
    if ($Result -ne $null) {
        Write-Output ("dsHeuristics: " + $Result)
        Write-Host "[" -ForegroundColor white -NoNewLine; 
        Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
        Write-Host "] Disabled anonymous LDAP" -ForegroundColor white
    } else {
        Write-Warning "dsHeuristics is not set"
    }
    
    # Resetting NTDS folder and file permissions
    $BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
    $LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)

    $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow       
    )

    $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
        @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $NTDS = Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    $DSA = $NTDS.'DSA Database File'
    $Logs = $NTDS.'Database log files path'
    $DSA = $DSA.Substring(0, $DSA.LastIndexOf("\"))
    
    $ACL1 = Get-Acl -Path $DSA
    foreach ($Rule in $ACL1.Access) {
        $ACL1.RemoveAccessRule($Rule) | Out-Null
    }
    $ACL1.AddAccessRule($AdministratorAce)
    $ACL1.AddAccessRule($SystemAce)

    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
    Write-Host "] Setting $DSA ACL" -ForegroundColor white

    # need to change perms on folder to set file perms correctly
    Set-Acl -Path $DSA -AclObject $ACL1
    Get-ChildItem -Path $DSA | ForEach-Object {
        $Acl = Get-Acl -Path $_.FullName
        foreach ($Rule in $Acl.Access) {
            if (-not $Rule.IsInherited) {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        Set-Acl -Path $_.FullName -AclObject $Acl
    }

    # $Logs = path to the NTDS folder, so this fixes perms on that
    $ACL2 = Get-Acl -Path $Logs
    foreach ($Rule in $ACL2.Access) {
        $ACL2.RemoveAccessRule($Rule) | Out-Null
    }
    $ACL2.AddAccessRule($AdministratorAce)
    $ACL2.AddAccessRule($SystemAce)
    $ACL2.AddAccessRule($LocalServiceAce)
    $ACL2.AddAccessRule($CreatorOwnerAce)

    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
    Write-Host "] Setting $Logs ACL" -ForegroundColor white

    Set-Acl -Path $Logs -AclObject $ACL2
    Get-ChildItem -Path $Logs | ForEach-Object {
        $Acl = Get-Acl -Path $_.FullName
        foreach ($Rule in $Acl.Access) {
            if (-not $Rule.IsInherited) {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        Set-Acl -Path $_.FullName -AclObject $Acl
    }

    # surely this will not break things
    $Domain = (Get-ADDomain -Current LocalComputer).DNSRoot

    # Set RID Manager Auditing
    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Enabled RID Manager auditing" -ForegroundColor white

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"
    Write-Host "[" -ForegroundColor white -NoNewLine;
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Enabled GPO auditing" -ForegroundColor white

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Enabled auditing on Domain object" -ForegroundColor white

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on Infrastructure object" -ForegroundColor white

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on Domain Controllers object" -ForegroundColor white

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
    Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on AdminSDHolder object" -ForegroundColor white

    # T1003.001 - delete vss shadow copies (removing copies of NTDS database)
    vssadmin.exe delete shadows /all /quiet
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Deleted VSS shadow copies" -ForegroundColor white

    ## TODO: Split DNS secure settings into own category
    # Sign zone with DNSSEC
    Invoke-DnsServerZoneSign -ZoneName $Domain -SignWithDefault -PassThru -Force
    # Preventing cache poisoning attacks
    reg add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v SecureResponses /t REG_DWORD /d 1 /f | Out-Null
    # SIGRed - CVE-2020-1350
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 /f | Out-Null
    # CVE-2020-25705
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] CVE-2020-1350 and CVE-2020-25705 mitigations in place" -ForegroundColor white   
    # Enabling global query block list (disabled IPv6 to IPv4 tunneling)
    Set-DnsServerGlobalQueryBlockList -Enable $true | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Enabled global query block list for DNS" -ForegroundColor white   
    # Enabling response rate limiting
    Set-DnsServerRRL -Mode Enable -Force | Out-Null
    Set-DnsServerRRL -ResetToDefault -Force | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Response rate limiting enabled" -ForegroundColor white   
    # Ensure DNS server restarts after failure + other settings
    Set-DnsServerCache -PollutionProtection $true
    Set-DnsServerDiagnostics -EventLogLevel 3
    dnscmd /config /EnableVersionQuery 0
    Set-DnsServerRecursion -Enable $false
    sc.exe failure DNS reset= 10 actions= restart/10000/restart/10000/restart/10000
    net stop DNS
    net start DNS
    Write-Host "[INFO] AD/DNS hardening in place"
}

# IIS security
if ($IIS) {
 # Imports the WebAdministration module
    Import-Module WebAdministration
    
    # Gets all sites under IIS:\Sites
    $sites = Get-ChildItem IIS:\Sites

    foreach ($site in $sites) {
        $siteName = $site.Name
        $siteBindings = Get-WebBinding -Name $siteName

        $isWebServer = $false
        $isFtpServer = $false

        # Checks the bindings to differentiate between web and FTP servers
        foreach ($binding in $siteBindings) {
            $bindingInformation = $binding.BindingInformation
            Write-Host "Site: $siteName - Binding: $bindingInformation"
            
            # Checks if the site is an HTTP/HTTPS web server (based on common HTTP/HTTPS ports)
            if ($bindingInformation -match ":80" -or $bindingInformation -match ":443") {
                $isWebServer = $true
                Write-Host "$siteName is an HTTP/HTTPS web server"
            }

            # Checks if the site is an FTP server (based on FTP port 21)
            if ($bindingInformation -match ":21") {
                $isFtpServer = $true
                Write-Host "$siteName is an FTP server"
            }
        }

        # Applies hardening steps for Web Server
        if ($isWebServer) {
            Write-Host "Applying Web server hardening for $siteName"

            # Set application pool privileges to minimum for application pools
            foreach ($item in (Get-ChildItem IIS:\AppPools)) { 
                $tempPath = "IIS:\AppPools\" + $item.Name
                Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
            }

            # Disables directory browsing for all sites using appcmd
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/directoryBrowse /enabled:"False"

            # Enables logging for all sites using appcmd
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/httpLogging /dontLog:"True" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/httpLogging /selectiveLogging:"LogAll" /commit:apphost

            # Disables anonymous authentication for all sites using Set-WebConfiguration
            Set-WebConfiguration -Filter "/system.webServer/security/authentication/anonymousAuthentication" -PSPath "IIS:\Sites\$siteName" -Value 0

            # Sets HTTP Errors statusCode to 405 for all sites
            Set-WebConfiguration -Filter "/system.webServer/httpErrors" -PSPath "IIS:\Sites\$siteName" -Value @{errorMode="Custom"; existingResponse="Replace"; statusCode=405}

            # Applies request filtering to block potentially dangerous file extensions
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='exe',allowed='False']"
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='bat',allowed='False']"
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /+"fileExtensions.[fileExtension='ps1',allowed='False']"

            # Applies request filtering to block HTTP TRACE and OPTIONS
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /+"verbs.[verb='OPTIONS',allowed='False']"
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.webServer/security/requestFiltering /+"verbs.[verb='TRACE',allowed='False']"

            # Enables Logging for IIS Web Management
            reg add "HKLM\Software\Microsoft\WebManagement\Server" /v EnableLogging /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Enabled IIS Web Management Logging."

            # Enables Remote Management for IIS
            reg add "HKLM\Software\Microsoft\WebManagement\Server" /v EnableRemoteManagement /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Enabled IIS Remote Management."

            # Enables IIS Admin Logging to ABO Mapper Log
            reg add "HKLM\System\CurrentControlSet\Services\IISADMIN\Parameters" /v EnableABOMapperLog /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Enabled IIS Admin Logging to ABO Mapper Log."

            # Disables TRACE HTTP Method (Security Measure)
            reg add "HKLM\System\CurrentControlSet\Services\W3SVC\Parameters" /v EnableTraceMethod /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Disabled TRACE HTTP Method."

            # Disables OPTIONS HTTP Method (Security Measure)
            reg add "HKLM\System\CurrentControlSet\Services\W3SVC\Parameters" /v EnableOptionsMethod /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Disabled OPTIONS HTTP Method."

            # Requires Windows Credentials for Remote IIS Management
            reg add "HKLM\SOFTWARE\Microsoft\WebManagement\Server" /v RequiresWindowsCredentials /t REG_DWORD /d 1 /f | Out-Null
            Write-Host "Enforced Windows Credentials for IIS Remote Management."

            # Prevents overrideMode for authentication settings (CURRENTLY LOCKS OUT USER)
            #Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication" -Name "overrideMode" -Value "Deny" -PSPath "IIS:\Sites\$siteName"

        }

        # Applies hardening steps for FTP Server
        if ($isFtpServer) {
            Write-Host "Applying FTP server hardening for $siteName"

            # Enables basic authentication for FTP
            Set-WebConfigurationProperty -pspath "IIS:\" -filter "system.applicationHost/sites/site[@name='$siteName']/ftpServer/security/authentication/basicAuthentication" -name "enabled" -value "true"

            # Disables anonymous authentication for FTP
            Set-WebConfigurationProperty -pspath "IIS:\" -filter "system.applicationHost/sites/site[@name='$siteName']/ftpServer/security/authentication/anonymousAuthentication" -name "enabled" -value "false"

            # Limits the maximum number of simultaneous FTP connections
            Set-WebConfigurationProperty -pspath "IIS:\" -filter "system.applicationHost/sites/site[@name='$siteName']/ftpServer/connections" -name "maxConnections" -value 5
            
            # Enables Central FTP Logging
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/log /centralLogFileMode:"Central" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/log /centralLogFile.enabled:"True" /commit:apphost

            # Other important file handling settings
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.applicationHost/sites /siteDefaults.ftpServer.fileHandling.keepPartialUploads:"False" /commit:apphost.ftpServer.logFile.enabled:"True" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.applicationHost/sites /siteDefaults.ftpServer.fileHandling.allowReadUploadsInProgress:"False" /commit:apphost.ftpServer.logFile.enabled:"True" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.applicationHost/sites /siteDefaults.ftpServer.fileHandling.allowReplaceOnRename:"False" /commit:apphost.ftpServer.logFile.enabled:"True" /commit:apphost

            # Disables FTP Passive Mode (Not Working)
            #$externalIP = (Invoke-WebRequest ifconfig.me/ip).Content.Trim()
            #Set-WebConfigurationProperty -filter "system.applicationHost/sites/site[@name='$sitename']/ftpServer/firewallSupport" -name "externalIp4Address" -value $externalIP

            # Limits the size of files uploaded to the FTP server
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/security/requestFiltering /requestLimits.maxAllowedContentLength:"1000000" /requestLimits.maxUrl:"1024" /commit:apphost
            
            # Blocks dangerous file extensions
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/security/requestFiltering /+"fileExtensions.[fileExtension='.bat',allowed='False']" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/security/requestFiltering /+"fileExtensions.[fileExtension='.exe',allowed='False']" /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/security/requestFiltering /+"fileExtensions.[fileExtension='.ps1',allowed='False']" /commit:apphost
           
            # Configures FTP authorization rules (for FTP Users Group)
            C:\Windows\System32\inetsrv\appcmd.exe clear config $siteName /section:system.ftpServer/security/authorization /commit:apphost
            C:\Windows\System32\inetsrv\appcmd.exe set config $siteName -section:system.ftpServer/security/authorization /+"[accessType='Allow',roles='FTP Users',permissions='Read']" /commit:apphost
        }
    }
    # Restarts IIS services to apply changes
    Write-Host "Restarting IIS services to apply changes..."
    iisreset

    Write-Host "[INFO] IIS Hardening Configurations Applied Successfully."
}

# OpenSSH
$sshConfigServer = @"
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

StrictModes yes

UseDNS yes

MaxAuthTries 3

MaxSessions 1

LoginGraceTime 10

ClientAliveInterval 300
ClientAliveCountMax 3

IgnoreRhosts Yes

PermitEmptyPasswords no

PermitUserEnvironment no

PermitRootLogin no

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

Banner none
"@

$sshConfigClient = @"
Host *
 KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

 Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

 MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

 HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

 CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@
$sshConfigClientV9 = @"
 HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@
# OpenSSH server
if (Get-Service -Name 'sshd' -ErrorAction SilentlyContinue) {
    Import-Module (Join-Path -Path $ToolPath -ChildPath "OpenSSHUtils.psm1")
    # add openssh to path
    $opensshPath = "$env:WINDIR\System32\OpenSSH"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    if (-not ($currentPath.Split(';') -contains $opensshPath)) {
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$currentPath;$opensshPath",
            [EnvironmentVariableTarget]::Machine
        )
    }
    # set default shell
    reg add "HKLM\SOFTWARE\OpenSSH" /v DefaultShell /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f | Out-Null
    reg add "HKLM\SOFTWARE\OpenSSH" /v DefaultShellCommmandOption /t REG_SZ /d "/c" /f | Out-Null
    Stop-Service sshd
    # backup original config
    $sshDir =  Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh"
    $sshConfig = Join-Path -Path $sshDir -ChildPath "sshd_config"
    $backupConfig = Join-Path -Path $sshDir -ChildPath "sshd_config.bak"
    if (Test-Path -Path $sshConfig) {
        Copy-Item -Path $sshConfig -Destination $backupConfig -Force  
        # edit config file
        $lineToFind = "#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key"
        $fileContent = Get-Content -Path $sshConfig
        $lineIndex = $fileContent.IndexOf($lineToFind)
        if ($lineIndex -ge 0) {
            $newContent = $fileContent[$lineIndex] + "`r`n" + $sshConfigServer
            $fileContent[$lineIndex] = $newContent
            Set-Content -Path $sshConfig -Value $fileContent
            Write-Host "OpenSSH server configuration has been added to $sshConfig"
        } else {
            Write-Warning "The specified line '$lineToFind' was not found in the file."
        }
        Repair-SshdConfigPermission -FilePath $sshConfig
    }
    # regenerate host keys and repair permissions
    Get-ChildItem -Path $sshDir -Filter "ssh_host_*_key*" | ForEach-Object {
        Rename-Item $_.FullName "$($_.FullName).bak"
    }
    & "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -A
    Get-ChildItem -Path $sshDir -Filter "ssh_host_*_key*" | ForEach-Object {
        Repair-SshdHostKeyPermission -FilePath $_.FullName
    }
    # (re)generate moduli and repair file permissions
    $moduliPath = Join-Path -Path $sshDir -ChildPath "moduli"
    if (Test-Path -Path $moduliPath) {
        Get-Content $moduliPath | ForEach-Object {
            $fields = $_ -split "\s+"
            if ($fields[4] -as [int] -ge 3071) {
                $_
            }
        } | Set-Content "$env:TEMP\moduli.safe"
        Copy-Item "$env:TEMP\moduli.safe" "C:\ProgramData\ssh\moduli" -Force
        Repair-ModuliFilePermission -FilePath "C:\ProgramData\ssh\moduli"
    } 
    # repair authorized keys permissions
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"  -ErrorAction SilentlyContinue | % {
        $properties =  Get-ItemProperty $_.pspath  -ErrorAction SilentlyContinue
        $userProfilePath = ""
        if($properties)
        {
            $userProfilePath =  $properties.ProfileImagePath
        }
        $filePath = Join-Path $userProfilePath .ssh\authorized_keys
        if(Test-Path $filePath -PathType Leaf)
        {
            Repair-AuthorizedKeyPermission -FilePath $filePath
        }
    }
    # repair admin authorized key permissions
    $sshdAdministratorsAuthorizedKeysPath = join-path $env:ProgramData\ssh "administrators_authorized_keys"
    if (Test-Path $sshdAdministratorsAuthorizedKeysPath -PathType Leaf) {
        Repair-AdministratorsAuthorizedKeysPermission -FilePath $sshdAdministratorsAuthorizedKeysPath
    }
    # # repair file permissions
    $dirs = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $dirs) {
        $username = $dir.Name
        $sshPath = Join-Path -Path $dir.FullName -ChildPath ".ssh"
        $sid = Get-UserSID -User "$($env:USERDOMAIN)\$($username)"
        if (Test-Path $sshPath) {
            Repair-UserSshConfigPermission -FilePath (Join-Path -Path $sshPath -ChildPath "config") -UserSid $sid
            Get-ChildItem $sshPath* -Include "id_rsa","id_dsa","id_ecdsa","id_ed25519" -ErrorAction SilentlyContinue | ForEach-Object {
                Repair-UserKeyPermission -FilePath $_.FullName -UserSid $sid
            }
        }
    }
    # repair folder permissions
    Repair-SSHFolderPermission -FilePath $sshDir
    Restart-Service sshd 
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Configured OpenSSH Server and reset file permissions" -ForegroundColor white 
}
# OpenSSH client
if (Test-Path "$env:WINDIR\System32\OpenSSH\ssh.exe") {
    $sshDir = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh"
    $sshConfig = Join-Path -Path $sshDir -ChildPath "ssh_config"
    $backupConfig = Join-Path -Path $sshDir -ChildPath "ssh_config.bak"
    if (!(Test-Path $sshConfig)) {
        New-Item -ItemType File -Path $sshConfig -Force 
    } else {
        Copy-Item -Path $sshConfig -Destination $backupConfig -Force  
    }
    $sshConfigClient = $sshConfigClient -replace '(?<=MACs\s)([^\r\n]*)', '$1,hmac-sha2-256'
    Set-Content -Path $sshConfig -Value $sshConfigClient
    if ((& ssh -V 2>&1) -match "_9\.") {
        Add-Content -Path $sshConfig -Value $sshConfigClientV9
    }
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Configured OpenSSH client" -ForegroundColor white 
}

# Configure BitLocker
Enable-Bitlocker -MountPoint "C:" -EncryptionMethod XtsAes256 -Password $Password
Write-Host "[" -ForegroundColor white -NoNewLine; 
Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
Write-Host "] Bitlocker configured" -ForegroundColor white  

# Enabling Constrained Language Mode (the wrong way) (disabled for now because it breaks some tools)
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d 4 /f | Out-Null
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Constrained Language mode enabled" -ForegroundColor white   

# Report errors
$Error | Out-File (Join-Path -Path $currentDir -ChildPath "results\hard.txt") -Append -Encoding utf8

Write-Host "Hardening Script done! Please restart the system as soon as possible." -ForegroundColor Cyan
Write-Host "See " -NoNewline -ForegroundColor Cyan; Write-Host (Join-Path -Path $currentDir -ChildPath "results\hard.txt") -ForegroundColor Magenta -NoNewline; Write-Host " for errors." -ForegroundColor Cyan

# Chandi Fortnite
