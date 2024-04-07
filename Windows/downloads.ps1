# Objective: downloads scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

# *-WindowsFeature - Roles and Features on Windows Server 2012 R2 and above
# *-WindowsCapability - Features under Settings > "Optional Features"
# *-WindowsOptionalFeature - Featuers under Control Panel > "Turn Windows features on or off" (apparently this is compatible with Windows Server)

param (
    [string]$Path = $(throw "-Path is required.")
)

# somehow this block verifies if the path is legit
$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
        break
    }
    $true
})]
$InputPath = $Path
Set-Location -Path $InputPath | Out-Null

# Creating all the directories
$ErrorActionPreference = "Continue"
New-Item -Path $InputPath -Name "scripts" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "installers" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "tools" -ItemType "directory" | Out-Null
$ScriptPath = Join-Path -Path $InputPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $InputPath -ChildPath "installers"
$ToolsPath = Join-Path -Path $InputPath -ChildPath "tools"

New-Item -Path $ScriptPath -Name "conf" -ItemType "directory" | Out-Null
New-Item -Path $ScriptPath -Name "results" -ItemType "directory" | Out-Null
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"
$ResultsPath = Join-Path -Path $ScriptPath -ChildPath "results"

New-Item -Path $ResultsPath -Name "artifacts" -ItemType "directory" | Out-Null
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory" | Out-Null
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Directories created" -ForegroundColor white

# yo i hope this works
if ((Get-CimInstance -Class Win32_OperatingSystem).Caption -match "Windows Server") {
    Install-WindowsFeature -Name Bitlocker,Windows-Defender
    # the following feature might not exist based on the windows server version
    Install-WindowsFeature -Name Windows-Defender-GUI
}

# Custom tooling downloads
$ProgressPreference = 'SilentlyContinue'
# Audit script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1", (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# Backups script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1", (Join-Path -Path $ScriptPath -ChildPath "backup.ps1"))
# Command runbook
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt", (Join-Path -Path $ScriptPath -ChildPath "command_runbook.txt"))
# Defender exploit guard settings
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml", (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml"))  
# Firewall script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
# Inventory script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1", (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
# Logging script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
# Wazuh agent config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/agent_windows.conf", (Join-Path -Path $ConfPath -ChildPath "agent_windows.conf"))
# Yara response script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat", (Join-Path -Path $ScriptPath -ChildPath "yara.bat"))
# TODO: replace with proper link to zookeeper.ps1
# User Management script 
(New-Object System.Net.WebClient).DownloadFile("", (Join-Path -Path $ScriptPath -ChildPath ""))
# Secure baseline script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/secure.ps1", (Join-Path -Path $ScriptPath -ChildPath "secure.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] System scripts and config files downloaded" -ForegroundColor white

# Service tooling 
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { # DC detection
    # RSAT tooling (AD management tools + DNS management)
    Install-WindowsFeature -Name RSAT-AD-Tools,RSAT-DNS-Server,GPMC
    # Domain, Domain Controller, and admin template GPOs 
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/gpos/%7B2FF38BB4-4B44-44FE-9E95-5426EC5EE2C7%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{2FF38BB4-4B44-44FE-9E95-5426EC5EE2C7}.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/gpos/%7B065414B1-7553-477D-A047-5169D6A5D587%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{065414B1-7553-477D-A047-5169D6A5D587}.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/gpos/%7B3281473A-F66C-423B-B824-DB24CB2B7DC5%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{3281473A-F66C-423B-B824-DB24CB2B7DC5}.zip"))
    # Reset-KrbtgtKeyInteractive script
    (New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1", (Join-Path -Path $ScriptPath -ChildPath "Reset-KrbtgtKeyInteractive.ps1"))
    # Pingcastle
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/vletoux/pingcastle/releases/download/3.1.0.1/PingCastle_3.1.0.1.zip", (Join-Path -Path $InputPath -ChildPath "pc.zip"))
    # Adalanche
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe", (Join-Path -Path $ToolsPath -ChildPath "adalanche.exe"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools downloaded" -ForegroundColor white
    # Pingcastle, GPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pc.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "pc") 
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{2FF38BB4-4B44-44FE-9E95-5426EC5EE2C7}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{065414B1-7553-477D-A047-5169D6A5D587}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{3281473A-F66C-423B-B824-DB24CB2B7DC5}.zip") -DestinationPath $ConfPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools extracted" -ForegroundColor white
} else { # non-DC server/client tools
    # Administrative template GPO
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/gpos/%7B3281473A-F66C-423B-B824-DB24CB2B7DC5%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{3281473A-F66C-423B-B824-DB24CB2B7DC5}.zip"))
    # Local policy security template
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Hivestorm/main/Windows/gpos/msc-sec-template.inf", (Join-Path -Path $ConfPath -ChildPath "msc-sec-template.inf"))
    # LGPO tool
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and local policy files downloaded" -ForegroundColor white
    # LGPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO extracted" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) { # ADCS tools
    # Add package manager and repository for PowerShell
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
    # install dependency for locksmith (AD PowerShell module) and ADCS management tools
    Install-WindowsFeature -Name RSAT-AD-PowerShell,RSAT-ADCS-Mgmt
    # install locksmith
    Install-Module -Name Locksmith -Scope CurrentUser
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Locksmith downloaded and installed" -ForegroundColor white
}

# Server Core Tooling
if ((Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion") -and (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty "InstallationType") -eq "Server Core") {
    # Explorer++
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", (Join-Path -Path $InputPath -ChildPath "epp.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "epp.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "epp")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Explorer++ downloaded and extracted" -ForegroundColor white
    # Server Core App Compatibility FOD
    Add-WindowsCapability -Online -Name ServerCore.AppCompatibility~~~~0.0.1.0
    # NetworkMiner
    (New-Object System.Net.WebClient).DownloadFile("https://netresec.com/?download=NetworkMiner", (Join-Path -Path $InputPath -ChildPath "nm.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "nm.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "nm")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] NetworkMiner downloaded and extracted" -ForegroundColor white
}

# Third-party tooling for every system
# Get-InjectedThread and Stop-Thread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Stop-Thread.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Get-InjectedThread and Stop-Thread downloaded" -ForegroundColor white
# PrivEsc checker script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1", (Join-Path -Path $ScriptPath -ChildPath "PrivescCheck.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PrivescChecker script downloaded" -ForegroundColor white
# chainsaw + dependency library
$redistpath = Join-Path -Path $SetupPath -ChildPath "vc_redist.64.exe"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip", (Join-Path -Path $InputPath -ChildPath "cs.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", $redistpath)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw and C++ redist downloaded" -ForegroundColor white
## silently installing dependency library
& $redistpath /install /passive /norestart
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] C++ redist installed" -ForegroundColor white
# hollows hunter
(New-Object System.Net.WebClient).DownloadFile("https://github.com/hasherezade/hollows_hunter/releases/latest/download/hollows_hunter64.zip", (Join-Path -Path $InputPath -ChildPath "hh64.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter downloaded" -ForegroundColor white
# Wazuh agent
(New-Object System.Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi", (Join-Path -Path $SetupPath -ChildPath "wazuhagent.msi"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh agent installer downloaded" -ForegroundColor white
# Basic Sysmon conf file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Sysmon config downloaded" -ForegroundColor white
# Windows Firewall Control + .NET 4.8
$net48path = Join-Path -Path $SetupPath -ChildPath "net_installer.exe"
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?LinkId=2085155", $net48path)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Windows Firewall Control and .NET 4.8 installers downloaded" -ForegroundColor white
## silently installing .NET 4.8 library
& $net48path /passive /norestart
# Malwarebytes
(New-Object System.Net.WebClient).DownloadFile("https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe", (Join-Path -Path $SetupPath -ChildPath "MBSetup.exe"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Malwarebytes installer downloaded" -ForegroundColor white
# PatchMyPC
(New-Object System.Net.WebClient).DownloadFile("https://patchmypc.com/freeupdater/PatchMyPC.exe", (Join-Path -Path $ToolsPath -ChildPath "PatchMyPC.exe"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PatchMyPC downloaded" -ForegroundColor white
# BCU
(New-Object System.Net.WebClient).DownloadFile("https://github.com/Klocman/Bulk-Crap-Uninstaller/releases/download/v5.7/BCUninstaller_5.7_portable.zip", (Join-Path -Path $InputPath -ChildPath "bcu.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] BCU downloaded" -ForegroundColor white
# Everything
(New-Object System.Net.WebClient).DownloadFile("https://www.voidtools.com/Everything-1.4.1.1024.x86.zip", (Join-Path -Path $InputPath -ChildPath "everything.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Everything downloaded" -ForegroundColor white
# Meld
(New-Object System.Net.WebClient).DownloadFile("https://download.gnome.org/binaries/win32/meld/3.22/Meld-3.22.2-mingw.msi", (Join-Path -Path $InputPath -ChildPath "meld.msi"))
msiexec /i (Join-Path -Path $InputPath -ChildPath "meld.msi") /quiet /qn /norestart
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Meld downloaded and installed" -ForegroundColor white
# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "st.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $InputPath -ChildPath "sm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AccessChk.zip", (Join-Path -Path $InputPath -ChildPath "ac.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AccessEnum.zip", (Join-Path -Path $InputPath -ChildPath "ae.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white
# yara
(New-Object System.Net.WebClient).DownloadFile("https://github.com/VirusTotal/yara/releases/download/v4.5.0/yara-master-2251-win64.zip", (Join-Path -Path $InputPath -ChildPath "yara.zip"))
## yara rules
(New-Object System.Net.WebClient).DownloadFile("https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip", (Join-Path -Path $InputPath -ChildPath "elastic.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules downloaded" -ForegroundColor white

# Extraction
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "st.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "st")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ac.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ac")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ac.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ae")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "hh64.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter extracted" -ForegroundColor white
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "cs.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "yara.zip") -DestinationPath $ToolsPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "elastic.zip") -DestinationPath $InputPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "bcu.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "bcu")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] BCU extracted" -ForegroundColor white
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "everything.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "everything")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Everything extracted" -ForegroundColor white
#Chandi Fortnite
