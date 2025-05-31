param(
    [Parameter(Mandatory=$false)]
    [Array]$extraDirs
)

[string]$path = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\backup.ps1"))

if (!(Test-Path -Path (Join-Path $path "backup"))) {
    New-Item -Path $path -Name "backup" -ItemType "directory" | Out-Null
}
[string]$backupParentPath = (Join-Path $path "backup")
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
[string]$backupPath = (Join-Path $backupParentpath $dateTime)

if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    New-Item -Path $backupPath -Name "sysvol" -ItemType "directory" | Out-Null
    robocopy c:\windows\sysvol (Join-Path $backupPath "sysvol") /copyall /mir /b /r:0 /xd | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SYSVOL folder backed up" -ForegroundColor white

    dnscmd /exportsettings | Out-Null
    New-Item -Path $backupPath -Name "dns_backup" -ItemType "directory" | Out-Null
    xcopy /E /I C:\Windows\System32\dns (Join-Path -Path $backupPath -childPath "dns_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DNS folder backed up" -ForegroundColor white
}

if (Get-Service -Name W3SVC 2>$null) {
    xcopy /E /I C:\inetpub (Join-Path -Path $backupPath -childPath "iis_backup") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] IIS folder backed up" -ForegroundColor white
}

if (Get-Service -Name CertSvc 2>$null) {
    New-Item -Path $backupPath -Name "ca_backup" -ItemType "directory" | Out-Null
    New-Item -Path (Join-Path -Path $backupPath -childPath "ca_backup") -Name "ca_templates" -ItemType "directory" | Out-Null
    certutil -backupDB (Join-Path -Path $backupPath -childPath "ca_backup") | Out-Null
    Get-CATemplate | Foreach-Object { $_.Name } | Out-File -FilePath (Join-Path -Path $backupPath -childPath "ca_backup\ca_templates\CATemplates.txt") -Encoding String -Force
    Get-Content -Path (Join-Path -Path $backupPath -ChildPath "ca_backup\ca_templates\CATemplates.txt") | ForEach-Object {certutil -v -template $_ > (Join-Path -Path $backupPath -ChildPath "ca_backup\ca_templates\$_.txt")}
    reg export HKLM\System\CurrentControlSet\Services\CertSvc\Configuration (Join-Path -Path $backupPath -childPath "ca_backup\regkey.reg") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] CA certs, templates, and settings backed up" -ForegroundColor white
}

if (Get-Service -Name WinRM 2>$null) {
    New-Item -Path $backupPath -Name "winrm" -ItemType "directory" | Out-Null
    $winrmConfigBackupPath = Join-Path -Path $backupPath -childPath "winrm\winrm_config_backup.txt"
    winrm get winrm/config > $winrmConfigBackupPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM configuration backed up" -ForegroundColor white
}

# Notes for xcopy
# /H - Include Hidden Files
# /I - Creates the Destination Directory if it doesn't exist (Kind of)
# /K - Retains read-only perms on read-only files
# /S - Copy Subdirectories
# /X - Copy File Audit settings and file ACLs

# Wazuh agent backup 
# xcopy "C:\Program Files (x86)\ossec-agent\client.keys" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\ossec.conf" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\*.pem" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\ossec.log" $backupPath /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\logs\*"  $backupPath\logs\ /H /I /K /S /X | Out-Null
# xcopy "C:\Program Files (x86)\ossec-agent\rids\*"  $backupPath\rids\ /H /I /K /S /X | Out-Null
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh agent files backed up" -ForegroundColor white

# Back up Extra Directories
foreach ($dir in $extraDirs){
    # xcopy doesn't work with a triling '\'
    if ($dir[$dir.Length - 1] -eq "\"){
        $dir = $dir.substring(0, $dir.Length - 1)
    }
    # Get the Last directory, because that is going to be the name of the directory within the backup
    $dirs = $dir -split "\\"
    $lastDir = $dirs[$dirs.Length - 1]
    
    # Copy over the directory
    xcopy $dir (Join-Path -Path $backupPath -ChildPath $lastDir) /H /I /K /S /X | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] $($lastDir) folder backed up" -ForegroundColor white
}
