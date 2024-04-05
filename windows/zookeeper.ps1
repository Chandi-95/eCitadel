$me = $Env:UserName
[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("zookeeper.ps1"))

Write-Host "Warning -- Run this script after all forensics or after you are sure that no required information is in an unauthorized user's home."
Write-Host "this script will delete unauthorized users permantly, a snapshot might also be a good idea"

$authorizedDir =  "C:\users\$me\Desktop\authorizedUsers.txt"
Create-Item $authorizedDir

Write-Host "Added a txt to the desktop. Copy paste the authorized users there, one per line"
Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

try {
    [string[]]$AllowUsers = Get-Content $authorizedDir
} catch {
    Write-Host "[ERROR] Unable to get list of users"
    exit 1
}

if ($AllowUsers.length -lt 2) {
	Write-Host "[ERROR] user list is suspiciously small"
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

Write-Host "Step1: Disable all users not on the list"
Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

if ($IsDC) {
	$DomainUsers = Get-ADUser -filter *
	foreach ($DomainUser in $DomainUsers) {
		if (-not $DomainUser.Name -in $UserList) {
			Disable-ADAccount -Name $DomainUser.Name
			Write-Host "[INFO]" $DomainUser.Name "disabled"
		}
        else {
			$LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
			foreach ($LocalUser in $LocalUsers) {
				if (-not $LocalUser.Name -in $UserList) {
					Disable-LocalUser -Name $LocalUser.Name
					Write-Host "[INFO]" $LocalUser.Name "disabled"
				}
			}
    }

#chandi fortnite