$me = $Env:UserName
$superSecretPassword = ConvertTo-SecureString "Password-12345" -AsPlainText -Force
[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("zookeeper.ps1"))

Write-Host "Warning -- Run this script after all forensics or after you are sure that no required information is in an unauthorized user's home."
Write-Host "this script will delete unauthorized users permantly, a snapshot might also be a good idea"

$authorizedDir =  "C:\users\$me\Desktop\authorizedUsers.txt"

try {
	New-Item -ErrorAction Stop $authorizedDir | Out-Null 
	
	Write-Host "Added a txt to the desktop. Copy paste the authorized users there, one per line"
	Write-Host 'Press any key to continue...';
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	Write-Host ""
} catch {
    Write-Host "Using existing file."
}


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
Write-Host 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-Host ""

if ($IsDC) {
	$DomainUsers = Get-ADUser -filter *
	foreach ($DomainUser in $DomainUsers) {
		if (-not($DomainUser.Name -in $AllowUsers)) {
			Disable-ADAccount -Name $DomainUser.Name
			Write-Host "[INFO]" $DomainUser.Name "disabled"
		} 
	}
} else {
	$LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
	foreach ($LocalUser in $LocalUsers) {
		if (-not($LocalUser.Name -in $AllowUsers)) {
			Disable-LocalUser -Name $LocalUser.Name
			Write-Host "[INFO]" $LocalUser.Name "disabled"
		}
	}
}

Write-Host "Now wait for a score check. If you don't loose points for a disabled user then continue."
Write-Host "If you do loose points then go fix the user list and renable the account. DO NOT CONTINUE"
Write-Host 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-Host ""

Write-Host "Step2: DELETE all users not on the list"
Write-Host 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-Host ""

if ($IsDC) {
	$DomainUsers = Get-ADUser -filter *
	foreach ($DomainUser in $DomainUsers) {
		if (-not($DomainUser.Name -in $AllowUsers)) {
			Remove-ADAccount -Name $DomainUser.Name
			Write-Host "[INFO]" $DomainUser.Name "is no longer with us"
		} 
	}
} else {
	$LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
	foreach ($LocalUser in $LocalUsers) {
		if (-not($LocalUser.Name -in $AllowUsers) -and (-not($LocalUser.Name -in @("Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount")))) {
			Remove-LocalUser -Name $LocalUser.Name
			Write-Host "[INFO]" $LocalUser.Name "is no longer with us"
		}
	}
}

Write-Host "Step3: Create Missing Users"
if ($IsDC) {
	foreach ($User in $AllowUsers){
		try{
			New-ADUser -Name $User -Password $superSecretPassword -ErrorAction Stop
			Write-Host "[INFO]" $User "created"
		}
		catch{continue}
	}
} else {
	foreach ($User in $AllowUsers){
		try{
			New-LocalUser -Name $User -Password $superSecretPassword -ErrorAction Stop
			Write-Host "[INFO]" $User "created"
		}
		catch{continue}
	}
}

Write-Host "Step4: Permission remaining users"
Write-Host "[Warning] This will reset all passwords (except yours) to Password-12345"
Write-Host 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
Write-Host ""

 if ($IsDC) {
	$DomainUsers = Get-ADUser -filter *
	foreach ($DomainUser in $DomainUsers) {
		if(-not($DomainUser.name -eq $me)){
			Enable-ADAccount -Name $DomainUser.Name
			$DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $true -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -UserMayChangePassword $true -PasswordNotRequired $false
			net user $DomainUser.Name $superSecretPassword
			Write-Host "[INFO]" $DomainUser.Name "secured"
		}
	}
} else {
	$LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
	foreach ($LocalUser in $LocalUsers) {
		if(-not($LocalUser.name -eq $me)){
			Enable-LocalUser -Name $LocalUser.Name
			$LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires
			net user $LocalUser.Name $superSecretPassword | Out-Null
			net user $LocalUser.Name /PASSWORDREQ:YES | Out-Null
			Write-Host "[INFO]" $LocalUser.Name "secured"
		}
	}
}



#chandi fortnite