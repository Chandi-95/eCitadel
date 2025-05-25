# user management script for wildcard
# Authors: Asa Horn & Chandi Kanhai
param(
    [Parameter(mandatory=$true)]
    [String]$UserList
)

# Initial setup
function Generate-RandomPassword($length = 15) {
    $password = -join ((33..126) | Get-Random -Count $length | ForEach-Object {[char]$_})
	return $password
}

[string]$CmdPath = $MyInvocation.MyCommand.Path
$CurrentDir = $CmdPath.substring(0, $CmdPath.IndexOf("zookeeper.ps1"))

try {
    [string[]]$AllowedUsers = Get-Content $UserList
} catch {
	Write-Host "[" -ForegroundColor white -NoNewLine; 
	Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
	Write-Host "] Unable to get list of users" -ForegroundColor white 
    exit 1
}
if ($AllowedUsers.length -lt 2) {
	Write-Host "[" -ForegroundColor white -NoNewLine; 
	Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
	Write-Host "] Less than 2 users found. Double check the user list" -ForegroundColor white 
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

Write-Host "`n
	Step 1: Create Missing Users`n" -ForegroundColor magenta -BackgroundColor white
Write-Host ""
if ($DC) {
    foreach ($User in $AllowedUsers) {
        $exists = Get-ADUser -Filter "SamAccountName -like '$User'" -ErrorAction SilentlyContinue
        if ($exists -eq $null) {
            # New-ADUser -Name $User -AccountPassword $superSecretPassword
            Write-Host "[INFO]" $User "created"
        }
    }
} else {
    foreach ($User in $AllowedUsers) {
        $exists = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
        if ($exists -eq $null) {
			try {
				$PlaintextPassword = Generate-RandomPassword
				$SecurePassword = ConvertTo-SecureString $PlaintextPassword -AsPlainText -Force
				# New-LocalUser -Name $User -Password $SecurePassword | Out-Null
				Write-Host "[" -ForegroundColor white -NoNewLine; 
				Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
				Write-Host "] User " -ForegroundColor white -NoNewLine;
				Write-Host $User -ForegroundColor cyan -NoNewLine;
				Write-Host " created, password: " -ForegroundColor white -NoNewLine;
				Write-Host $PlaintextPassword -ForegroundColor cyan; 
			} catch {
				Write-Host "[" -ForegroundColor white -NoNewLine; 
				Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
				Write-Host "] Creating user " -ForegroundColor white -NoNewLine;
				Write-Host $User -ForegroundColor cyan -NoNewLine;
				Write-Host " failed." -ForegroundColor white
			}
        }
    }
}

# Adding backup user
$PlaintextPassword = Generate-RandomPassword
$SecurePassword = ConvertTo-SecureString $PlaintextPassword -AsPlainText -Force
$BackupUser = 'blue'
try {
	# New-LocalUser -Name $BackupUser -Password $SecurePassword | Out-Null
	# net localgroup Administrators $BackupUser /add | Out-Null
	# if ($DC) {
		# Add-ADGroupMember -Identity "Domain Admins" -Members $BackupUser | Out-Null
	# }
	Write-Host "[" -ForegroundColor white -NoNewLine; 
	Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
	Write-Host "] Backup user " -ForegroundColor white -NoNewLine;
	Write-Host $BackupUser -ForegroundColor cyan -NoNewLine;
	Write-Host " created, password: " -ForegroundColor white -NoNewLine;
	Write-Host $PlaintextPassword -ForegroundColor cyan; 
} catch {
	Write-Host "[" -ForegroundColor white -NoNewLine; 
	Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
	Write-Host "] Adding backup user failed." -ForegroundColor white;
}

Write-Host "`n
	Step 2: Disable all users not on the list & enable authorized users`n" -ForegroundColor magenta -BackgroundColor white
Write-Host ""
if ($DC) {
    # $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike '$backupusername'"
    # foreach ($DomainUser in $DomainUsers) {
        # if (!($DomainUser.Name -in $AllowUsers)) {
            # Disable-ADAccount -Identity $DomainUser
            # Write-Host "[INFO]" $DomainUser.Name "disabled"
        # } else {
            # Enable-ADAccount -Identity $DomainUser
            # Write-Host "[INFO]" $DomainUser.Name "enabled"
        # }
    # }
} else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='$BackupUser'"
    foreach ($LocalUser in $LocalUsers) {
        if (!($LocalUser.Name -in $AllowedUsers)) {
            # Disable-LocalUser -Name $LocalUser.Name
			Write-Host "[" -ForegroundColor white -NoNewLine; 
			Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
			Write-Host "] User " -ForegroundColor white -NoNewLine;
            Write-Host $LocalUser.Name -ForegroundColor cyan -NoNewLine;
			Write-Host " is now " -ForegroundColor white -NoNewLine;
			Write-Host "DISABLED" -ForegroundColor red -BackgroundColor black;
        } else {
            # Enable-LocalUser -Name $LocalUser.Name
			Write-Host "[" -ForegroundColor white -NoNewLine; 
			Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
			Write-Host "] User " -ForegroundColor white -NoNewLine;
            Write-Host $LocalUser.Name -ForegroundColor cyan -NoNewLine;
			Write-Host " is now " -ForegroundColor white -NoNewLine;
			Write-Host "ENABLED" -ForegroundColor green -BackgroundColor black;
        }
    }
}

# Deleting unauthorized users
$choice = $(Write-Host) + $(Write-Host "Would you like to delete unauthorized users (Y/n)?" -ForegroundColor magenta -BackgroundColor yellow -NoNewLine) + $(Write-Host " " -NoNewLine; Read-Host) 
if ($choice -eq "Y") {
	Write-Host ""
    if ($DC) {
        $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike 'Guest' -and SamAccountName -notlike 'Administrator' -and SamAccountName -notlike '$backupusername'"
        foreach ($DomainUser in $DomainUsers) {
            if (!($DomainUser.Name -in $AllowedUsers)) {
                # Remove-ADUser -Identity $DomainUser
                Write-Host "[INFO]" $DomainUser.Name "gone"
            }
        }
    } else {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='$BackupUser' and name!='Administrator' and name!='Guest' and name!='WDAGUtilityAccount' and name!='DefaultAccount'"
        foreach ($LocalUser in $LocalUsers) {
            if (!($LocalUser.Name -in $AllowedUsers)) {
                # Remove-LocalUser -Name $LocalUser.Name
                Write-Host "[" -ForegroundColor white -NoNewLine; 
				Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
				Write-Host "] User " -ForegroundColor white -NoNewLine;
				Write-Host $LocalUser.Name -ForegroundColor cyan -NoNewLine;
				Write-Host " has been " -ForegroundColor white -NoNewLine;
				Write-Host "DELETED" -ForegroundColor red -BackgroundColor black;
            } 
        }
    }
}

Write-Host "`n
	Step 3: Set permissions and reset passwords for authorized users`n" -ForegroundColor magenta -BackgroundColor white
Write-Host ""
if ($DC) {
    $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike 'Guest' -and SamAccountName -notlike 'Administrator'"
    foreach ($DomainUser in $DomainUsers) {
        # $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -PasswordNotRequired $false -AccountNotDelegated $true 
        # $DomainUser | Set-ADAccountControl -DoesNotRequirePreAuth $false
        # Set-ADAccountPassword -Identity $DomainUser -NewPassword $superSecretPassword
        Write-Host "[INFO]" $DomainUser.Name "secured"
    }
} else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='Administrator' and name!='Guest' and name!='WDAGUtilityAccount' and name!='DefaultAccount'"
    foreach ($LocalUser in $LocalUsers) {
		$PlaintextPassword = Generate-RandomPassword
		$SecurePassword = ConvertTo-SecureString $PlaintextPassword -AsPlainText -Force
		# net user $LocalUser.Name /passwordreq:yes
        # $LocalUser | Set-LocalUser -Password $SecurePassword -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires $true 
        Write-Host "[" -ForegroundColor white -NoNewLine; 
		Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
		Write-Host "] User " -ForegroundColor white -NoNewLine;
		Write-Host $LocalUser.Name -ForegroundColor cyan -NoNewLine;
		Write-Host " secured, password: " -ForegroundColor white -NoNewLine;
		Write-Host $PlaintextPassword -ForegroundColor cyan; 
    }
}

Write-Host "`n
	Step 4: Audit Groups`n" -ForegroundColor magenta -BackgroundColor white
Write-Host ""

if ($DC) {
    # foreach ($group in (Get-ADGroup -Filter 'Name -ne "Domain Users"')) {
        # Write-Host "Current Group: $($group.Name)" -ForegroundColor Cyan
        # Write-Host ""
        # foreach ($member in Get-ADGroupMember -Identity $group) {
            # $prompt = "Should user " + $member.Name + " be in this group (Y/n)?"
            # $choice = Read-Host $prompt
            # if ($choice -eq "n") {
                # Remove-ADGroupMember -Identity $group -Member $member
            # }
            # Clear-Host
        # }
        # Write-Host "Current Group: $($group.Name)" -ForegroundColor Cyan
        # Write-Host "Members:`n$($(Get-ADGroupMember -Identity $group).Name)"
        # Write-Host ""
        # $prompt = "Should there be more users in $group.name (Y/n)?"
        # $choice = Read-Host $prompt
        # if ($choice -eq "Y") {
            # while(1) { 
                # $name = Read-Host "Enter the username to add (enter no username to exit)"
                # if ($name -eq "") {
                    # break
                # } else {
                    # Add-ADGroupMember -Identity $group -Members $name
                # }
            # }
        # }
    # } 
} else {
	Write-Host "[" -ForegroundColor white -NoNewLine; 
	Write-Host "INFO" -ForegroundColor yellow -NoNewLine; 
	Write-Host "] Manual audit of local group membership required" -ForegroundColor white
}

#chandi fortnite
