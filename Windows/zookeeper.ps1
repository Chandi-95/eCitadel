# user management script for wildcard
# Authors: Asa Horn & Chandi Kanhai
param(
    [Parameter()]
    [String]$filepath 
)

[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("zookeeper.ps1"))

try {
    [string[]]$AllowUsers = Get-Content $filepath
} catch {
    Write-Host "[ERROR] Unable to get list of users"
    exit 1
}
if ($AllowUsers.length -lt 2) {
    Write-Host "[ERROR] User list is suspiciously small" -ForegroundColor Red
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

$Password = "Password-12345!"
$superSecretPassword = ConvertTo-SecureString $Password -AsPlainText -Force

# adding backup user
$backupusername = 'blue'
New-LocalUser -Name $backupusername -Password $superSecretPassword
net localgroup Administrators blue /add
if ($DC) {
    Add-ADGroupMember -Identity "Domain Admins" -Members "blue"
}
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Backup user blue created, password: $Password" -ForegroundColor white 

Write-Host ""
Write-Host "Step 1: Create Missing Users" -ForegroundColor Magenta
Write-Host ""

if ($DC) {
    foreach ($User in $AllowUsers) {
        $exists = Get-ADUser -Filter "SamAccountName -like '$User'" -ErrorAction SilentlyContinue
        if ($exists -eq $null) {
            New-ADUser -Name $User -AccountPassword $superSecretPassword
            Write-Host "[INFO]" $User "created"
        }
    }
} else {
    foreach ($User in $AllowUsers) {
        $exists = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
        if ($exists -eq $null) {
            New-LocalUser -Name $User -Password $superSecretPassword
            Write-Host "[INFO]" $User "created"
        }
    }
}

Write-Host ""
Write-Host "Step 2: Disable all users not on the list and enable authorized users" -ForegroundColor Magenta
Write-Host ""

if ($DC) {
    $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike '$backupusername'"
    foreach ($DomainUser in $DomainUsers) {
        if (!($DomainUser.Name -in $AllowUsers)) {
            Disable-ADAccount -Identity $DomainUser
            Write-Host "[INFO]" $DomainUser.Name "disabled"
        } else {
            Enable-ADAccount -Identity $DomainUser
            Write-Host "[INFO]" $DomainUser.Name "enabled"
        }
    }
} else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='$backupusername'"
    foreach ($LocalUser in $LocalUsers) {
        if (!($LocalUser.Name -in $AllowUsers)) {
            Disable-LocalUser -Name $LocalUser.Name
            Write-Host "[INFO]" $LocalUser.Name "disabled"
        } else {
            Enable-LocalUser -Name $LocalUser.Name
            Write-Host "[INFO]" $LocalUser.Name "enabled"
        }
    }
}

$choice = Read-Host "Would you like to delete unauthorized users (Y/n)?"
if ($choice -eq "Y") {
    if ($DC) {
        $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike 'Guest' -and SamAccountName -notlike 'Administrator' -and SamAccountName -notlike '$backupusername'"
        foreach ($DomainUser in $DomainUsers) {
            if (!($DomainUser.Name -in $AllowUsers)) {
                Remove-ADUser -Identity $DomainUser
                Write-Host "[INFO]" $DomainUser.Name "gone"
            }
        }
    } else {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='$backupusername' and name!='Administrator' and name!='Guest' and name!='WDAGUtilityAccount' and name!='DefaultAccount'"
        foreach ($LocalUser in $LocalUsers) {
            if (!($LocalUser.Name -in $AllowUsers)) {
                Remove-LocalUser -Name $LocalUser.Name
                Write-Host "[INFO]" $LocalUser.Name "gone"
            } 
        }
    }
}

Write-Host ""
Write-Host "Step 3: Permission and reset passwords for authorized users" -ForegroundColor Magenta
Write-Host ""

if ($DC) {
    $DomainUsers = Get-ADUser -Filter "SamAccountName -notlike '$Env:UserName' -and SamAccountName -notlike 'krbtgt' -and SamAccountName -notlike 'Guest' -and SamAccountName -notlike 'Administrator'"
    foreach ($DomainUser in $DomainUsers) {
        $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -PasswordNotRequired $false -AccountNotDelegated $true 
        $DomainUser | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Set-ADAccountPassword -Identity $DomainUser -NewPassword $superSecretPassword
        Write-Host "[INFO]" $DomainUser.Name "secured"
    }
} else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='Administrator' and name!='Guest' and name!='WDAGUtilityAccount' and name!='DefaultAccount'"
    foreach ($LocalUser in $LocalUsers) {
        $LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires -Password $superSecretPassword
        net user $LocalUser.Name /passwordreq:yes
        Write-Host "[INFO]" $LocalUser.Name "secured"
    }
}

Write-Host ""
Write-Host "Step 4: Audit Groups" -ForegroundColor Magenta
Write-Host ""

if ($IsDC) {
    foreach ($group in (Get-ADGroup -Filter 'Name -ne "Domain Users"')) {
        Write-Host "Current Group: $($group.Name)" -ForegroundColor Cyan
        Write-Host ""
        foreach ($member in Get-ADGroupMember -Identity $group) {
            $prompt = "Should user " + $member.Name + " be in this group (Y/n)?"
            $choice = Read-Host $prompt
            if ($choice -eq "n") {
                Remove-ADGroupMember -Identity $group -Member $member
            }
            Clear-Host
        }
        Write-Host "Current Group: $($group.Name)" -ForegroundColor Cyan
        Write-Host "Members:`n$($(Get-ADGroupMember -Identity $group).Name)"
        Write-Host ""
        $prompt = "Should there be more users in $group.name (Y/n)?"
        $choice = Read-Host $prompt
        if ($choice -eq "Y") {
            while(1) { 
                $name = Read-Host "Enter the username to add (enter no username to exit)"
                if ($name -eq "") {
                    break
                } else {
                    Add-ADGroupMember -Identity $group -Members $name
                }
            }
        }
    } 
}   

#chandi fortnite
