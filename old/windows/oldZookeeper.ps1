$me = $Env:UserName
$superSecretPassword = ConvertTo-SecureString "Password-12345" -AsPlainText -Force
[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("zookeeper.ps1"))

Write-Host "[Info] Made a back up user. Blue|Password-12345" -ForegroundColor Blue
net user blue Password-12345 /add 2>$null
net localgroup Administrators /add blue

Write-Host "[Warning] Run this script after all forensics or after you are sure that no required information is in an unauthorized-" -ForegroundColor Yellow
Write-Host "[Warning] user's home. this script will delete unauthorized users permantly, a snapshot might also be a good idea." -ForegroundColor Yellow
Write-Host ""

$authorizedDir = "C:\users\$me\Desktop\authorizedUsers.txt"

try {
    New-Item -ErrorAction Stop $authorizedDir | Out-Null

    Write-Host "[Instruction] Added a txt to the desktop. Copy paste the authorized users there, one per line" -ForegroundColor White
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
} 
catch {
    Write-Host "[Info] Using existing file." -ForegroundColor Blue
}

try {
    [string[]]$AllowUsers = Get-Content $authorizedDir
} 
catch {
    Write-Host "[ERROR] Unable to get list of users" -ForegroundColor Red
    exit 1
}

if ($AllowUsers.length -lt 2) {
    Write-Host "[ERROR] User list is suspiciously small" -ForegroundColor Red
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected" -ForegroundColor Blue
}

Write-Host ""
Write-Host "Step1: Disable all users not on the list" -ForegroundColor Magenta
Write-Host 'Press <enter> to continue...' -ForegroundColor Gray
while ($resp.Key -notlike "Enter") {
    while (-not [console]::KeyAvailable) {
        Start-Sleep -Milliseconds 50
    }
    $resp = [console]::ReadKey($true)
}
$resp = "CTRL"
Write-Host ""

if ($IsDC) {
    $DomainUsers = Get-ADUser -filter "name!='$Env:Username' and name!='blue'"
    foreach ($DomainUser in $DomainUsers) {
        if ((-not($DomainUser.Name -in $AllowUsers)) -and (-not($DomainUser.Name -eq $me))) {
            Disable-ADAccount -Name $DomainUser.Name
            Write-Host "[INFO]" $DomainUser.Name "disabled" -ForegroundColor Blue
        }
    }
} 
else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
    foreach ($LocalUser in $LocalUsers) {
        if (-not($LocalUser.Name -in $AllowUsers)) {
            Disable-LocalUser -Name $LocalUser.Name
            Write-Host "[INFO]" $LocalUser.Name "disabled" -ForegroundColor Blue
        }
    }
}

Write-Host ""
Write-Host "[Instruction] Now wait for a score check. If you don't loose points for a disabled user then continue." -ForegroundColor White
Write-Host "[Instruction] If you do loose points then go fix the user list and renable the account. DO NOT CONTINUE" -ForegroundColor White
Write-Host 'Press <enter> to continue...' -ForegroundColor Gray
while ($resp.Key -notlike "Enter") {
    while (-not [console]::KeyAvailable) {
        Start-Sleep -Milliseconds 50
    }
    $resp = [console]::ReadKey($true)
}
$resp = "CTRL"
Write-Host ""

Write-Host "Step2: DELETE all users not on the list" -ForegroundColor Magenta
Write-Host 'Press <enter> to continue...' -ForegroundColor Gray
while ($resp.Key -notlike "Enter") {
    while (-not [console]::KeyAvailable) {
        Start-Sleep -Milliseconds 50
    }
    $resp = [console]::ReadKey($true)
}
$resp = "CTRL"
Write-Host ""

if ($IsDC) {
    $DomainUsers = Get-ADUser -filter "name!='$Env:Username' and name!='blue'"
    foreach ($DomainUser in $DomainUsers) {
        if ((-not($DomainUser.Name -in $AllowUsers)) -and (-not($DomainUser.Name -eq $me))) {
            Remove-ADUser -Name $DomainUser.Name
            Write-Host "[INFO]" $DomainUser.Name "is no longer with us" -ForegroundColor Blue
        }
    }
} 
else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='blue'"
    foreach ($LocalUser in $LocalUsers) {
        if (-not($LocalUser.Name -in $AllowUsers) -and (-not($LocalUser.Name -in @("Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount", "blue")))) {
            Remove-LocalUser -Name $LocalUser.Name
            Write-Host "[INFO]" $LocalUser.Name "is no longer with us" -ForegroundColor Blue
        }
    }
}

Write-Host ""
Write-Host "Step3: Create Missing Users" -ForegroundColor Magenta
Write-Host ""

if ($IsDC) {
    foreach ($User in $AllowUsers) {
        try {
            New-ADUser -Name $User -Password $superSecretPassword -ErrorAction Stop
            Write-Host "[INFO]" $User "created" -ForegroundColor Blue
        }
        catch {
            continue
        }
    }
} 
else {
    foreach ($User in $AllowUsers) {
        try {
            New-LocalUser -Name $User -Password $superSecretPassword -ErrorAction Stop
            Write-Host "[INFO]" $User "created" -ForegroundColor Blue
        }
        catch {
            continue
        }
    }
}

Write-Host ""
Write-Host "Step4: Permission remaining users" -ForegroundColor Magenta
Write-Host "[Warning] This will reset all passwords (except yours) to Password-12345" -ForegroundColor Yellow
Write-Host 'Press <enter> to continue...' -ForegroundColor Gray
while ($resp.Key -notlike "Enter") {
    while (-not [console]::KeyAvailable) {
        Start-Sleep -Milliseconds 50
    }
    $resp = [console]::ReadKey($true)
}
$resp = "CTRL"

if ($IsDC) {
    $DomainUsers = Get-ADUser -filter "name!='$Env:Username' and name!='blue'"
    foreach ($DomainUser in $DomainUsers) {
        if (-not($DomainUser.name -eq $me)) {
            Enable-ADAccount -Name $DomainUser.Name
            $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $true -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -UserMayChangePassword $true -PasswordNotRequired $false
            net user $DomainUser.Name $superSecretPassword
            Write-Host "[INFO]" $DomainUser.Name "secured" -ForegroundColor Blue
        }
    }
} 
else {
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username' and name!='blue'"
    foreach ($LocalUser in $LocalUsers) {
        if (-not($LocalUser.name -eq $me)) {
            Enable-LocalUser -Name $LocalUser.Name
            $LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires
            net user $LocalUser.Name $superSecretPassword | Out-Null
            net user $LocalUser.Name /PASSWORDREQ:YES | Out-Null
            Write-Host "[INFO]" $LocalUser.Name "secured" -ForegroundColor Blue
        }
    }
}

Write-Host ""
Write-Host "Step5: Audit Groups" -ForegroundColor Magenta
Write-Host 'Press <enter> to continue...' -ForegroundColor Gray
while ($resp.Key -notlike "Enter") {
    while (-not [console]::KeyAvailable) {
        Start-Sleep -Milliseconds 50
    }
    $resp = [console]::ReadKey($true)
}
$resp = "CTRL"

if ($IsDC) {
    foreach ($group in Get-ADGroup | Where-Object Name -notlike "Domain Users") {
        foreach ($member in Get-ADGroupMember -Identity $group.Name) {
            $prompt = "[Instruction] Should user " + $Member.Name + " be in " + $Group.Name + ": Y/n "
            $yn = read-host $prompt

            if ($yn -eq "n" -or $yn -eq "N") {
                Remove-ADGroupMember -Identity $Group -Member $member
                Write-Host "[INFO]" $member.Name " has been removed from " $group.Name -ForegroundColor Blue
            }
        }
        while (1) {
            $prompt = "[Instruction] Should there be more users in $group.name? (enter for no or type a name)"
            $resp = read-host $prompt
            if ($resp -eq "") {
                break
            }
            Add-ADGroupMember -Identity $group.name -Members $resp
        }
    }
} 
else {
    foreach ($group in get-localgroup | Where-Object Name -notlike "Users") {
        foreach ($member in Get-LocalGroupMember -Group $group.Name) {
            $prompt = "[Instruction] Should user " + $Member.Name + " be in " + $Group.Name + ": Y/n "
            $yn = read-host $prompt

            if ($yn -eq "n" -or $yn -eq "N") {
                Remove-LocalGroupMember -Group $Group -Member $member
                Write-Host "[INFO]" $member.Name " has been removed from " $group.Name -ForegroundColor Blue
            }
        }
        while (1) {
            $prompt = "[Instruction] Should there be more users in $($group.name)? (enter for no or type a name)"
            $resp = read-host $prompt
            if ($resp -eq "") {
                break
            }
            net localgroup $group.name /add $resp
        }
    }
}

#chandi fortnite