param(
    [Parameter()]
    [String]$filepath 
)

[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("usermgmt.ps1"))

try {
    [string[]]$AllowUsers = Get-Content $filepath
} catch {
    Write-Host "[ERROR] Unable to get list of users"
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

Function Set-krbtgtPassword([bool] $IsDC) {
    Clear-Host
    if ($IsDC) {
        $krbtgtPath = Join-Path -Path $currentDir -ChildPath "Reset-KrbtgtKeyInteractive.ps1"
        & $krbtgtPath
    } else {
        Write-Host "[ERROR] Computer is not a domain controller"
        exit
    }
}
Function Set-Password([string]$UserName, [bool]$IsDC) {
    Clear-Host
    $Password = Read-Host -AsSecureString "Password"
    $Password2 = Read-Host -AsSecureString "Confirm Password"
    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))

    if ($pwd1_text -cne $pwd2_text) {
        Write-Host "[ERROR] Passwords don't match" 
        exit
    } else {
        if ($IsDC) {
            Set-ADAccountPassword -Identity $UserName -NewPassword $Password
            Write-Host "[INFO] Password set for" $UserName
        } else {
            Set-LocalUser -Name $UserName -Password $Password
            Write-Host "[INFO] Password set for" $UserName
        }
    }
}

Function Set-UserProperties([string[]]$UserList, [bool]$IsDC) {
    if ($IsDC) {
        $DomainUsers = Get-ADUser -filter *
        foreach ($DomainUser in $DomainUsers) {
            if ($DomainUser.Name -in $UserList) {
                # Enable-ADAccount -Name $DomainUser.Name
                # -AccountNotDelegated $true disabled due to competition using delegated accounts
                $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -UserMayChangePassword $false -PasswordNotRequired $false
                # $DomainUser | Set-ADAccountControl -DoesNotRequirePreAuth $false
                Disable-ADAccount -Name $DomainUser.Name
                Write-Host "[INFO]" $DomainUser.Name "disabled"
            } else {
                # Write-Host "[INFO]" $DomainUser.Name "disabled"
            }
        }
    } else {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
        foreach ($LocalUser in $LocalUsers) {
            if ($LocalUser.Name -in $UserList) {
                # Enable-LocalUser -Name $LocalUser.Name
                $LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires
                Disable-LocalUser -Name $LocalUser.Name
                Write-Host "[INFO]" $LocalUser.Name "disabled"
            } else { 
                # Write-Host "[INFO]" $LocalUser.Name "disabled"
            }
        }
    }
}

while ($true) {
    Write-Host "Options:"
    Write-Host "1. Change passwords for all users in list"
    Write-Host "2. Change password for current user"
    Write-Host "3. Disable all users in list and apply proper user properties"
    Write-Host "4. Reset krbtgt password"
    Write-Host "5. Exit"
    $option = Read-Host "Enter an option"
    
    if ($option -eq '1') {
        foreach ($user in $AllowUsers) {
            Set-Password -UserName $user -IsDC $DC
        }
    } elseif ($option -eq '2') {
        Set-Password -UserName $Env:UserName -IsDC $DC
    } elseif ($option -eq '3') {
        Set-UserProperties -UserList $AllowUsers -IsDC $DC
    } elseif ($option -eq '4') {
        Set-krbtgtPassword -IsDC $DC
    } elseif ($option -eq '5') {
        exit 0
    } else {
        Write-Host "Invalid option, try again"
    }
}
#Chandi Fortnite