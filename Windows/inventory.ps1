# *-WindowsFeature - Roles and Features on Windows Server 2012 R2 and above
# *-WindowsCapability - Features under Settings > "Optional Features"
# *-WindowsOptionalFeature - Featuers under Control Panel > "Turn Windows features on or off" (apparently this is compatible with Windows Server)

$CssPath = (Join-Path (($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("inventory.ps1")))  "report.css")

$PreContent = "<div class='container'>`n<h1 style='text-align: center;'>Host Information Report</h1>`n"

$ComputerName = "<h2>Computer name: $env:computername</h2>"

$DomainName = ""
if (Test-Path env:USERDNSDOMAIN) {
	$DomainName = "<h2>Domain: $env:userdnsdomain</h2>"
}

$OSInfo = Get-CimInstance -Class Win32_OperatingSystem | 
	Select-Object @{n='Name';e={$_.Caption}},
		@{n='Version';e={$_.Version}},
		@{n='Build';e={$_.BuildNumber}},
		@{n='Architecture';e={$_.OSArchitecture}},
		@{n='WinDir';e={$_.WindowsDirectory}},
		@{n='SystemDir';e={$_.SystemDirectory}} |
	ConvertTo-Html -Fragment -PreContent "<h3>Operating System Information</h3>"

$UserInfo = ""
if (!(Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"')) {
	$UserInfo = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = 'True'" | ForEach-Object {
		$userName = $_.Name
		$groups = Get-WmiObject -Class Win32_GroupUser |  ForEach-Object {
			# Parse PartComponent to extract the username
			$user = $_.PartComponent -match 'Win32_UserAccount.*Name="([^"]+)"' | Out-Null
			if ($Matches[1] -eq $userName) {
				# Parse GroupComponent to extract the group name
				$_.GroupComponent -match 'Win32_Group.*Name="([^"]+)"' | Out-Null
				$Matches[1] # Return the group name
			}
		}

		[PSCustomObject]@{
			Username         = $_.Name
			FullName         = $_.FullName
			"Type"           = if ($_.SID -like "*-500") { "Admin" } elseif ($_.SID -like "*-501") { "Guest" } else { "User" }
			Enabled		 	 = if ($_.Disabled -eq $false) { "Y" } else { "N" }
			PwExpire	 	 = if ($_.PasswordExpires -eq $true) { "Y" } else { "N" }
			PwReq 			 = if ($_.PasswordRequired -eq $true) { "Y" } else { "N" }
			Groups           = $groups -join ", "
			Description		 = $_.Description
		}
	} | ConvertTo-Html -Fragment -PreContent "<h3>Local Users and Groups</h3>"
} else {
	$UserInfo = Get-ADUser -Filter * -Properties Name,Description,DisplayName,AccountNotDelegated,adminCount,
		AllowReversiblePasswordEncryption,CannotChangePassword,DoesNotRequirePreAuth,Enabled,LockedOut,
		PasswordNeverExpires,PasswordNotRequired,SamAccountName,ServicePrincipalNames,TrustedForDelegation,UseDESKeyOnly | ForEach-Object {
			$user = $_
			$groups = (Get-ADUser $user.SamAccountName -Properties MemberOf).MemberOf | ForEach-Object { 
				(Get-ADGroup $_).Name 
			} | Sort-Object
			
			[PSCustomObject]@{
				Username	= $user.Name
				FullName	= $user.DisplayName
				Description = $user.Description
				SPNs 		= $user.ServicePrincipalNames -join ", "
				Groups 		= $groups -join ", "
				Enabled		= if ($user.Enabled -eq $true) { "Y" } else { "N" }
				Locked		= if ($user.LockedOut -eq $true) { "Y" } else { "N" }
				Protected	= if ($user.adminCount -like "*1*") { "Y" } else { "N" }
				RevPwEnc	= if ($user.AllowReversiblePasswordEncryption -eq $true) { "Y" } else { "N" }
				"ChgPw?"	= if ($user.CannotChangePassword -eq $false) { "Y" } else { "N" }
				PwExpires	= if ($user.PasswordNeverExpires -eq $false) { "Y" } else { "N" }
				PwReq		= if ($user.PasswordNotRequired -eq $false) { "Y" } else { "N" }
				Delegated	= if ($user.AccountNotDelegated -eq $false) { "Y" } else { "N" }
				DelTrust	= if ($user.TrustedForDelegation -eq $true) { "Y" } else { "N" }
				PreAuth		= if ($user.DoesNotRequirePreAuth -eq $false) { "Y" } else { "N" }
				DESOnly		= if ($user.UseDESKeyOnly -eq $true) { "Y" } else { "N" }
			}
		} | ConvertTo-Html -Fragment -PreContent "<h3>Active Directory Users and Groups</h3>"
}

$NetworkInfo = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | 
	Select-Object @{n='Name';e={$_.Description}},
		@{n='MAC Address';e={$_.MACAddress}},
		@{n='IP Address';e={$_.IpAddress -join '; '}},
		@{n='Subnet';e={$_.IpSubnet -join '; '}}, 
        @{n='Default Gateway';e={$_.DefaultIPgateway -join '; '}}, 
        @{n='DNS Servers';e={$_.DNSServerSearchOrder -join '; '}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Network Adapter Information</h3>"

$Processes = @{}
Get-Process -IncludeUserName | ForEach-Object { $Processes[$_.Id] = $_ }
$now = Get-Date
$TCPInfo = Get-NetTCPConnection -State Listen,Established | Where-Object { $_.LocalAddress -notlike "*::*" } | 
    Sort-Object -Property @{Expression = "State"; Descending = $true}, @{Expression = "LocalPort"; Descending = $false} |
	Select-Object @{n='Local IP:Port';e={$_.LocalAddress,$_.LocalPort -join ':'}},
		@{n='Remote IP:Port';e={$_.RemoteAddress,$_.RemotePort -join ':'}},
		State,
		@{Name="Uptime";Expression={($now-$_.CreationTime).seconds,"s" -join '' }},
		@{Name="Username"; Expression={ $Processes[[int]$_.OwningProcess].UserName }},
		@{n='PID';e={$_.OwningProcess}},
		@{n='Process';e={$Processes[[int]$_.OwningProcess].ProcessName}},
		@{n='Command Line';e={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} |
	ConvertTo-Html -Fragment -PreContent "<h3>TCP Connection Info</h3>"

$UDPInfo = Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notlike "*::*" -and $_.LocalPort -lt 49152 } | 
	Sort-Object -Property LocalPort | 
	Select-Object @{n='Local IP:Port';e={$_.LocalAddress,$_.LocalPort -join ':'}},
		@{Name="Uptime";Expression={($now-$_.CreationTime).seconds,"s" -join '' }},
		@{Name="Username"; Expression={ $Processes[[int]$_.OwningProcess].UserName }},
		@{n='PID';e={$_.OwningProcess}},
		@{n='Process';e={$Processes[[int]$_.OwningProcess].ProcessName}},
		@{n='Command Line';e={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>UDP Sockets</h3>"

if ((Get-CimInstance -Class Win32_OperatingSystem).Caption -match "Windows Server") {
	$FeatureInfo = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | ForEach-Object {
		$_ | Select-Object `
			@{Name = 'Name';			Expression = { $_.DisplayName }},
			@{Name = 'Full Name';		Expression = { $_.Name }},
			@{Name = 'Services'; 		Expression = { ($_.SystemService -join ", ") }},
			@{Name = 'Sub-Features'; 	Expression = { ($_.SubFeatures -join ", ") }}
	} | ConvertTo-Html -Fragment -PreContent "<h3>Installed Roles and Features</h3>"
} else {
	$FeatureInfo = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | 
	Select-Object FeatureName | ConvertTo-Html -Fragment -PreContent "<h3>Installed Features</h3>"
}

$CapabilityInfo = Get-WindowsCapability -Online | Where-Object { $_.State -eq "Installed" } | 
	Select-Object Name,RestartNeeded | ConvertTo-Html -Fragment -PreContent "<h3>Installed Capabilities</h3>"

# 32-bit on 64-bit - HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
# 32 on 32 or 64 on 64 - HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
# CurrentUser - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*

$primaryApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null }
$secondaryApps = ""
if ([System.Environment]::Is64BitOperatingSystem) {
	$secondaryApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null }
}
$SystemApps = $primaryApps + $secondaryApps | Sort-Object -Property DisplayName |
	Select-Object @{n='Name';e={$_.DisplayName}},
        @{n='Version';e={$_.DisplayVersion}},
        Publisher,
        @{Name="Install Date"; Expression={
            if ($_.InstallDate -match '^\d{8}$') { 
                [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null).ToString("MM-dd-yyyy")
            } else {
                ""
            }}
        },
		@{Name="Install Location/Source";Expression={
			($_.InstallLocation, $_.InstallSource) -ne $null -join "::" -replace '^::|::$', ''
		}},
		@{n='Uninstall Command';e={$_.UninstallString}} |
	ConvertTo-Html -Fragment -PreContent "<h3>Installed Applications (System-Wide)</h3>"
$SystemApps = $SystemApps.Replace("::","<br>")

$currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$UserApps = @(Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null })
$profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
foreach ($profile in $profiles) {
    $sid = $profile.PSChildName
	if ($sid -match '^S-1-5-(18|19|20)$' -or $sid -eq $currentUserSid) {
        continue
    }

	try {
		$profilePath = (Get-ItemProperty $profile.PSPath).ProfileImagePath
    	$ntuserPath = "$profilePath\NTUSER.DAT"
		if (Test-Path $ntuserPath) {
			# If already loaded, skip loading
			if (-not (Test-Path "Registry::HKU\$sid")) {
				reg load "HKU\$sid" "$ntuserPath" | Out-Null
				$hiveLoaded = $true
			} else {
				$hiveLoaded = $false
			}
			$UserApps += Get-ItemProperty "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null }
		}
	} catch {
		Write-Warning "Failed to process SID $($sid): $_"
	} finally {
		if ($hiveLoaded) {
			reg unload "HKU\$sid" | Out-Null
		}
	}
}
$UserAppsHtml = $UserApps | Sort-Object -Property DisplayName |
	Select-Object @{n='Name';e={$_.DisplayName}},
        @{n='Version';e={$_.DisplayVersion}},
        Publisher,
        @{Name="Install Date"; Expression={
            if ($_.InstallDate -match '^\d{8}$') { 
                [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null).ToString("MM-dd-yyyy")
            } else {
                ""
            }}
        },
		@{Name="Install Location/Source";Expression={
			($_.InstallLocation, $_.InstallSource) -ne $null -join "::" -replace '^::|::$', ''
		}},
		@{n='Uninstall Command';e={$_.UninstallString}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Installed Applications (User)</h3>"
$UserAppsHtml = $UserAppsHtml.Replace("::","<br>")

# Windows Apps
$WindowsApps = Get-AppxPackage -AllUsers | Where-Object { $_.SignatureKind -ne "System" } | Sort-Object -Property AppName | ForEach-Object {
    $package = $_
    $package.PackageUserInformation | ForEach-Object {
		$sidStr = $_.UserSecurityId.Sid
		if ($null -eq $sidStr) {
			$userAccount = ""
		} else {
			try {
				$sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
				$userAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
			} catch {
				# If translation fails, fallback to SID string
				$userAccount = $sidObj.ToString()
			}
		}
        $_ | Select-Object `
            @{Name = 'Name';               Expression = { $package.Name }},
            @{Name = 'Version';            Expression = { $package.Version }},
            @{Name = 'Publisher';          Expression = { $package.Publisher }},
            @{Name = 'Signature';          Expression = { $package.SignatureKind }},
			@{Name = 'Installed For';      Expression = { $userAccount }},
            @{Name = 'Install Location';   Expression = { $package.InstallLocation }}
    }
} | ConvertTo-Html -Fragment -PreContent "<h3>Windows Apps</h3>"

# search for external package managers, display their packages (e.g. winget, chocolatey)
try {
    winget --version > $null 2>&1 
	Write-Host "winget packages:" -ForegroundColor Yellow
	winget list --accept-source-agreements
} catch {
	Write-Host "Winget is not installed on this system." -ForegroundColor Yellow
}
if (Get-Command choco -ErrorAction SilentlyContinue) {
	Write-Host "Chocolatey packages:" -ForegroundColor Yellow
    choco list 
} else {
    Write-Host "Chocolatey is not installed on this system." -ForegroundColor Yellow
}

$Report = ConvertTo-Html -CssUri $CssPath -Body "$PreContent $ComputerName $DomainName $OSInfo $UserInfo $NetworkInfo $TCPInfo $UDPInfo $FeatureInfo $CapabilityInfo $SystemApps $UserAppsHtml $WindowsApps" -Title "Host Information Report" -PostContent "<p>Creation Date $(Get-Date)</p></div>" 

$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"

$Report | Out-File "results\inventory-$timestamp.html"
