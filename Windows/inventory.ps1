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

$LocalUserInfo = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = 'True'" | ForEach-Object {
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

$NetworkInfo = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | 
	Select-Object @{n='Name';e={$_.Description}},
		@{n='MAC Address';e={$_.MACAddress}},
		@{n='IP Address';e={$_.IpAddress -join '; '}},
		@{n='Subnet';e={$_.IpSubnet -join '; '}}, 
        @{n='Default Gateway';e={$_.DefaultIPgateway -join '; '}}, 
        @{n='DNS Servers';e={$_.DNSServerSearchOrder -join '; '}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Network Adapter Information</h3>"

$TCPInfo = Get-NetTCPConnection -State Listen,Established -ErrorAction "SilentlyContinue" | 
	Sort-Object state,localport | 
	Select-Object @{n='Local IP:Port';e={$_.LocalAddress,$_.LocalPort -join ':'}},
		@{n='Remote IP:Port';e={$_.RemoteAddress,$_.RemotePort -join ':'}},
		@{n='State';e={if ($_.State -like "Listen") { "L" } elseif ($_.State -like "Established") { "E" } else { "" }}},
		@{n='PID - Process';e={$_.OwningProcess,(Get-Process -Id $_.OwningProcess).ProcessName -join ' - '}},
		@{n='Command Line';e={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Listening & Established TCP Connections</h3>"

$UDPInfo = Get-NetUDPEndpoint | 
	Sort-Object localport | 
	Select-Object @{n='Local IP:Port';e={$_.LocalAddress,$_.LocalPort -join ':'}},
		@{n='PID - Process';e={$_.OwningProcess,(Get-Process -Id $_.OwningProcess).ProcessName -join ' - '}},
		@{n='Command Line';e={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>UDP Sockets</h3>"

# 32-bit on 64-bit
$installedApps32Bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
# 32 on 32 or 64 on 64
$installedApps64Bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
# replace with loading in every user's hive
$installedAppsUser = Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
# Combine the results and select relevant properties including the file path
# TODO: combine InstallLocation and InstallSource into one column
# TODO: sort alphabetically

# $installedApps = $installedApps32Bit + $installedApps64Bit + $installedAppsUser | Where-Object { $_.DisplayName -ne $null } | ConvertTo-Html -Fragment -Property DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, InstallSource -PreContent "<h3>Installed Applications</h3>"

$primaryApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null }
$secondaryApps = ""
if ((Get-CimInstance -Class Win32_OperatingSystem | Select-Object OSArchitecture) -eq "64-bit") {
	$secondaryApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -ne $null }
}
$SystemApps = $primaryApps + $secondaryApps | 
	Where-Object { $_.DisplayName -ne $null } |
	Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,
		@{Name="InstallPath";Expression={
			($_.InstallLocation, $_.InstallSource) -ne $null -join "::" -replace '^::|::$', ''
		}} |
	ConvertTo-Html -Fragment -PreContent "<h3>Installed Applications (System-Wide)</h3>"
$SystemApps = $SystemApps.Replace("::","<br>")
	
#TODO: MS Store apps
# Get-AppxPackage -AllUsers
# TODO: differentiate between windows client and server methods of getting installed features
# if ((Get-CimInstance -Class Win32_OperatingSystem).Caption -match "Windows Server") {
	# $FeatureInfo = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | ConvertTo-Html -Fragment -Property Name,Path -PreContent "<h3>Installed Roles and Features</h3>"
# }

# TODO: search for external package managers

$Report = ConvertTo-Html -CssUri $CssPath -Body "$PreContent $ComputerName $DomainName $OSInfo $LocalUserInfo $NetworkInfo $TCPInfo $UDPInfo $SystemApps" -Title "Host Information Report" -PostContent "<p>Creation Date $(Get-Date)</p></div>" 

$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"

$Report | Out-File ".\inventory-$timestamp.html"
# $Report | Out-File .\inventory.html