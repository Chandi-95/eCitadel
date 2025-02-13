$CssPath = (Join-Path (($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("inventory.ps1")))  "report.css")

$PreContent = "<div class='container'>`n<h1 style='text-align: center;'>Host Inventory Report</h1>`n"

$ComputerName = "<h2>Computer name: $env:computername</h2>"

$DomainName = ""
if (Test-Path env:USERDNSDOMAIN) {
	$DomainName = "<h2>Domain: $env:userdnsdomain</h2>"
}

$OSInfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -Property Version,Caption,BuildNumber,OSArchitecture,ServicePackMajorVersion,WindowsDirectory -Fragment -PreContent "<h3>Operating System Information</h3>"

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
		Description		 = $_.Description
        Status           = if ($_.Disabled -eq $true) { "Disabled" } else { "Active" }
        AccountType      = if ($_.SID -like "*-500") { "Administrator" } elseif ($_.SID -like "*-501") { "Guest" } else { "Standard" }
		PasswordExpires	 = $_.PasswordExpires
		PasswordRequired = $_.PasswordRequired
        Groups           = $groups -join ", "
    }
} | ConvertTo-Html -Fragment -PreContent "<h3>Local Users and Groups</h3>"

# -Filter IPEnabled=TRUE
$NetworkInfo = Get-CimInstance -Class Win32_NetworkAdapterConfiguration  | 
	Select-Object Description,MACAddress,
		@{Name='IpAddress';Expression={$_.IpAddress -join '; '}},
		@{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}}, 
        @{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join '; '}}, 
        @{Name='DNSServerSearchOrder';Expression={$_.DNSServerSearchOrder -join '; '}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Network Adapter Information</h3>"

$TCPInfo = Get-NetTCPConnection -State Listen,Established -ErrorAction "SilentlyContinue" | 
	Sort-Object state,localport | 
	Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
		@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},
		@{'Name'='CommandLine';'Expression'={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | 
	ConvertTo-Html -Fragment -PreContent "<h3>Listening & Established TCP Connections</h3>"

$UDPInfo = Get-NetUDPEndpoint | 
	Sort-Object localport | 
	Select-Object LocalAddress,LocalPort,OwningProcess,
		@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},
		@{'Name'='CommandLine';'Expression'={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | 
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
$Report = ConvertTo-Html -CssUri $CssPath -Body "$PreContent $ComputerName $DomainName $OSInfo $LocalUserInfo $NetworkInfo $TCPInfo $UDPInfo $SystemApps" -Title "Host Information Report" -PostContent "<p>Creation Date $(Get-Date)</p></div>" 
$Report | Out-File .\inventory-report.html