$VerbosePreference = "SilentlyContinue"
[string]$cmdPath = $MyInvocation.MyCommand.Path
$currentDir = $cmdPath.substring(0, $cmdPath.IndexOf("audit.ps1"))
$accesscheckPath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\sys\ac\accesschk64.exe"
$everythingcliPath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\everything-cli\es.exe"
$firewallPath = Join-Path -Path $currentDir -ChildPath 'results\firewallaudit.txt'
$registryPath = Join-Path -Path $currentDir -ChildPath 'results\registryaudit.txt'
$processPath = Join-Path -Path $currentDir -ChildPath 'results\processaudit.txt'
$servicePath = Join-Path -Path $currentDir -ChildPath 'results\serviceaudit.txt'
$thruntingPath = Join-Path -Path $currentDir -ChildPath 'results\thruntingaudit.txt'
$filesystemPath = Join-Path -path $currentDir -ChildPath 'results\filesystemaudit.txt'
$filesPath = Join-Path -path $currentDir -ChildPath 'results\unauthfilesaudit.txt'
$certPath = Join-Path -path $currentDir -ChildPath 'results\certaudit.txt'
$artifactsPath = Join-Path $currentDir -ChildPath 'results\artifacts'

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

# $IIS = $false
# if (Get-Service -Name W3SVC 2>$null) {
#     $IIS = $true
# }

$CA = $false
if (Get-Service -Name CertSvc 2>$null) {
    $CA = $true
}

Function Invoke-Chainsaw {
    $chainsawpath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\chainsaw"
    & (Join-Path -Path $chainsawpath -ChildPath "chainsaw_x86_64-pc-windows-msvc.exe") hunt (Join-Path -Path $env:windir -ChildPath "System32\winevt\Logs") -s (Join-Path -Path $chainsawpath -ChildPath "sigma") -r (Join-Path -Path $chainsawpath -ChildPath "rules") --mapping (Join-Path -Path $chainsawpath -ChildPath "mappings\sigma-event-logs-all.yml") --output (Join-Path -Path $currentDir -ChildPath "results\chainsaw_report.txt") | Out-Null
}
Invoke-Chainsaw

Function Get-KeysValues {
    param(
        [hashtable]$hash
    )

    $key_test = ""
    foreach ($Key in $hash.Keys) {
        # drop wildcard character
        if ($Key -like '*\`**') {
            $key_test = "Registry::" + $Key.TrimEnd("\*")
        } else {
            $key_test = "Registry::" + $Key
        }

        if (Test-Path -Path $key_test) {
            if ($hash[$key].Count -eq 0) { # querying only key/subkeys
                $properties = Get-ItemProperty ("Registry::" + $Key)
            } else {
                $properties = Get-ItemProperty ("Registry::" + $Key) -Name $hash[$Key] -ErrorAction SilentlyContinue
            }
            foreach ($property in $properties) {
                $key_path = "Key -",(Convert-Path $property.PSPath | Out-String) -join " "
                Write-Output $key_path
                Write-Output ($property | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSProvider | Format-List | Out-String).Trim()
                Write-Output "`r`n"
            }         
        } else {
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewline; Write-Host $key -ForegroundColor Magenta -NoNewline; Write-Host " not found" -ForegroundColor White
        }
    }
}

Function Write-KeysValues {
    param (
        [string]$header,
        [hashtable]$keysvalues,
        [string]$filepath
    )
    Write-Output $header | Out-File -FilePath $filepath -Append
    Get-KeysValues $keysvalues | Out-File -FilePath $filepath -Append
}

Function Start-ACLCheck {
    param(
        $Target, 
        $ServiceName
    )

    # Gather ACL of object (file/directory, service, or registry key)
    if ($null -ne $Target) {
        try {
            $owner = (Get-Acl $Target -ErrorAction SilentlyContinue).Owner
            $acl = $null
            $serviceacl = $null
            if (Test-Path -Path $Target -PathType Leaf) {
                $acl = & $accesscheckPath -accepteula -wuv -nobanner $Target
            } else {
                if ($Target -ilike 'hk*') {
                    $acl = & $accesscheckPath -accepteula -kwuv -nobanner $Target
                } else {
                    $acl = & $accesscheckPath -accepteula -dwuv -nobanner $Target
                }
            }              

            if ($ServiceName) {
                $serviceacl = & $accesscheckPath -accepteula -cwuv -nobanner $serviceName
            }
        } catch { 
            $null
        }
      
      
        if ($serviceacl) {
            $splitserviceacl = $serviceacl -split "`n" | Select-Object -Skip 2 
            $serviceacl = $splitserviceacl -Join "`n"

            $splitserviceacl = $serviceacl -split "  RW " | Select-Object -Skip 1
            $interestingserviceaces = ""
            foreach ($aclentry in $splitserviceacl) {
                if (($aclentry -notlike '*TrustedInstaller*') -and ($aclentry -notlike '*Administrators*') -and ($aclentry -notlike '*SYSTEM*') -and ($aclentry -notlike '*Server Operators*')) {
                    $interestingserviceaces += "  RW $aclentry"
                } 
            }
            # TODO: Figure out how to write this only when an interesting property is discovered
            if ($interestingserviceaces -ne "") {
                Write-Output $ServiceName
                Write-Output $interestingserviceaces
                Write-Output "`n"                
            }
        }

        if ($acl) {
            $owner = ($owner | Out-String).Trim()
            $interestingowner = ""
            if (($owner -ne "") -and ($owner -notlike '*TrustedInstaller') -and ($owner -notlike '*Administrators') -and ($owner -notlike '*SYSTEM')) {
                $interestingowner += "  $owner has ownership`n"
            }
            
            # skipping first 2 lines b/c they are useless
            $splitacl = $acl -split "`n" | Select-Object -Skip 2 
            $acl = $splitacl -Join "`n"

            # Processing
            $splitacl = $acl -split "  RW " | Select-Object -Skip 1
            $interestingaces = ""
            foreach ($aclentry in $splitacl) {
                if (($aclentry -notlike '*TrustedInstaller*') -and ($aclentry -notlike '*Administrators*') -and ($aclentry -notlike '*SYSTEM*') -and ($aclentry -notlike '*Server Operators*') -and ($aclentry -notlike '*SERVICE*')) {
                    $interestingaces += "  RW $aclentry"
                } 
            }
            
            # Writing
            if (($interestingaces -ne "") -or ($interestingowner -ne "")) {
                if ($ServiceName) {
                    Write-Output "$ServiceName ($($Target)) ACL properties:"
                } 

                if ($interestingowner -ne "") {
                    Write-Output $interestingowner
                }

                if ($interestingaces -ne "") {
                    Write-Output $interestingaces.TrimEnd("`n")
                }
                Write-Output "`n"
            }
        }
    }  
}

Function Write-FirewallRules {
    $firewallProfiles =  Get-NetFirewallProfile
    foreach ($profile in $firewallProfiles) {
        Write-Output "----------- $($profile.Name) -----------"
        Write-Output ($profile | Select-Object Enabled | Format-List | Out-String).Trim()
        Write-Output "=============================="
        $rules = $profile | Get-NetFirewallRule
        foreach ($rule in $rules) {
            Write-Output ($rule | Select-Object Name,DisplayName,Direction,Action,Enabled | Format-List | Out-String).Trim()
            Write-Output ""
        }
        Write-Output "----------- End $($profile.Name) -----------"
        Write-Output ""
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited $($profile.Name) Profile firewall rules" -ForegroundColor white
    }
}
Function Write-ProcessChecks {
    # Process List
    $processes = Get-Process -IncludeUserName
    Write-Output "----------- Process List -----------"
    Write-Output $processes | Sort-Object Id | Format-Table Id,ProcessName,Description,UserName,Path -Wrap | Out-String -Width 10000
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited process information" -ForegroundColor white
    # Process ACLs
    Write-Output "----------- Interesting Process ACLs -----------"
    $uniqueprocesses = $processes | Select-Object Path -Unique 
    foreach ($process in $uniqueprocesses) { 
        $aclCheck = Start-ACLCheck -Target $process.path
        if ($aclCheck.length -gt 0) {
            Write-Output $process.path
            Write-Output $aclCheck
        }
    }
    Write-Output "`n"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited process ACLs" -ForegroundColor white
}
Function Invoke-HollowsHunter {
    Write-Output "----------- Hollows Hunter Results -----------"
    $current = Get-Location
    $hollowshunterPath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\hollows_hunter.exe"
    $resultsPath = Join-Path -Path $currentDir -ChildPath "results"
    cd $resultsPath
    & $hollowshunterPath /dir $artifactsPath /uniqd
    cd $current
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited processes using Hollows Hunter, check " -ForegroundColor white -NoNewline; Write-Host $artifactsPath -ForegroundColor Magenta -NoNewline; Write-Host " for any dumps" -ForegroundColor white
}
Function Write-InjectedThreads {
    Write-Output "----------- Injected Threads -----------"
    $InjectedThread = Join-Path $currentDir -ChildPath "Get-InjectedThread.ps1"
    $threads = & $InjectedThread | Out-String
    Write-Output $threads
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited threads" -ForegroundColor white
}

Function Find-UnquotedServicePaths {
    param (
        $servicesList
    )
    $foundServices = $servicesList | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
    if($($foundServices | Measure-Object).Count -lt 1) {
        Write-Output "No unquoted service paths were found"
        Write-Output "`n"
    } else {
        $foundServices | Sort-Object -Property ProcessId,Name | Format-List -Property ProcessId,State,StartMode,Name,DisplayName,StartName,PathName | Out-String -Width 10000
    }
}
Function Find-SuspiciousServiceProperties {
    param(
        $service,
        $path
    )

    # sus path
    $PathSuspicious = $false
    if ($path -like 'C:\Users\*') {
        $PathSuspicious = $true
    }
    
    # unsigned binaries
    $Unsigned = $false
    try {
        $Signatures = Get-AuthenticodeSignature -FilePath $path
        if ($Signatures.Status -ne "Valid") {
            $Unsigned = $true
        }
    } catch {
        Write-Output "Unable to determine validity of service binary signature`n"
    }
   
    # sus extension
    $SuspiciousExtension = $false
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($path)
    if ($suspiciousExtensions -contains $extension) {
        $SuspiciousExtension = $true
    }

    # commented out b/c super noisy
    # $LocalSystemAccount = ($service.StartName -eq "LocalSystem")
    $NoDescription = ([string]::IsNullOrEmpty($service.Description))
    
    # TODO: turn into switch statement cause why not
    if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $SuspiciousExtension) {
        Write-Output "$($service.Name) ($($service.DisplayName)) suspicious characteristics:"

        if ($PathSuspicious) {
            Write-Output "  - Running from a potentially suspicious path: $path"
        }
        # commented out b/c super noisy
        #if ($LocalSystemAccount) {
        #    Write-Output "  - Running with a LocalSystem account"
        #}
        if ($NoDescription) {
            Write-Output "  - No description provided"
        }
        if ($Unsigned) {
            Write-Output "  - Unsigned executable"
        }
        if ($SuspiciousExtension) {
            Write-Output "  - Suspicious file extension"
        }
        Write-Output ""
    }
}
Function Invoke-ServiceChecks {
    param(
        $servicesList
    )
    $servicesList | ForEach-Object {
        $extension = [IO.Path]::GetExtension($_.PathName.Split([IO.Path]::GetInvalidFileNameChars()) -join '').Split(' ')[0].Trim()
        $pattern = "(?<=\" + $extension + "\b)"
        $Path = ($_.PathName -split $pattern)[0].Trim('"')
        Find-SuspiciousServiceProperties -service $_ -path $Path
        Start-ACLCheck -Target $Path -ServiceName $_.Name
    }
}
function Get-ServiceRecovery {
    param(
        $ServiceName
    )
    $failureActions = (Get-ItemProperty hklm:\system\currentcontrolset\services\$ServiceName).FailureActions
    $possibleActions = 'NoAction', 'RestartService','RestartComputer','RunProgram'

    try {
        [PsCustomObject]@{
            Service           = $ServiceName
            FirstFailure      = $possibleActions[$failureActions[20]]
            SecondFailure     = $possibleActions[$failureActions[28]]
            SubsequentFailure = $possibleActions[$failureActions[36]]
        }
    } catch {
        [PsCustomObject]@{
            Service           = $ServiceName
            FirstFailure      = ""
            SecondFailure     = ""
            SubsequentFailure = ""
        }
    }
}
Function Write-ServiceChecks {
    $services = Get-CimInstance -Class Win32_Service
    Write-Output "----------- Service List -----------"
    # PID, Name, DisplayName, State, StartMode, StartName, PathName
    $services | ForEach-Object { 
        $recovery = Get-ServiceRecovery -ServiceName $_.Name
        $_ | Select-Object @{Name="PID";Expression={$_.ProcessId}}, 
                            State, StartMode, Name, DisplayName, StartName, PathName, 
                            @{Name="FirstFailure";Expression={$recovery.FirstFailure}}, 
                            @{Name="SecondFailure";Expression={$recovery.SecondFailure}}, 
                            @{Name="SubsequentFailure";Expression={$recovery.SubsequentFailure}}
    } | Sort-Object PID | Format-Table -Property PID, Name, DisplayName, State, StartMode, FirstFailure, SecondFailure, SubsequentFailure, StartName, PathName -AutoSize -Wrap | Out-String -Width 10000
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited service information" -ForegroundColor white
    # Unquoted service path check
    Write-Output "----------- Unquoted Service Paths -----------"
    Find-UnquotedServicePaths $services
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited for unquoted service paths" -ForegroundColor white
    # Service properties + ACL check
    Write-Output "----------- Interesting Service Properties -----------"
    Invoke-ServiceChecks $services
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited service properties" -ForegroundColor white
}

Function Find-HiddenServices {
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
    $hidden = $hidden | Format-List
    Write-Output "`n"
    Write-Output "----------- Hidden Services -----------"
    Write-Output $hidden
    Write-Output "`n"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited for hidden services" -ForegroundColor white
}
# WARNING: takes forever
Function Invoke-ServiceRegistryACLCheck {
    Write-Output "----------- Interesting Service Registry Key ACLs -----------"
    Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
        $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
        $aclCheck = Start-ACLCheck -Target $target
        if ($aclCheck.length -gt 0) {
            Write-Output "$target`n"
            Write-Output $aclCheck
        }
    }
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited service registry key ACLs" -ForegroundColor white
}

Function Get-DefenderExclusionSettings {
    Write-Output "----------- Windows Defender Exclusion Settings -----------"
    $exclusions = Get-MpPreference | findstr Exclusion
    Write-Output $exclusions | Format-List
    Write-Output "`n"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Windows Defender exclusion settings" -ForegroundColor white
}

Function Invoke-ScheduledTaskChecks {
    param (
        $tasks
    )
    $aclCheck = Start-ACLCheck -Target "C:\Windows\System32\Tasks"
    if ($aclCheck.length -gt 0) {
        Write-Output "C:\Windows\System32\Tasks`n"
        Write-Output $aclCheck
    }
    foreach ($task in $tasks) {
        $Actions = $task.Actions.Execute
        if ($Actions -ne $null) {
            foreach ($a in $actions) {
                if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }
                elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }
                elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }
                elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }
                $a = $a.Replace('"', '')
                $aclCheck = Start-ACLCheck -Target $a
                if ($aclCheck.length -gt 0) {
                    Write-Output "$a`n"
                    Write-Output $aclCheck
                }
            }
        }
    }
}
Function Write-ScheduledTaskChecks {
    Write-Output "----------- Scheduled Tasks -----------"
    $tasks = Get-ScheduledTask
    Write-Output $tasks | Select-Object State,TaskName,TaskPath,@{Name="NextRunTime";Expression={$(($_ | Get-ScheduledTaskInfo).NextRunTime)}},@{Name="Command";Expression={$_.Actions.Execute}},@{Name="Arguments";Expression={$_.Actions.Arguments}} | Format-Table -Wrap -AutoSize | Out-String -Width 10000 #
    Write-Output "----------- Interesting Scheduled Tasks Properties -----------"
    Invoke-ScheduledTaskChecks -tasks $tasks
    Write-Output "`n"
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited scheduled tasks" -ForegroundColor white
}

Function Get-GroupPolicyReport {
    if ($DC) {
        $reportPath = Join-Path -Path $artifactsPath -ChildPath "DomainGrpPolReport.html"
        Get-GPOReport -All -ReportType HTML -Path $reportPath
    } else {
        $reportPath = Join-Path -Path $artifactsPath -ChildPath "LocalGrpPolReport.html"
        gpresult /h $reportPath
    }
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Exported GPO report" -ForegroundColor white
}

Function Get-RecentlyRunCommands {
    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        # get the SID from output
        $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
        $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
        $HKUSID | ForEach-Object {
            if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
                Write-Output "----------- HKU Recently Run Commands -----------"
                foreach ($p in $property) {
                    Write-Output "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))" 
                }
            }
        }
    }
}

Function Get-PowerShellHistory {
    $users = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($user in $users) {
        $historyFile = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        if (-not (Test-Path $historyFile)) {
            $errorActionPreference = "SilentlyContinue"
            $psReadlineOptions = Get-PSReadlineOption -ErrorAction $errorActionPreference
            if ($psReadlineOptions -and $psReadlineOptions.HistorySavePath) {
                $historyFile = $psReadlineOptions.HistorySavePath
            }
        }
        if (Test-Path $historyFile) {
            $output += Get-Content -Path $historyFile | Out-String
            $date = Get-Date -Format "ddMMyyyy"
            $time = Get-Date -Format "HHmm"
            $filename = "${user.Name}_${date}_${time}_PSHistory.txt"
            $filePath = Join-Path -Path $artifactsPath -ChildPath $filename
            $output | Out-File -FilePath $filePath
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Exported PowerShell history for user: " -ForegroundColor white -NoNewline; Write-Host $user.Name -ForegroundColor Magenta -NoNewLine; Write-Host " to artifacts folder" -ForegroundColor white
        } else {
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] No PowerShell history found for user: " -ForegroundColor white -NoNewline; Write-Host $user.Name -ForegroundColor Magenta
        }
    }
}
Function Find-PowershellProfiles {
    Write-Output "----------- PowerShell Profiles -----------"
    $profiles = $PROFILE | Select-Object * -Exclude Length
    $profiles.PSObject.Properties | ForEach-Object {
        if (Test-Path $_.Value) {
            Write-Output "Exists: $($_.Value)"
        } else {
            Write-Output "Does not exist: $($_.Value)"
        }
    }
    Write-Output "`n"
}

Function Write-EnvironmentVariables {
    Write-Output "----------- Environment Variables -----------"
    dir env: | format-table -autosize
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Environment variables audited" -ForegroundColor white
}

Function Invoke-CertificatesCheck {
    $sigcheckpath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\sys\sc\sigcheck64.exe"
    $output = & $sigcheckpath -accepteula -nobanner -tv * | Out-String
    Write-Output $output
}

Function Invoke-UnsignedFilesCheck {
    param (
        $directory
    )
    $sigcheckpath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\sys\sc\sigcheck64.exe"
    $output = & $sigcheckpath -accepteula -nobanner -u -e $directory | Out-String
    if ($output.Trim() -ne "No matching files were found.") {
        Write-Output $output
    }
}

Function Invoke-ADSCheck {
    param (
        $directory
    )
    $streamspath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\sys\st\streams64.exe"
    $output = & $streamspath -accepteula -nobanner $directory | Out-String
    if ($output.Trim() -ne "No files with streams found.") {
        Write-Output $output
    }
}

Function Invoke-ModifiedFilesCheck {
    param (
        $directory
    )
    & $everythingcliPath "dm:thisweek" "parent:$($directory)" -sort date-modified -dm -attribs -size -full-path-and-name -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
}

Function Process-Item { 
    param (
        [string]$Item,
        [bool]$IsDirectory,
        $Queue
    )

    $result = ""

    if (Test-Path $Item) {
        $aclCheck = Start-ACLCheck -Target $Item
        if ($IsDirectory) {
            $modifiedFilesCheck = Invoke-ModifiedFilesCheck $Item
            $unsignedFilesCheck = Invoke-UnsignedFilesCheck $Item
            $adsCheck = Invoke-ADSCheck $Item
        }
            
        if (($aclCheck.length -gt 0) -or ($modifiedFilesCheck.length -gt 0) -or ($unsignedFilesCheck.length -gt 0) -or ($adsCheck.length -gt 0)) {
            $result += "----------- $Item -----------`n"
            if ($aclCheck.length -gt 0) {
                $result += "ACL properties:`n"
                $result += $aclCheck
                $result += "`n"
            }                
            if ($modifiedFilesCheck.length -gt 0) {
                $result += "Items modified in the last 7 days:"
                $result += $modifiedFilesCheck
            }
            if ($unsignedFilesCheck.length -gt 0) {
                $result += "Unsigned files:`n"
                $result += $unsignedFilesCheck
            }
            if ($adsCheck.length -gt 0) {
                $result += "Alternate Data Streams:`n"
                $result += $adsCheck
            } 
        }
        if ($result.length -gt 0) {
            $Queue.Enqueue($result)
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Item checked: " -ForegroundColor white -NoNewline; Write-Host $Item -ForegroundColor Magenta
        }
    } else {
        Write-Host "Path does not exist: $Item"
    }
}

Function Write-FileAndDirectoryChecks {
    $resultsQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()

    $initialSessionState = [InitialSessionState]::CreateDefault()
    Get-ChildItem function:/ | Where-Object Source -like "" | ForEach-Object {
    $functionDefinition = Get-Content "Function:\$($_.Name)"
    $sessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry `
        -ArgumentList $_.Name, $functionDefinition 
    $initialSessionState.Commands.Add($sessionStateFunction)
}
    
    $vars = @{currentDir=$currentDir;accesscheckPath=$accesscheckPath;everythingcliPath=$everythingcliPath}
    ForEach ($v in $vars.Keys) {
        $variableEntry = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($v, $vars[$v], '')
        $initialSessionState.Variables.Add($variableEntry)
    }
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS+1,$initialSessionState,$Host)
    $runspacePool.ApartmentState = "STA"
    $runspacePool.Open()
    $runspaces = @()

    $directories = @{
        "C:\Intel" = $true;
        "C:\Temp" = $true;
        "$env:windir" = $false;
        "$env:windir\System32" = $false;
        "$env:windir\System32\dns" = $true;
        "C:\inetpub\wwwroot" = $true;
        "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" = $true;
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" = $true
    }
    Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
        $directories[$_.FullName] = $true
        $pdir1 = Join-Path -Path $_.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        $pdir2 = Join-Path -Path "C:\Documents and Settings" -ChildPath $_.Name
        $pdir2 = Join-Path -Path $pdir2 -ChildPath "Start Menu\Programs\Startup"
        $directories[$pdir1] = $true
        $directories[$pdir2] = $true
    }

    foreach ($key in $directories.Keys) {
        if (Test-Path $key) {
            $baseIsDirectory = (Get-Item -Path $key).PSIsContainer
            Process-Item -Item $key -IsDirectory $baseIsDirectory -Queue $resultsQueue

            if ($directories[$key]) {
                $items = Get-ChildItem -Attributes !ReparsePoint -Force -Recurse -Path $key -Depth 2
            } else {
                 $items = Get-ChildItem -Attributes !ReparsePoint -Force -Path $key
            }

            # Add each item to a runspace for parallel processing
            foreach ($item in $items) {
                $SubItem = $item.FullName
                $IsDirectory = $item.PSIsContainer
                $runspace = [powershell]::Create().AddScript({
                    param ($Item, $IsDirectory, $Queue)
                    Process-Item -Item $Item -IsDirectory $IsDirectory -Queue $Queue
                }).AddParameter('Item', $SubItem).AddParameter('IsDirectory', $IsDirectory).AddParameter('Queue', $resultsQueue)

                $runspace.RunspacePool = $runspacePool
                $runspaces += [PSCustomObject]@{
                    Pipe = $runspace
                    Status = $runspace.BeginInvoke()
                }
            }
        } else {
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Path not checked: " -ForegroundColor white -NoNewline; Write-Host $key -ForegroundColor Magenta
        }
     }

    while($runspaces | ? { -not $_.Status.IsCompleted }) {
        Start-Sleep -Seconds 1
    }

    # Collect results and clean up runspaces
    foreach ($runspace in $runspaces) {
        $runspace.Pipe.EndInvoke($runspace.Status)
        $runspace.Pipe.Dispose()
    }

    # Write the collected results to the output file
    $result = ""
    while ($resultsQueue.TryDequeue([ref]$result)) {
        Write-Output $result
    }

    # Cleanup
    $runspacePool.Close()
    $runspacePool.Dispose()
}

Function Invoke-UnauthorizedFilesCheck {
    Write-Output "----------- Video Files -----------"
    $videofiles = & $everythingcliPath "ext:3g2;3gp;avi;flv;h264;m4v;mkv;mov;mp4;mpg;mpeg;rm;swf;vob;wmv" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\systemresources" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $videofiles
    
    Write-Output "----------- Audio Files -----------"
    $audiofiles = & $everythingcliPath "ext:aac;aif;cda;flac;m4a;m4b;m4p;mid;midi;mp3;mpa;ogg;wav;wma;wpl" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\systemapps" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $audiofiles

    Write-Output "----------- Compressed Files -----------"    
    $compressedfiles = & $everythingcliPath "ext:7z;aar;ace;alz;apk;arj;br;bz2;cab;gz;lz;lz4;lzma;lzo;pkg;tar;tgz;tlz;txz;rar;rz;z;zip" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\softwaredistribution" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $compressedfiles

    Write-Output "----------- Disk Files -----------"  
    $diskfiles = & $everythingcliPath "ext:dmg;img;iso" "c:" "!c:\ProgramData\EpicGames" -date-modified -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $diskfiles

    Write-Output "----------- Web/Database Files -----------"  
    $internetfiles = & $everythingcliPath "ext:asp;aspx;db;css;htm;html;js;jsp;php;phar;sql;xhtml" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\systemapps" "!c:\windows\microsoft.net" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $internetfiles

    Write-Output "----------- Office/Text Files -----------"  
    $officefiles = & $everythingcliPath "ext:csv;doc;docx;odp;ods;odt;pdf;pps;ppt;pptx;rtf;tex;txt;wks;wpd;wps;xlr;xls;xlsx" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\systemapps" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $officefiles

    Write-Output "----------- README Files -----------"  
    $readmes = & $everythingcliPath "nowholefilename:README" "c:" "!c:\programdata\epicgames" -date-modified -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $readmes

    Write-Output "----------- Code/Script Files -----------"  
    $codefiles = & $everythingcliPath "ext:bat;c;class;cpp;cs;h;java;jar;pl;py;msi;sh;swift;wsf;vb;vbs" "c:" "!c:\ProgramData\EpicGames" "!c:\windows\winsxs" "!c:\windows\inf" "!c:\windows\microsoft.net" '!"c:\program files\meld"' -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $codefiles

    Write-Output "----------- Image Files -----------"
    $imagefiles = & $everythingcliPath "ext:ai;bmp;gif;ico;jpeg;jpg;png;ps;psd;svg;tif;tiff" "c:" "!c:\windows\winsxs" "!c:\windows\systemapps" "!c:\windows\systemresources" "!c:\windows\immersivecontrolpanel" "!c:\windows\microsoft.net" '!"c:\program files*"' "!c:\windows\web" "!c:\ProgramData\EpicGames" -date-modified -ext -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $imagefiles

    Write-Output "----------- Files Matching Certain Phrases -----------"  
    $phrases = & $everythingcliPath "nowholefilename:password|nowholefilename:creditcard|nowholefilename:payload|nowholefilename:target|nowholefilename:keylogger|nowholefilename:virus|nowholefilename:access|nowholefilename:numbers|nowholefilename:ophcrack" "c:" "!c:\programdata\epicgames" "!c:\windows\winsxs" "!c:\windows\systemapps" "!c:\windows\systemresources" "!c:\windows\immersivecontrolpanel" "!c:\windows\microsoft.net" "!c:\windows\softwaredistribution" "!c:\windows\servicing" "!c:\windows\assembly" -date-modified -size -attrib -sort date-modified -csv | ConvertFrom-Csv | Format-Table -Wrap -AutoSize | Out-String -Width 10000
    Write-Output $phrases

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited for unauthorized files" -ForegroundColor White
 }

Function Start-PrivescCheck {
    $privescpath = Join-Path -Path $currentDir -ChildPath "PrivescCheck.ps1"
    $reportPath = Join-Path -Path $currentDir -ChildPath "results\PrivescCheck"
    . $privescpath; Invoke-PrivescCheck -Extended -Report $reportPath -Format HTML -Force | Out-Null
}

# T1546.007 - Event Triggered Execution: Netsh Helper DLL
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\NetSh" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh" = @()
}
Write-KeysValues "----------- netsh Helper DLL Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited netsh Helper DLL keys" -ForegroundColor white
# T1546.009 - Event Triggered Execution: AppCert DLLs
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs" = @()
}
Write-KeysValues "----------- AppCert DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AppCert DLL values" -ForegroundColor white
# T1546.010 - Event Triggered Execution: AppCert DLLs
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" = @("AppInit_DLLs");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" = @("AppInit_DLLs")
}
Write-KeysValues "----------- AppInit DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AppInit DLL values" -ForegroundColor white
# T1546.012 - Event Triggered Execution: Image File Execution Options Injection
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" = @("Debugger");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*" = @("Debugger")
}
Write-KeysValues "----------- IFEO Debugger Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited IFEO keys" -ForegroundColor white
# T1546.015 - Event Triggered Execution: Component Object Model Hijacking
$keysvalues = @{
    "HKLM\Software\Classes\CLSID\*" = @("InprocServer", "InprocServer32","LocalServer","LocalServer32","TreatAs","ProcID");
    "HKCU\Software\Classes\CLSID\*" = @("InprocServer", "InprocServer32","LocalServer","LocalServer32","TreatAs","ProcID")
}
Write-KeysValues "----------- COM Hijacking Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited COM keys" -ForegroundColor white

# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
## ye olde run keys
# TODO: check ACLs on run key values
# @("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
# "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
# "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
# "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
# # CheckACL of each Property Value found
#     $ROPath = $_
#     (Get-Item $_) | ForEach-Object {
#         $ROProperty = $_.property
#         $ROProperty | ForEach-Object {
#             Start-ACLCheck ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"')
#         }
#     }
# }
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"= @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"= @();
    "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce"= @();
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx"= @();
    "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms"= @()
}
Write-KeysValues "----------- Run Key Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited run keys" -ForegroundColor white
## Automatic service startup keys
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" = @();
    "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" = @()
}
Write-KeysValues "----------- Automatic Service Startup Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited service run keys" -ForegroundColor white
## Startup folder items
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @();
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" = @();
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" = @()
}
Write-KeysValues "----------- StartUp Folder Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited startup folder keys" -ForegroundColor white
## BootExecute key - default of "autocheck autochk /q /v *"
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" = @("BootExecute")
}
Write-KeysValues "----------- Boot Execute Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited BootExecute value" -ForegroundColor white

# T1547.002 - Boot or Logon Autostart Execution: Authentication Package
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Authentication Packages")
}
Write-KeysValues "----------- Authentication Packages -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Authentication Packages value" -ForegroundColor white
# T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" = @("Shell","Userinit","Notify");
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" = @("Shell","Userinit","Notify")
}
Write-KeysValues "----------- Winlogon Helper DLLs -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Winlogon Helper DLL keys" -ForegroundColor white
# T1547.005 - Boot or Logon Autostart Execution: Security Support Provider
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Security Packages");
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" = @("Security Packages")
}
Write-KeysValues "----------- Security Packages -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Security Packages value" -ForegroundColor white
# T1547.010 - Boot or Logon Autostart Execution: Port Monitors
$keysvalues = @{
    "HKLM\System\CurrentControlSet\Control\Print\Monitors\*" = @()
}
Write-KeysValues "----------- Port Monitor Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Port Monitor keys" -ForegroundColor white
# T1547.014 - Boot or Logon Autostart Execution: Active Setup
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\*" = @("StubPath");
    "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\*" = @("StubPath")
}
Write-KeysValues "----------- Active Startup Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Active Setup keys" -ForegroundColor white

# T1556.002 - Modify Authentication Process: Password Filter DLL
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" = @("Notification Packages")
}
Write-KeysValues "----------- Password Filter Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Password Filter DLL value" -ForegroundColor white
# T1556.008 - Modify Authentication Process: Network Provider DLL
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" = @("ProviderOrder")
}
Write-KeysValues "----------- Network Provider Order Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Network Provider DLL value" -ForegroundColor white

# Security Providers
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" = @("SecurityProviders")
}
Write-KeysValues "----------- Security Provider Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Security Providers" -ForegroundColor white

# Alternate Shell
$keysvalues = @{
    "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" = @("AlternateShell")
}
Write-KeysValues "----------- Alternate Shell Item -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AlternateShell value" -ForegroundColor white

# Startup/shutdown script keys
$keysvalues = @{
    "HKLM\Software\Policies\Microsoft\Windows\System\Scripts\*" = @();
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\*" = @();
    "HKCU\Software\Policies\Microsoft\Windows\System\Scripts\*" = @()
}
Write-KeysValues "----------- Startup/Shutdown Script Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited startup/shutdown script keys" -ForegroundColor white

# Assistive Technology 
$keysvalues = @{
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\*" = @("StartExe");
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" = @("Configuration")
}
Write-KeysValues "----------- Assistive Technology Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Assistive Technology keys" -ForegroundColor white

# Protocol filtering and handling
$keysvalues = @{
    "HKLM\Software\Classes\Protocols\Filter\*" = @(); 
    "HKLM\Software\Classes\Protocols\Handler\*" = @();
    "HKLM\Software\Wow6432Node\Classes\Protocols\Filter\*" = @(); 
    "HKLM\Software\Wow6432Node\Classes\Protocols\Handler\*" = @();
    "HKCU\Software\Classes\Protocols\Filter\*" = @();
    "HKCU\Software\Classes\Protocols\Handler\*" = @()
}
Write-KeysValues "----------- Protocol Filtering/Handling Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited Protocol Filtering & Handling keys" -ForegroundColor white

#Trust Providers 
$keysvalues = @{
    "HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" = @();
    "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" = @();
    "HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust\FinalPolicy\*" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\*" = @();
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\*" = @()
}
Write-KeysValues "----------- Trust Provider Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Trust Provider Items" -ForegroundColor white

$keysvalues = @{
    "HKCU\Control Panel\Desktop" = @(); #Screen Saver 
    "HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram" = @(); #Boot Verification Program
    "HKCU\txtfile\shell\open\command" = @(); #File Extension Hijacking
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" = @(); #TelemetryController 
    "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\" = @(); #Recycle Bin COM Extension Handler 
    "HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\" = @(); #Recycle Bin COM Extension Handler
    "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" = @(); #TS Intial
    "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" = @(); #TS Intial 
    "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" = @(); #TS Intial
    "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL" = @(); #Autodial DLL
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" = @(); #HKCU Load 
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" = @(); #Winlogon Notification Package 
    "HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv" = @(); #LSA Extension
    "HKCU\Software\Microsoft\Command Processor\AutoRun"  = @(); #cmd.exe AutoRun
    "HKLM\SOFTWARE\Microsoft\AMSI\Providers" = @(); #AMSI Providers
    "HKCR\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32" = @(); #hhctrl.ocx
    "HKCU\Software\Microsoft\HtmlHelp Author" = @(); #.chm helper DLL
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\" = @(); #Disk Cleanup Handler 
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" = @(); #Group Policy Client Side Extension
    "HKLM\System\CurrentControlSet\Control\ContentIndex\Language" = @(); #Natural Language 6 DLLs
    "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs" = @(); #WER Debugger 
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" = @() #AeDebug
}
Write-KeysValues "----------- Miscellaneous Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Miscellaneous Items on key:" -ForegroundColor white; Write-Host $key -ForegroundColor Magenta

$keysvalues = @{
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$" = @(); #Monitoring Silent Process Exit
}
Write-KeysValues "----------- Silent Process Exit Items -----------" $keysvalues $registryPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Silent Process Exit Items " -ForegroundColor White


Write-FirewallRules | Out-File $firewallPath

Write-ProcessChecks | Out-File $processPath -Append
Write-InjectedThreads | Out-File $processPath -Append
Invoke-HollowsHunter | Out-File $processPath -Append

Write-ServiceChecks | Out-File $servicePath -Append
Find-HiddenServices | Out-File $servicePath -Append
Invoke-ServiceRegistryACLCheck | Out-File $servicePath -Append

Get-DefenderExclusionSettings | Out-File $thruntingPath -Append
Write-ScheduledTaskChecks | Out-File $thruntingPath -Append
Find-PowershellProfiles | Out-File $thruntingPath -Append
Write-EnvironmentVariables | Out-File $thruntingPath -Append
Get-RecentlyRunCommands | Out-File $thruntingPath -Append 

Get-GroupPolicyReport
Get-PowerShellHistory
Start-PrivescCheck

$current = Get-Location
$resultsPath = Join-Path -Path $currentDir -ChildPath "results"
# AD tools time
if ($DC) {
    $pingcastlePath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\pc\PingCastle.exe"
    $adalanchePath = Join-Path -Path $currentDir.Substring(0, $currentDir.IndexOf("scripts")) -ChildPath "tools\adalanche.exe"
    Set-Location $resultsPath
    & $pingcastlePath --healthcheck --carto --datefile | Out-Null
    & $adalanchePath collect activedirectory | Out-Null
    Set-Location $current
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited AD with PingCastle" -ForegroundColor white
    
    
    $keysvalues = @{
        "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" = @("ServerLevelPluginDll")
    }
    Write-KeysValues "----------- Server Level Plugin DLLs -----------" $keysvalues $registryPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audited DNS Server plugins" -ForegroundColor white
    
}
# locksmith time
if ($CA) {
    Set-Location $resultsPath
	Invoke-Locksmith -Mode 3
	Set-Location $current
}

Invoke-CertificatesCheck | Out-File $certPath -Append
Write-FileAndDirectoryChecks | Out-File $filesystemPath -Append
Invoke-UnauthorizedFilesCheck | Out-File $filesPath -Append
#Chandi Fortnite