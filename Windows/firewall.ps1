# Parameter for enabling/disabling lockout prevention
param(
    [Parameter(Mandatory=$false)]
    [bool]$LockoutPrevention=$True,
    [Parameter(Mandatory=$false)]
    [array]$extrarules,
    [Parameter(Mandatory=$false)]
    [string]$ansibleIP="any",
    [Parameter(Mandatory=$false)]
    [string]$wazuhIP="any",
    [Parameter(Mandatory=$false)]
    [string]$graylogIP="any",
    [Parameter(Mandatory=$false)]
    [string]$rdpIP="any",
    [Parameter(Mandatory=$false)]
    [string]$domainSubnet="any",
    [Parameter(Mandatory=$false)]
    [string]$dcIP="any",
    [Parameter(Mandatory=$false)]
    [string]$caIP="any",
    [Parameter(Mandatory=$false)]
    [string]$secondDCIP="none",
    [Parameter(Mandatory=$false)]
    [array]$scoringIP = @("protocol","0.0.0.0"),
    [Parameter(Mandatory=$false)]
    [array]$scoringIP2 = @("protocol","0.0.0.0"),
    [Parameter(Mandatory=$false)]
    [array]$randomExtraPorts
)

Function handleErrors {
    param(
        [array]$errorString,
        [int]$numRules,
        [string]$ruleType
    )
    for($i = 0; $i -lt $numRules; $i ++){
        $j = $i * 2
        if($errorString[$j] -ne "Ok."){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Error When Setting " -ForegroundColor White -NoNewline; Write-Host $ruleType -NoNewline; Write-Host " rules: " -NoNewline; Write-Host $errorString[$j + 1]
            return $false
        }
    }
    return $true
}

if (!((Get-Service -Name "MpsSvc").Status -eq "Running")) {
    Start-Service -Name MpsSvc
    if (!((Get-Service -Name "MpsSvc").Status -eq "Running")){
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Windows Defender Firewall service could not be started" -ForegroundColor white
    }
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Windows Defender Firewall service started" -ForegroundColor white
}

# Delete all rules
netsh advfirewall set allprofiles state off | Out-Null
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
netsh advfirewall firewall delete rule name=all | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] All firewall rules deleted" -ForegroundColor white

# Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 32676 | Out-Null
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Firewall logging enabled" -ForegroundColor white

# if key doesn't already exist, install WFC
if (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Windows Firewall Control")) {
    $currentDir = ($MyInvocation.MyCommand.Path).substring(0,($MyInvocation.MyCommand.Path).indexOf("scripts\firewall.ps1"))
    $installerPath = Join-Path -Path $currentDir -ChildPath "installs\wfc6setup.exe"
    & $installerPath -i -r -noshortcuts -norules "C:\Program Files\WFC"
}

# Rules!
# Common Scored Services
## Domain Controller Rules (includes DNS server)
if (Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = "2")') {
    ## Inbound rules
    $errorChecking = netsh adv f a r n=DC-TCP-In dir=in act=allow prof=any prot=tcp remoteip=$domainSubnet localport=88,135,389,445,464,636,3268,3269
    $errorChecking += netsh adv f a r n=DC-UDP-In dir=in act=allow prof=any prot=udp remoteip=$domainSubnet localport=88,123,135,389,445,464,636
    $errorChecking += netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp remoteip=$domainSubnet localport=rpc
    $errorChecking += netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp remoteip=$domainSubnet localport=rpc-epmap
    $errorChecking += netsh adv f a r n=DNS-Server dir=in act=allow prof=any prot=udp remoteip=$domainSubnet localport=53
    if(handleErrors -errorString $errorChecking -numRules 5 -ruleType "Domain Controller"){
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Domain Controller firewall rules set" -ForegroundColor white
    }
    if(!($secondDCIP.Equals("none"))){
        # If there are two domain controllers in the environment, add rules for them to talk to each other
        $errorChecking = netsh adv f a r n=DC-To-DC-TCP-In dir=in act=allow prof=any prot=tcp remoteip=$secondDCIP localport=88,135,389,445,464,636,3268,3269
        $errorChecking += netsh adv f a r n=DC-To-DC-TCP-Out dir=out act=allow prof=any prot=tcp remoteip=$secondDCIP remoteport=88,135,389,445,464,636,3268,3269
        $errorChecking += netsh adv f a r n=DC-To-DC-UDP-In dir=in act=allow prof=any prot=udp remoteip=$secondDCIP localport=53,88,123,135,389,445,464,636
        $errorChecking += netsh adv f a r n=DC-To-DC-UDP-Out dir=out act=allow prof=any prot=udp remoteip=$secondDCIP remoteport=53,88,123,135,389,445,464,636

        $errorChecking += netsh adv f a r n=DC-To-DC-RPC-In dir=in act=allow prof=any prot=tcp remoteip=$secondDCIP localport=rpc
        $errorChecking += netsh adv f a r n=DC-To-DC-EPMAP-In dir=in act=allow prof=any prot=tcp remoteip=$secondDCIP localport=rpc-epmap
        $errorChecking += netsh adv f a r n=DC-To-DC-RPC-Out dir=out act=allow prof=any prot=tcp remoteip=$secondDCIP remoteport=rpc
        $errorChecking += netsh adv f a r n=DC-To-DC-EPMAP-Out dir=out act=allow prof=any prot=tcp remoteip=$secondDCIP remoteport=rpc-epmap

        if(handleErrors -errorString $errorChecking -numRules 8 -ruleType "Domain Controller to Domain Controller"){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Domain Controller to Domain Controller firewall rules set" -ForegroundColor white
        }
    }
} else {
    ## If not a DC it's probably domain-joined so add client rules
    $errorChecking = netsh adv f a r n=DC-TCP-Out dir=out act=allow prof=any prot=tcp remoteip=$dcIP remoteport=88,135,389,445,636,3268
    $errorChecking += netsh adv f a r n=DC-UDP-Out dir=out act=allow prof=any prot=udp remoteip=$dcIP remoteport=88,123,135,389,445,636
    if(handleErrors -errorString $errorChecking -numRules 2 -ruleType "Domain Client"){
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Domain-joined system firewall rules set" -ForegroundColor white
    }
}

# DNS client
$errorChecking = netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53
if(handleErrors -errorString $errorChecking -numRules 1 -ruleType "DNS Client"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DNS Client firewall rules set" -ForegroundColor white
}

# LSASS (needed for authentication and NLA)
# is this a bad idea? probably. keep an eye on network connections made by this program
$errorChecking = netsh adv f a r n=LSASS-Out dir=out act=allow prof=any remoteip=$dcIP prog="C:\Windows\System32\lsass.exe"
if(handleErrors -errorString $errorChecking -numRules 1 -ruleType "LSASS"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LSASS firewall rule set" -ForegroundColor white
}

## Certificate Authority
if (Get-Service -Name CertSvc 2>$null) {
    $errorChecking = netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp remoteip=$domainSubnet localport=rpc
    $errorChecking += netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp remoteip=$domainSubnet localport=rpc-epmap
    if(handleErrors -errorString $errorChecking -numRules 2 -ruleType "Certificate Authority"){
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Certificate Authority server firewall rule set" -ForegroundColor white
    }
}
$errorChecking = netsh adv f a r n=CA-Client dir=out act=allow prof=any prot=tcp remoteip=$caIP remoteport=135
if(handleErrors -errorString $errorChecking -numRules 1 -ruleType "CA Client"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Certificate Authority client firewall rule set" -ForegroundColor white
}

# All possible ports needed to be allowed through firewall for various services/scorechecks
# Determined by $extrarules parameter

# This array contains all of the possible services that we would want to allow in the firewall, along with what protocol and ports they use
$protocolArray = @(
    [pscustomobject]@{Service="icmp";Protocol="none";Ports="none"}
    [pscustomobject]@{Service="http";Protocol="tcp";Ports="80,443"}
    [pscustomobject]@{Service="rdp";Protocol="both";Ports="3389"}
    [pscustomobject]@{Service="winrm";Protocol="tcp";Ports="5985,5986"}
    [pscustomobject]@{Service="ssh";Protocol="tcp";Ports="22"}
    [pscustomobject]@{Service="vnc";Protocol="both";Ports="5900"}
    [pscustomobject]@{Service="ldap";Protocol="both";Ports="389"}
    [pscustomobject]@{Service="ldaps";Protocol="tcp";Ports="636"}
    [pscustomobject]@{Service="ldapgc";Protocol="tcp";Ports="3268"}
    [pscustomobject]@{Service="ldapgcs";Protocol="tcp";Ports="3269"}
    [pscustomobject]@{Service="smb";Protocol="tcp";Ports="445"}
    [pscustomobject]@{Service="dhcp";Protocol="udp";Ports="67,68"}
    [pscustomobject]@{Service="ftp";Protocol="tcp";Ports="20,21"}
    [pscustomobject]@{Service="sftp";Protocol="tcp";Ports="22"}
    [pscustomobject]@{Service="openvpn";Protocol="udp";Ports="1194"}
    [pscustomobject]@{Service="hyperv";Protocol="tcp";Ports="2179"}
    [pscustomobject]@{Service="smtp";Protocol="tcp";Ports="25"}
    [pscustomobject]@{Service="smtps";Protocol="tcp";Ports="465,587"}
    [pscustomobject]@{Service="imap";Protocol="tcp";Ports="143"}
    [pscustomobject]@{Service="imaps";Protocol="tcp";Ports="993"}
    [pscustomobject]@{Service="pop3";Protocol="tcp";Ports="110"}
    [pscustomobject]@{Service="pop3s";Protocol="tcp";Ports="995"}
    [pscustomobject]@{Service="pandora";Protocol="tcp";Ports="41121"}
    [pscustomobject]@{Service="syslog";Protocol="udp";Ports="514"}
    [pscustomobject]@{Service="kerberos";Protocol="both";Ports="88"}
    [pscustomobject]@{Service="rpc";Protocol="tcp";Ports="rpc"}
    [pscustomobject]@{Service="epmap";Protocol="tcp";Ports="rpc-epmap"}
    [pscustomobject]@{Service="w32time";Protocol="udp";Ports="123"}
    [pscustomobject]@{Service="dns";Protocol="udp";Ports="53"}
    [pscustomobject]@{Service="ntp";Protocol="udp";Ports="123"}
)
if($extrarules.count -ne 0){
    foreach($rule in $extrarules){
        # in, out, or both
        $direction = "both"
        $service = ""
        # The if/else statement below determines if the extra rule is meant as inbound/outbound, and for what protocol
        if($rule[-1] -eq "i"){
            $direction = "in"
            $service = $rule.substring(0,$rule.length-1)
        }
        elseif($rule[-1] -eq "o"){
            if($rule[$rule.length-2] -eq "i"){
                $direction = "both"
                $service = $rule.substring(0,$rule.length-2)
            }
            else{
                $direction = "out"
                $service = $rule.substring(0,$rule.length-1)
            }
        }
        $service = $service.toLower()

        $ruleObject = ($protocolArray | Where-Object {$_.Service -eq $service})

        # If the scoring IP parameter is used and the scored service is equal to the current service being set, 
        # then the remote port ips are restricted to just the scoring ip.
        $remoteIP = "any"
        if($scoringIP[0].toLower() -eq $service){
            $remoteIP = $scoringIP[1]
        }
        elseif($scoringIP2[0].toLower() -eq $service){
            $remoteIP = $scoringIP2[1]
        }

        if($ruleObject.Service -eq "icmp"){
            # Is the service ICMP? Logic is different because ICMP is only layers 1-3, no ports are used
            
            if($direction -eq "both"){
                $errorChecking = netsh adv f a r n=ICMP-IN dir=in act=allow prof=any remoteip=$remoteIP prot=icmpv4:8,any
                $errorChecking += netsh adv f a r n=ICMP-OUT dir=out act=allow prof=any remoteip=$remoteIP prot=icmpv4:8,any
                if(handleErrors -errorString $errorChecking -numRules 2 -ruleType "ICMP"){
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ICMP firewall Rules Set" 
                }
            }
            else{
                $name = "ICMP-" + $direction.toUpper()
                $errorChecking = netsh adv f a r n=$name dir=$direction act=allow prof=any remoteip=$remoteIP prot=icmpv4:8,any
                if(handleErrors -errorString $errorChecking -numRules 1 -ruleType "ICMP"){
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ICMP " -ForegroundColor White -NoNewLine ; Write-Host $direction -NoNewline; Write-Host "bound firewall rules set"
                }
            }
        }
        else{
            # All other Services possible

            if($direction -eq "both"){
                # rule should be applied both inbound and outbound

                $nameServer = $service.toUpper() + "-In"
                $nameClient = $service.toUpper() + "-Out"

                if($ruleObject.protocol -eq "both"){
                    # Rule should be applied for both tcp and udp ports

                    $numRules = 4

                    $tcpNameServer = $nameServer + "-TCP"
                    $tcpNameClient = $nameClient + "-TCP"
                    $udpNameServer = $nameServer + "-UCP"
                    $udpNameClient = $nameClient + "-UDP"

                    $errorChecking = netsh adv f a r n=$tcpNameServer dir=in act=allow prof=any prot=tcp remoteip=$remoteIP localport=($ruleObject.Ports)
                    $errorChecking += netsh adv f a r n=$tcpNameClient dir=out act=allow prof=any prot=tcp remoteip=$remoteIP remoteport=($ruleObject.Ports)
                    $errorChecking += netsh adv f a r n=$udpNameServer dir=in act=allow prof=any prot=udp remoteip=$remoteIP localport=($ruleObject.Ports)
                    $errorChecking += netsh adv f a r n=$udpNameClient dir=out act=allow prof=any prot=udp remoteip=$remoteIP remoteport=($ruleObject.Ports)
                }
                else{
                    # Rule is only tcp or udp

                    $numRules = 2

                    $errorChecking = netsh adv f a r n=$nameServer dir=in act=allow prof=any prot=($ruleObject.Protocol) remoteip=$remoteIP localport=($ruleObject.Ports)
                    $errorChecking += netsh adv f a r n=$nameClient dir=out act=allow prof=any prot=($ruleObject.Protocol) remoteip=$remoteIP remoteport=($ruleObject.Ports)
                }
                
                if(handleErrors -errorString $errorChecking -numRules $numRules -ruleType $service.ToUpper()){
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] " -ForegroundColor White -NoNewLine; Write-Host $service.ToUpper() -NoNewLine; Write-Host " firewall rules set" 
                }
            }
            else{
                # Rule should only be applied one way
                
                $name = $service.toUpper() + "-" + $direction.toUpper()
                if($ruleObject.protocol -eq "both"){
                    # Rule should be applied for both tcp and udp ports
                    $tcpName = $name + "-TCP"
                    $udpName = $name + "-UDP"

                    $numRules = 2
                    
                    if($direction -eq "in"){
                        $errorChecking = netsh adv f a r n=$tcpName dir=$direction act=allow prof=any prot=tcp remoteip=$remoteIP localport=($ruleObject.Ports)
                        $errorChecking += netsh adv f a r n=$udpName dir=$direction act=allow prof=any prot=udp remoteip=$remoteIP localport=($ruleObject.Ports)
                    }
                    else{
                        $errorChecking = netsh adv f a r n=$tcpName dir=$direction act=allow prof=any prot=tcp remoteip=$remoteIP remoteport=($ruleObject.Ports)
                        $errorChecking += netsh adv f a r n=$udpName dir=$direction act=allow prof=any prot=udp remoteip=$remoteIP remoteport=($ruleObject.Ports)
                    }
                }
                else{
                    # Rule is only tcp or udp

                    $numRules = 1

                    if($direction -eq "in"){
                        $errorChecking = netsh adv f a r n=$name dir=$direction act=allow prof=any prot=($ruleObject.Protocol) remoteip=$remoteIP localport=($ruleObject.Ports)
                    }
                    else{
                        $errorChecking = netsh adv f a r n=$name dir=$direction act=allow prof=any prot=($ruleObject.Protocol) remoteip=$remoteIP remoteport=($ruleObject.Ports)
                    }
                }
                if(handleErrors -errorString $errorChecking -numRules $numRules -ruleType $service.ToUpper){
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] " -ForegroundColor White -NoNewLine; Write-Host $service.ToUpper() -NoNewLine; Write-Host " " -NoNewLine; Write-Host $direction -NoNewline; Write-Host "bound firewall rules set"
                }
            }
        }
    }
}

# Any extra ports that we don't have as optional parameters, just in case
if($randomExtraPorts -ne 0){
    foreach($port in $randomExtraPorts){
        $errorChecking = netsh adv f a r n="Random-Extra-Port-TCP-IN-$($port)" dir=in act=allow prof=any prot=tcp localport=($port)
        $errorChecking += netsh adv f a r n="Random-Extra-Port-TCP-OUT-$($port)" dir=out act=allow prof=any prot=tcp remoteport=($port)
        $errorChecking += netsh adv f a r n="Random-Extra-Port-UDP-IN-$($port)" dir=in act=allow prof=any prot=udp localport=($port)
        $errorChecking += netsh adv f a r n="Random-Extra-Port-UDP-OUT-$($port)" dir=out act=allow prof=any prot=udp remoteport=($port)

        if(handleErrors -errorString $errorChecking -numRules 4 -ruleType "Random Extra Rule (Port $($port))"){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Port $($port) firewall rules set" -ForegroundColor White
        }
    }
}

# Remoting Protocols

## RDP in
$errorChecking = netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp remoteip=$rdpIP localport=3389
$errorChecking += netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp remoteip=$rdpIP localport=3389
if(handleErrors -errorString $errorChecking -numRules 2 -ruleType "RDP"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] RDP inbound firewall rules set" -ForegroundColor white
}

## WinRM
$errorChecking = netsh adv f a r n=WinRM-Ansible-Server dir=in act=allow prof=any prot=tcp remoteip=$ansibleIP localport=5985,5986
if(handleErrors -errorString $errorChecking -numRules 1 -ruleType "WinRM"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WinRM inbound firewall rule set" -ForegroundColor white
}

# Logging Protocols
## Wazuh 
$numRules = 2
$errorChecking = netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteip=$wazuhIP remoteport=1514
if($wazuhIP -ne "Any"){
    $errorChecking += netsh adv f a r n=Wazuh-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=$wazuhIP remoteport=80,443
    $numRules++
}
### Temporary rule to allow enrollment of an agent
$errorChecking += netsh adv f a r n=Wazuh-Agent-Enrollment dir=out act=allow prof=any prot=tcp remoteip=$wazuhIP remoteport=1515

if(handleErrors -errorString $errorChecking -numRules $numRules -ruleType "Wazuh"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wazuh firewall rules set" -ForegroundColor white
}

$numRules = 1
$errorChecking = netsh adv f a r n=Graylog-Client dir=out act=allow prof=any prot=tcp remoteip=$graylogIP remoteport=1514,9000,9200,9300,27017
if($graylogIP -ne "Any"){
    $errorChecking += netsh adv f a r n=Graylog-HTTP-Dashboard dir=out act=allow prof=any prot=tcp remoteip=$graylogIP remoteport=80,443
    $numRules++
}

if(handleErrors -errorString $errorChecking -numRules $numRules -ruleType "Graylog"){
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Graylog firewall rules set" -ForegroundColor white
}

# blocking win32/64 lolbins from making network connections when they shouldn't
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null 
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any | Out-Null

# Logic to add all fw rules to group for WFC
Get-NetFirewallRule -All | ForEach-Object {$_.Group = 'bingus'; $_ | Set-NetFirewallRule}

# Turn on firewall and default block
netsh advfirewall set allprofiles state on | Out-Null
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Firewall on, set to block for all inbound and outbound traffic" -ForegroundColor white

# Lockout prevention
if ($LockoutPrevention) {
    Start-Sleep (10)
    write-host "[" -ForegroundColor white -NoNewLine; Write-Host "LOCKOUT" -ForegroundColor Magenta -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host "Hit Control + C to apply the changes" -ForegroundColor white -BackgroundColor DarkRed 
    Start-Sleep (30)
    write-host "[" -ForegroundColor white -NoNewLine; Write-Host "LOCKOUT" -ForegroundColor Magenta -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host "No user response, undoing the changes" -ForegroundColor white
    netsh advfirewall set allprofiles state off
}
#Chandi Fortnite