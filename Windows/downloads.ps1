# Objective: downloads scripts/tools needed

# TODO: make use of ninite and run installers

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

# *-WindowsFeature - Roles and Features on Windows Server 2012 R2 and above
# *-WindowsCapability - Features under Settings > "Optional Features"
# *-WindowsOptionalFeature - Featuers under Control Panel > "Turn Windows features on or off" (apparently this is compatible with Windows Server)

param (
    [Parameter(mandatory=$true)]
    [string]$Path
)

# fallbacks
[Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# somehow this block verifies if the path is legit
$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; 
        Write-Host "ERROR" -ForegroundColor red -NoNewLine; 
        Write-Host "] Invalid path" -ForegroundColor white
        break
    }
    $true
})]
$InputPath = $Path
Set-Location -Path $InputPath | Out-Null

# overengineered class for managing downloads
class DownloadJob {
    [string]$Type
    [psobject]$Source
    [bool]$NeedsExtraction
    [string]$ExtractTo

    [System.Collections.Generic.List[System.Threading.Tasks.Task]]$Tasks
    [System.Collections.Generic.List[string]]$DownloadedFiles

    DownloadJob([string]$Type, [psobject]$Source) {
        $this.Type = $Type
        $this.Source = $Source
        $this.Tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
        $this.DownloadedFiles = [System.Collections.Generic.List[string]]::new()
    }

    [void]DownloadAllAsync([string]$RootDir) {
        $urlsToDownload = [System.Collections.ArrayList]::new()
        switch ($this.Type) {
            'GitHubRelease' {
                foreach ($repoEntry in $this.Source) {
                    $repo = $repoEntry.Repo
                    $keywords = $repoEntry.Keywords
                    $subDir = $repoEntry.Path
                    Write-Host "🔍 GitHub Release: $repo"
                    $assets = $this.GetMatchingRelease($repo, $keywords)
                    foreach ($url in $assets) {
                        $urlsToDownload.Add([pscustomobject]@{
                            Url  = $url
                            Path = $subDir
                        }) | Out-Null
                    }
                }
            }
            'RawGitHub' {
                foreach ($entry in $this.Source) {
                    foreach ($path in $entry.Endpoint) {
                        $urlsToDownload.Add([PSCustomObject]@{
                            Url = "https://raw.githubusercontent.com/$path"
                            Path = $entry.Path
                        }) | Out-Null
                    }
                }
            }
            'GistGitHub' {
                foreach ($entry in $this.Source) {
                    foreach ($path in $entry.Endpoint) {
                        $urlsToDownload.Add([PSCustomObject]@{
                            Url = "https://gist.githubusercontent.com/$path"
                            Path = $entry.Path
                        }) | Out-Null
                    }
                }
            }
            'BaseUrl' {
                foreach ($entry in $this.Source) {
                    foreach ($file in $entry.Files) {
                        $urlsToDownload.Add([pscustomobject]@{
                            Url  = "$($entry.BaseUrl)$file"
                            Path = $entry.Path
                        }) | Out-Null
                    }
                }
            }
            'DirectUrl' {
                foreach ($entry in $this.Source) {
                    $urlsToDownload.Add([pscustomobject]@{
                        Url  = $entry.Url
                        Path = $entry.Path
                    }) | Out-Null
                }
            }
            'Ninite' {
                foreach ($entry in $this.Source) {
                    $apps = ($entry.Packages -join '-').ToLower()
                    $url = "https://ninite.com/$apps/ninite.exe"
                    $urlsToDownload.Add([PSCustomObject]@{
                        Url = $url
                        Path = $entry.Path
                    }) | Out-Null
                }
            }
            default {
                Write-Warning "Unknown source type: $($this.Source.Type)"
            }
        }

        foreach ($item in $urlsToDownload) {
            $url = $item.Url    
            $subDir = $item.Path
            $targetDir = if ($subDir) {
                Join-Path $RootDir $subDir
            } else {
                $RootDir
            }

            if (-Not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }

            $fileName = Split-Path $url -Leaf
            $destPath = Join-Path $targetDir $fileName

            if (Test-Path $destPath) {
                Write-Host " Already exists: $fileName"
                continue
            }

            $webClient = New-Object System.Net.WebClient

            Write-Host "Starting download: $url"
            $task = $webClient.DownloadFileTaskAsync($url, $destPath)
            $this.Tasks.Add($task)
            $this.DownloadedFiles.Add($destPath)
        }
    }

    [System.Collections.ArrayList]GetMatchingRelease([string]$repo, [string[]]$keywords) {
        $apiUrl = "https://api.github.com/repos/$($repo)/releases/latest"
        $headers = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36" }
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers
            $matchedAssets = [System.Collections.ArrayList]::new()
            foreach ($asset in $response.assets) {
                $name = $asset.name
                # Fuzzy match logic: file must contain ALL keywords (case-insensitive)
                $match = $true
                foreach ($keyword in $keywords) {
                    if ($name -notlike "*$keyword*") {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    $matchedAssets.Add($asset.browser_download_url) | Out-Null
                }
            }
            return $matchedAssets
        } catch {
            throw "Failed to fetch GitHub release: $_"
            return [System.Collections.ArrayList]::new()
        }
    }

    [void]WaitForCompletion() {
        Write-Host "⏳ Waiting for $($this.Tasks.Count) downloads..."
        try {
            [System.Threading.Tasks.Task]::WaitAll($this.Tasks.ToArray())
        } catch [System.AggregateException] {
            Write-Host "Caught an aggregate exception:"

            # This will enumerate over any inner exceptions and print their details
            foreach($innerEx in $_.Exception.InnerExceptions) {
                Write-Host "=== Inner Exception ==="
                Write-Host $innerEx.Message
                Write-Host $innerEx.StackTrace
            }
        }
        Write-Host "✅ Finished downloading $($this.Tasks.Count) items"
    }

    [void]ExtractDownloadedFiles([string]$RootDir) {
        foreach ($file in $this.DownloadedFiles) {
            if ($file -like "*.zip") {
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file)
                $targetDir = if ($this.ExtractTo) {
                    Join-Path -Path $RootDir -ChildPath $this.ExtractTo | Join-Path -ChildPath $baseName
                } else {
                    Join-Path -Path $RootDir -ChildPath $baseName
                }

                if (-not (Test-Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }

                try {
                    Write-Host "🗂️  Extracting $file to $targetDir"
                    Expand-Archive -Path $file -DestinationPath $targetDir
                    Move-Item -Path $file -Destination (Join-Path -Path $RootDir -ChildPath "zipped")
                } catch {
                    Write-Warning "❌ Failed to extract $($file): $_"
                }
            }
        }
    }
}

$ErrorActionPreference = "SilentlyContinue"

$ghSources = @(
    @{
        Endpoint = @(
            "CCDC-RIT/Hivestorm/main/Windows/audit.ps1",
            "CCDC-RIT/Hivestorm/main/Windows/inventory.ps1",
            "CCDC-RIT/Hivestorm/main/Windows/report.css",
            "CCDC-RIT/Hivestorm/main/Windows/zookeeper.ps1",
            "CCDC-RIT/Hivestorm/main/Windows/secure.ps1",
            "CCDC-RIT/Hivestorm/main/Windows/logging.ps1",
            "CCDC-RIT/Windows-Scripts/master/backup.ps1",
            "CCDC-RIT/Windows-Scripts/master/command_runbook.txt",
            "CCDC-RIT/Windows-Scripts/master/firewall.ps1",
            "itm4n/PrivescCheck/master/PrivescCheck.ps1"
        );
        Path = "scripts"
    },
    @{
        Endpoint = @(
            "CCDC-RIT/Windows-Scripts/master/auditpol.csv",
            "CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml",
            "CCDC-RIT/Logging-Scripts/main/agent_windows.conf",
            "olafhartong/sysmon-modular/master/sysmonconfig.xml"
        );
        Path = "scripts\conf"
    }
) | ForEach-Object { [pscustomobject]$_ }

$gistSources = @(
    @{ 
        Endpoint = @(
            "jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1",
            "jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1"
        ); 
        Path = "scripts" 
    }
) | ForEach-Object { [pscustomobject]$_ }

$releaseSources = @(
    @{
        Repo = "WithSecureLabs/chainsaw"
        Keywords = @("all_platforms", "rules", "zip")
        Path = ""
    },
    @{
        Repo = "Klocman/Bulk-Crap-Uninstaller"
        Keywords = @("BCUninstaller", "setup")
        Path = "installs"
    }
) | ForEach-Object { [pscustomobject]$_ }

$directSources = @(
    @{
        Url = "https://homeupdater.patchmypc.com/public/PatchMyPC-HomeUpdater-Portable.exe"
        Path = "tools"
    },
    # @{
    #     Url = "https://go.microsoft.com/fwlink/?LinkId=2085155"
    #     Path = "installs"
    # },
    @{
        Url = "https://www.binisoft.org/download/wfc6setup.exe"
        Path = "installs"
    },
    # @{
    #     Url = "https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe"
    #     Path = "installs"
    # },
    @{
        Url = "https://www.cyberlock.global/downloads/InstallDefenderUISilent.exe"
        Path = "installs"
    },
    @{
        Url = "https://download.gnome.org/binaries/win32/meld/3.22/Meld-3.22.2-mingw.msi"
        Path = "installs"
    }
) | ForEach-Object { [pscustomobject]$_ }

$baseSources = @(
    @{
        BaseUrl = "https://download.sysinternals.com/files/"
        Files = @(
            "Autoruns.zip",
            "ListDlls.zip",
            "ProcessExplorer.zip",
            "ProcessMonitor.zip", 
            "Sigcheck.zip", 
            "TCPView.zip",
            "Streams.zip",
            "Sysmon.zip",
            "AccessChk.zip",
            "AccessEnum.zip",
            "PSTools.zip",
            "Strings.zip"
        )
        Path = ""
    },
    @{
        BaseUrl = "https://github.com/"
        Files = @(
            "CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip",
            "CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip"
        )
        Path = ""
    }
) | ForEach-Object { [pscustomobject]$_ }

$niniteSources = @(
    [PSCustomObject]@{
        Packages = @(
            "everything", 
            "malwarebytes",
            ".net4.8.1"
        )
        Path = "installs"
    }
)

# yo i hope this works
if ((Get-CimInstance -Class Win32_OperatingSystem).Caption -match "Windows Server") {
    Install-WindowsFeature -Name Bitlocker,Windows-Defender | Out-Null
    # the following feature might not exist based on the windows server version
    Install-WindowsFeature -Name Windows-Defender-GUI | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Bitlocker and Windows Defender installed" -ForegroundColor white
}

# Server Core Tooling
if ((Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion") -and (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty "InstallationType") -eq "Server Core") {
    # Server Core App Compatibility FOD
    Add-WindowsCapability -Online -Name ServerCore.AppCompatibility~~~~0.0.1.0 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine;
    Write-Host "] Additional MS tools installed" -ForegroundColor white
    # Explorer++
    $releaseSources += [PSCustomObject]@{
        Repo = "derceg/explorerplusplus"
        Keywords = @("explorerpp", "x64.zip")
        Path = ""
    }
    # NetworkMiner
    $directSources += [PSCustomObject]@{
        Url = "https://netresec.com/?download=NetworkMiner"
        Path = ""
    }
}

# 64-bit vs. 32-bit tooling
if ([System.Environment]::Is64BitOperatingSystem) {
    $releaseSources += @(
        @{
            Repo = "hasherezade/hollows_hunter"
            Keywords = @("64", "exe")
            Path = "tools"
        },
        @{
            Repo = "virustotal/yara"
            Keywords = @("yara", "win64")
            Path = ""
        }
    ) | ForEach-Object { [pscustomobject]$_ }
    $directSources += @(
        # @{
        #     Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        #     Path = "installs"
        # },
        # @{
        #     Url = "https://www.voidtools.com/Everything-1.4.1.1027.x64.zip"
        #     Path = ""
        # },
        @{
            Url = "https://www.voidtools.com/ES-1.1.0.27.x64.zip"
            Path = ""
        }
    ) | ForEach-Object { [pscustomobject]$_ }
    $baseSources += [PSCustomObject]@{
        BaseUrl = "https://github.com/"
        Files = @(
            "rvazarkar/antipwny/raw/refs/heads/master/exe/x64/AntiPwny.exe",
            "rvazarkar/antipwny/raw/refs/heads/master/exe/x64/ObjectListView.dll"
        )
        Path = "tools"
    }
    $niniteSources[0].Packages += "vcredistx15"
} else {
    $releaseSources += @(
        @{
            Repo = "hasherezade/hollows_hunter"
            Keywords = @("32", "exe")
            Path = "tools"
        },
        @{
            Repo = "virustotal/yara"
            Keywords = @("yara", "win32")
            Path = ""
        }
    ) | ForEach-Object { [pscustomobject]$_ }
    $directSources += @(
        # @{
        #     Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
        #     Path = "installs"
        # },
        # @{
        #     Url = "https://www.voidtools.com/Everything-1.4.1.1027.x86.zip"
        #     Path = ""
        # },
        @{
            Url = "https://www.voidtools.com/ES-1.1.0.27.x86.zip"
            Path = ""
        }
    ) | ForEach-Object { [pscustomobject]$_ }
    $baseSources += [PSCustomObject]@{
        BaseUrl = "https://github.com/"
        Files = @(
            "rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe",
            "rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll"
        )
        Path = "tools"
    }
    $niniteSources[0].Packages += "vcredist15"
}

# Service-specific tooling
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { # DC detection
    # RSAT tooling (AD management tools + DNS management)
    Install-WindowsFeature -Name RSAT-AD-Tools,RSAT-DNS-Server,GPMC
    # Domain, Domain Controller, and admin template GPOs 
    $ghSources[1].Endpoint += @(
        "CCDC-RIT/Hivestorm/main/Windows/gpos/{09D1DE45-0C25-4975-97F9-9197976B322D}.zip",
        "CCDC-RIT/Hivestorm/main/Windows/gpos/{065414B1-7553-477D-A047-5169D6A5D587}.zip",
        "CCDC-RIT/Hivestorm/main/Windows/gpos/{064C9ADE-3C50-4BE1-B494-8CEF0F25D7E4}.zip"
    )
    # Reset-KrbtgtKeyInteractive
    $gistSources[0].Endpoint += "mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1" 
    # Pingcastle
    $releaseSources += [PSCustomObject]@{
        Repo = "netwrix/pingcasle"
        Keywords = @("PingCastle", "zip")
        Path = ""
    } 
    # Adalanche
    $releaseSources += [PSCustomObject]@{
        Repo = "lkarlslund/Adalanche"
        Keywords = @("adalanche-windows", "x64", "exe")
        Path = "tools"
    }
} else { # non-DC server/client tools
    $ghSources[1].Endpoint += @(
        "CCDC-RIT/Hivestorm/main/Windows/gpos/{064C9ADE-3C50-4BE1-B494-8CEF0F25D7E4}.zip",
        "CCDC-RIT/Hivestorm/main/Windows/gpos/msc-sec-template.inf"
    )
    $directSources += [PSCustomObject]@{
        Url = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip"
        Path = ""
    }
}

if (Get-Service -Name CertSvc 2>$null) { # ADCS tools
    # Add package manager and repository for PowerShell
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted | Out-Null
    # install dependency for locksmith (AD PowerShell module) and ADCS management tools
    Install-WindowsFeature -Name RSAT-AD-PowerShell,RSAT-ADCS-Mgmt | Out-Null
    # install locksmith
    Install-Module -Name Locksmith -Scope CurrentUser | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; 
    Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; 
    Write-Host "] Locksmith downloaded and installed" -ForegroundColor white
}

$jobs = [System.Collections.ArrayList]::new()

New-Item -Path $InputPath -Name "zipped" -ItemType "directory" | Out-Null
New-Item -Path (Join-Path -Path $InputPath -ChildPath "scripts") -Name "results" -ItemType "directory" | Out-Null
New-Item -Path (Join-Path -Path $InputPath -ChildPath "scripts" | Join-Path -ChildPath "results") -Name "artifacts" -ItemType "directory" | Out-Null

$jobGh = [DownloadJob]::new("RawGitHub", $ghSources)
$jobGh.NeedsExtraction = $true
$jobGh.ExtractTo = "scripts\conf"
$jobs.Add($jobGh) | Out-Null

$jobGist = [DownloadJob]::new("GistGitHub", $gistSources)
$jobs.Add($jobGist) | Out-Null

$jobRelease = [DownloadJob]::new("GitHubRelease", $releaseSources)
$jobRelease.NeedsExtraction = $true
$jobRelease.ExtractTo = "tools"
$jobs.Add($jobRelease) | Out-Null

$jobDirect = [DownloadJob]::new("DirectUrl", $directSources)
$jobDirect.NeedsExtraction = $true
$jobDirect.ExtractTo = "tools"
$jobs.Add($jobDirect) | Out-Null

$jobBase = [DownloadJob]::new("BaseUrl", $baseSources)
$jobBase.NeedsExtraction = $true
$jobBase.ExtractTo = "tools"
$jobs.Add($jobBase) | Out-Null

$jobNinite = [DownloadJob]::new("Ninite", $niniteSources)
$jobs.Add($jobNinite) | Out-Null

foreach ($job in $jobs) {
    $job.DownloadAllAsync($InputPath)
}

foreach ($job in $jobs) {
    $job.WaitForCompletion()
    $job.ExtractDownloadedFiles($InputPath)
}

# run installer(s)
Set-Location -Path (Join-Path -Path $InputPath -ChildPath "installs")
$msiFiles = Get-ChildItem -Path $searchPath -Filter *.msi -Recurse 
foreach ($msi in $msiFiles) {
    Start-Process "msiexec.exe" -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait
}
& ".\InstallDefenderUISilent.exe" /VERYSILENT
$bcu = Get-ChildItem -Path $searchPath -Filter *.exe -Recurse | 
    Where-Object { $_.Name -like "*BCU*" }
& $bcu.FullName /VERYSILENT /NORESTART
& ".\ninite.exe"