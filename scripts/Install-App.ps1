<# 
    Forbedringstiltag:
        - Efterfølgende:
            - Hvis acrobate er installeret, sæt som pdf åbner
            - Hvis ShareX er installeret, opsæt konfigurationer
        - AM opsætning?
        - Dot.Net opsætning?
        - Visual++ opsætning?

#>



Function Install-App {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$EnableAutoupdate,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeVisualPlusplus,
        [Parameter(Mandatory=$false)]
        [switch]$Default)

    ## Fjern før upload, for test skyld
        # Timestamps for actions
        Function Get-LogDate {
        return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}

    # Ensure admin rights
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    
		# Relaunch as an elevated process
		$Script = $MyInvocation.MyCommand.Path
		Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}
	
	# Standardliste, hvis -Default vælges
    if ($Default) {$Name = "chrome,7zip,vlc"}	

    # Liste over tilgængelige applikationer
    $apps = @{
        "office" = "Microsoft Office 2016 Retail|microsoft-office-deployment"
        "chrome" = "Google Chrome|googlechrome"
        "brave" = "Brave Browser|brave"
        "firefox" = "Mozilla Firefox|firefox"
        "librewolf" = "LibreWolf|librewolf"
        "opera" = "Opera|opera"
        "vivaldi" = "Vivaldi|vivaldi"
        "dropbox" = "Dropbox|dropbox"
        "drive" = "Google Drive|googledrive"
        "teamviewer" = "TeamViewer|teamviewer"
        "7zip" = "7-Zip|7zip"
        "winrar" = "Winrar|winrar"
        "greenshot" = "Greenshot|greenshot"
        "sharex" = "ShareX|sharex"
        "gimp" = "Gimp|gimp"
        "adobereader" = "Adobe Acrobat Reader|adobereader"
        "spotify" = "Spotify|spotify"
        "vlc" = "VLC|vlc"
        "itunes" = "iTunes|itunes"
        "winamp" = "Winamp|winamp"
        "foobar2000" = "foobar2000|foobar2000"
        "klite" = "K-lite|k-litecodecpackfull"
        "mpchc" = "MPC-HC|mpc-hc"
        "notepad" = "Notepad++|notepadplusplus"
        "qbittorrent" = "qBittorrent|qbittorrent"
        "vscode" = "Visual Studio Code|vscode"
        "vim" = "Vim|vim"
        "putty" = "PuTTY|putty"
        "superputty" = "SuperPutty|superputty"
        "teraterm" = "Tera Term|teraterm"
        "filezilla" = "FileZilla|filezilla"
        "winscp" = "WinSCP|winscp"
        "mremoteng" = "MremoteNG|mremoteng"
        "wireshark" = "Wireshark|wireshark"
        "github" = "GitHub Desktop|github-desktop"
        "powershell" = "PowerShell Core|powershell-core"
        "terminal" = "Windows Terminal|microsoft-windows-terminal"
        "teams" = "Microsoft Teams|microsoft-teams"
        "zoom" = "Zoom|zoom"
        "webex" = "Webex|webex"
        "twitch" = "Twitch|twitch"
        "ubisoft" = "Ubisoft Connect|ubisoft-connect"
        "steam" = "Steam|steam"
        "avg" = "AVG Antivirus Free|avgantivirusfree"
        "avast" = "Avast Free Antivirus|avastfreeantivirus"
        "malwarebytes" = "Malwarebytes|malwarebytes"
        "eset" = "ESET Internet Security|eset-internet-security"
        }

    
    do {
        if (-not $Name -and -not $Default -and -not $EnableAutoupdate -and -not $IncludeVisualPlusplus) {

            Clear-Host
            Write-Host "APP-INSTALLER`n" -ForegroundColor Green
            Write-Host ""
            Write-Host "`tBrowser                                            " -BackgroundColor Green -ForegroundColor Black
            Write-Host "`tGoogle Chrome`t    Firefox`t    Brave" -ForegroundColor Green
            Write-Host "`tVivaldi`t`t    Opera`t    LibreWolf" -ForegroundColor Green
            Write-Host "`tTools for office/school                            " -BackgroundColor Green -ForegroundColor Black
            Write-Host "`tMicrosoft Office    7-Zip`t    VLC" -ForegroundColor Green
            Write-Host "`tTeams`t`t    Zoom`t    Webex" -ForegroundColor Green
            Write-Host "`tAdobe Reader`t    Greenshot`t    ShareX" -ForegroundColor Green
            Write-Host "`tSecurity                                            " -BackgroundColor Green -ForegroundColor Black
            Write-Host "`tAVG Free`t    Avast Free`t    Malwarebytes" -ForegroundColor Green
            Write-Host "`tTools for tech's                                    " -BackgroundColor Green -ForegroundColor Black
            Write-Host "`tvscode`t`t    notepad++`t    mRemoteNG" -ForegroundColor Green
            Write-Host "`tPuTTY`t`t    Tera Term`t    SuperPutty" -ForegroundColor Green
            Write-Host "`tPowerShell Core`t    WinSCP`t    FileZilla" -ForegroundColor Green
            Write-Host "`tEntertainment                                       " -BackgroundColor Green -ForegroundColor Black
            Write-Host "`tSteam`t`t    UbiSoft`t    Twitch" -ForegroundColor Green
            Write-Host "`tSpotify`t`t    Winamp`t    MPC-HC" -ForegroundColor Green
            Write-Host "`tqBittorent" -ForegroundColor Green
            Write-Host ""

            Write-Host "Hvilke applikationer vil du installere? (comma-separated):" -NoNewline -ForegroundColor Green
            $Name = Read-Host
        }

        $requested_apps = $Name -split "[,;\s]+" | Where-Object {$_ -ne ""}
        $headersToInstall = @()

        foreach ($app in $requested_apps) {
            if ($apps.ContainsKey($app)) {
                $headersToInstall += ($apps[$app] -split "\|")[0]
            }
        }

        Write-Host "Scriptet vil installere følgende:" -ForegroundColor Cyan
        foreach ($header in $headersToInstall) {
            Write-Host "    - $header" -ForegroundColor Yellow
        }

        Write-Host "Vil du fortsætte? (y/n): " -NoNewline
        $proceed = Read-Host

        if ($proceed -eq "n") {
            $Name = $null
            Write-Host "Installation annulleret.`n`n" -ForegroundColor Red}

    } while ($proceed -ne "y")

    # Opdel input fra pipeline
        $requested_apps = $Name -split "[,;\s]+" | Where-Object {$_ -ne ""}
    
    Write-Host "`n$(Get-LogDate)`tINSTALLING APPLICATIONS" -f Green; Start-Sleep -S 2

    # Installér applikationer
        
        if ($Name){
            # Installér Chocolatey hvis ikke den er
            if (!(Test-Path "$env:ProgramData\Chocolatey")) {
                Write-Host "$(Get-LogDate)`t    System preparation:" -f Green
                Write-Host "$(Get-LogDate)`t        - Installing Chocolatey." -f Yellow;
                
                # Start job
                [void](Start-Job -Name "Chocolatey Installation" -ScriptBlock {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))})

                # Vent på at jobbet er færdigt, men uden output
                Wait-Job -Name "Chocolatey Installation" | Out-Null

                # Import Chocolatey uden output
                Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1" -ErrorAction SilentlyContinue
                Update-SessionEnvironment | Out-Null}

                Write-Host "$(Get-LogDate)`t    Installing application:" -ForegroundColor Green 
        
                foreach ($requested_app in $requested_apps) {

                # Korriger inputs
                $app_info = $apps[$requested_app] -split "\|"
                $header = $app_info[0]
                $package = $app_info[1]
                $url = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/res/Template-AppInstall"
                    if ($header -eq "Microsoft Office 2016 Retail"){$url = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/res/Template-OfficeInstall"}
                    $content = irm $url
                    $modifiedContent = $content -replace "REPLACE-ME-APP", $package

                # Start et job, som kører det modificerede indhold direkte
                Write-Host "$(Get-LogDate)`t        - $header." -f Yellow;
                $job = Start-Job -Name $header -ScriptBlock {param ($scriptContent)
                    Invoke-Expression $scriptContent} -ArgumentList $modifiedContent

                # Vent til jobbet er færdigt
                Wait-Job -Name $header | Out-Null
                
                Add-Type -AssemblyName System.Windows.Forms
                $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
                $path = (Get-Process -id $pid).Path
                $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                $balmsg.BalloonTipText = "$($header) er nu installeret."
                $balmsg.BalloonTipTitle = "Installation fuldendt"
                $balmsg.Visible = $true
                $balmsg.ShowBalloonTip(20000)

                }

                Write-Host "$(Get-LogDate)`t    Applications installed." -f Green

                
        }


    # Automatisk opdatering af applikationer
       
        if ($EnableAutoupdate) {
            Write-Host "$(Get-LogDate)`t    Enabling automatic patching:" -f Green

            # Download Script
            $appupdaterlink = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1"
            $appupdaterpath = Join-Path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -ChildPath "WinOptimizer\app-updater.ps1"
            New-Item -Path $appupdaterpath -Force | Out-Null
            Write-Host "$(Get-LogDate)`t        - Downloading script." -f Yellow;
            Invoke-WebRequest -Uri $appupdaterlink -OutFile $appupdaterpath -UseBasicParsing

            # Setting Scheduled Task
            $Taskname = "WinOptimizer - Patching Desktop Applications"
            $Taskaction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ep bypass -w hidden -file $appupdaterpath"
            $Tasksettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit '03:00:00' -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
            $Tasktrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek 'Monday','Tuesday','Wednesday','Thursday','Friday' -At 11:50
            $User = [Environment]::UserName
            Write-Host "$(Get-LogDate)`t        - Scheduling task." -f Yellow;
            Register-ScheduledTask -TaskName $Taskname -Action $Taskaction -Settings $Tasksettings -Trigger $Tasktrigger -User $User -RunLevel Highest -Force | Out-Null

            Write-Host "$(Get-LogDate)`t            - Opgavenavn: $Taskname" -f Yellow;
            Write-Host "$(Get-LogDate)`t            - Complete." -f Yellow;
            Write-Host "$(Get-LogDate)`t        - Automatic patching for desktop applications is now enabled." -f Yellow;
        }


<#    # Installér Visual C++ Redistributable, hvis valgt
    if ($IncludeVisualPlusplus) { Write-Host "$(Get-LogDate)`t- Installere versionerne Visual C++ Redistributable..." -ForegroundColor Yellow
        Start-Job -Name "Visual C++" -ScriptBlock { 
            # Download
                $link = "https://drive.google.com/uc?export=download&confirm=uc-download-link&id=1mHvNVA_pI0XnWyjRDNee0vhQxLp6agp_"
                $FileDestination = "$($env:TMP)\drivers.zip"
                $path = ($FileDestination | split-path -parent)
                (New-Object net.webclient).Downloadfile($link, $FileDestination)
            # Unzip
                Expand-Archive $FileDestination -DestinationPath $path | Out-Null; 
                Start-Sleep -s 5
            # Install
                Set-Location $path
                ./vcredist2005_x64.exe /q | Out-Null
                ./vcredist2008_x64.exe /qb | Out-Null
                ./vcredist2010_x64.exe /passive /norestart | Out-Null
                ./vcredist2012_x64.exe /passive /norestart | Out-Null
                ./vcredist2013_x64.exe /passive /norestart | Out-Null
                ./vcredist2015_2017_2019_2022_x64.exe /passive /norestart | Out-Null}
            # Vent indtil installation er færdig
                Wait-Job -Name "Visual C++" | Out-Null
                Write-Host "$(Get-LogDate)`t- Visual C++ installation completed." -ForegroundColor Yellow} #>




}

# Eksempel på hvordan du kan kalde funktionen:
# Install-App -Name "firefox,chrome,teams" -EnableAutoupdate -IncludeVisualPlusplus
