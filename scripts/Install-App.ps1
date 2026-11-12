Function Install-App {
    
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$DefaultAppPack,
        [Parameter(Mandatory=$false)]
        [switch]$DefaultAppPackWithOffice2016,
        [Parameter(Mandatory=$false)]
        [switch]$ActivateWindows,
        [Parameter(Mandatory=$false)]
        [switch]$ActivateMSOffice,
        [Parameter(Mandatory=$false)]
        [switch]$EnableAutoupdate,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeVisualPlusplus)

    <#
        .SYNOPSIS
        Install app function

        .DESCRIPTION
        Automates desktop applications installation, patching and activation.

        .EXAMPLE
        Install-App -Name "Chrome,7-zip,VLC,Office" -EnableAutoupdate

        .NOTES
            Potential improvements:
            - Configure application preferences based on installed apps:
                - Set Acrobat as the default PDF viewer when installed.
                - Configure ShareX when installed.
            - AM setup?
            - .NET setup?
            - Visual C++ setup?
    #>

    ## Remove before upload; added for testing.
        # Timestamps for actions
        Function Get-LogDate {
        return (Get-Date -f "[yyyy/MM/dd HH:mm:ss]")}

    if (-not (Assert-WinOptimizerAdministrator -Action 'Install-App')) {return}
	
    # Default application list.
    if ($DefaultAppPack) {$Name = "chrome,7zip,vlc"}
    if ($DefaultAppPackWithOffice2016) {$Name = "chrome,office,7zip,vlc"}

    # Map each input name to the display name and Chocolatey package used by the templates.
    $apps = @{
        "default" = "default|default"
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

    
    # Show the menu when no parameters are specified.
    
        if (-not $Name -and -not $DefaultAppPack -and -not $DefaultAppPackWithOffice2016 -and -not $EnableAutoupdate -and -not $IncludeVisualPlusplus -and -not $ActivateWindows -and -not $ActivateMSOffice) {
            do {
            Clear-Host
            Write-Host "APP-INSTALLER`n" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "`tBrowser                                            " -BackgroundColor Cyan -ForegroundColor Black
            Write-Host "`tGoogle Chrome`t    Firefox`t    Brave" -ForegroundColor Cyan
            Write-Host "`tVivaldi`t`t    Opera`t    LibreWolf" -ForegroundColor Cyan
            Write-Host "`tTools for office/school                            " -BackgroundColor Cyan -ForegroundColor Black
            Write-Host "`tMicrosoft Office    7-Zip`t    VLC" -ForegroundColor Cyan
            Write-Host "`tTeams`t`t    Zoom`t    Webex" -ForegroundColor Cyan
            Write-Host "`tAdobe Reader`t    Greenshot`t    ShareX" -ForegroundColor Cyan
            Write-Host "`tSecurity                                            " -BackgroundColor Cyan -ForegroundColor Black
            Write-Host "`tAVG Free`t    Avast Free`t    Malwarebytes" -ForegroundColor Cyan
            Write-Host "`tTools for tech's                                    " -BackgroundColor Cyan -ForegroundColor Black
            Write-Host "`tvscode`t`t    notepad++`t    mRemoteNG" -ForegroundColor Cyan
            Write-Host "`tPuTTY`t`t    Tera Term`t    SuperPutty" -ForegroundColor Cyan
            Write-Host "`tPowerShell Core`t    WinSCP`t    FileZilla" -ForegroundColor Cyan
            Write-Host "`tEntertainment                                       " -BackgroundColor Cyan -ForegroundColor Black
            Write-Host "`tSteam`t`t    UbiSoft`t    Twitch" -ForegroundColor Cyan
            Write-Host "`tSpotify`t`t    Winamp`t    MPC-HC" -ForegroundColor Cyan
            Write-Host "`tqBittorent" -ForegroundColor Cyan
            Write-Host ""

            Write-Host "Which applications would you like to install? (comma-separated):" -NoNewline -ForegroundColor Cyan
            $Name = Read-Host
        

                $requested_apps = $Name -split "[,;\s]+" | Where-Object {$_ -ne ""}
                $headersToInstall = @()

                foreach ($app in $requested_apps) {
                    if ($apps.ContainsKey($app)) {
                        $headersToInstall += ($apps[$app] -split "\|")[0]
                    }
                }

                Write-Host "The following applications will be installed:" -ForegroundColor Cyan
                foreach ($header in $headersToInstall) {
                    Write-Host "    - $header" -ForegroundColor Yellow
                }

                Write-Host "Would you like to continue? (y/n): " -NoNewline
                $proceed = Read-Host

                if ($proceed -eq "n") {
                    $Name = $null
                    Write-Host "Installation cancelled.`n`n" -ForegroundColor Red}

            } while ($proceed -ne "y")}

    # Split piped input.
        $requested_apps = $Name -split "[,;\s]+" | Where-Object {$_ -ne ""}

    # Install applications.
    Write-Host "`n$(Get-LogDate)`tINSTALLING APPLICATIONS" -ForegroundColor Cyan; Start-Sleep -S 2
        
        if ($Name){
            # Install Chocolatey if it is not already installed.
            if (!(Test-Path "$env:ProgramData\Chocolatey")) {
                Write-Host "$(Get-LogDate)`t    System preparation:" -ForegroundColor Cyan
                Write-Host "$(Get-LogDate)`t        - Installing Chocolatey." -f Yellow;
                
                # Start job
                [void](Start-Job -Name "Chocolatey Installation" -ScriptBlock {
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))})

                # Wait for the job to finish without displaying its output.
                Wait-Job -Name "Chocolatey Installation" | Out-Null

                # Import Chocolatey without displaying output.
                Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1" -ErrorAction SilentlyContinue
                Update-SessionEnvironment | Out-Null}

                Write-Host "$(Get-LogDate)`t    Installing application:" -ForegroundColor Cyan
        
                foreach ($requested_app in $requested_apps) {

                # Normalize the input.
                $app_info = $apps[$requested_app] -split "\|"
                $header = $app_info[0]
                $package = $app_info[1]
                $url = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/res/Template-AppInstall"
                    if ($header -eq "Microsoft Office 2016 Retail"){$url = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/refs/heads/main/res/Template-OfficeInstall"}
                    # The downloaded template contains a package placeholder replaced for this app.
                    $content = irm $url
                    $modifiedContent = $content -replace "REPLACE-ME-APP", $package

                # Start a job that runs the modified content directly.
                Write-Host "$(Get-LogDate)`t        - $header." -f Yellow;
                $job = Start-Job -Name $header -ScriptBlock {param ($scriptContent)
                    Invoke-Expression $scriptContent} -ArgumentList $modifiedContent

                # Wait for the job to finish.
                Wait-Job -Name $header | Out-Null
                
                Add-Type -AssemblyName System.Windows.Forms
                $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
                $path = (Get-Process -id $pid).Path
                $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
                $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                $balmsg.BalloonTipText = "$($header) has been installed."
                $balmsg.BalloonTipTitle = "Installation complete"
                $balmsg.Visible = $true
                $balmsg.ShowBalloonTip(20000)

                }

                Write-Host "$(Get-LogDate)`t    Applications installed." -ForegroundColor Cyan
                
        }

        
    # Install the Visual C++ Redistributables if requested.
    if ($IncludeVisualPlusplus) { Write-Host "$(Get-LogDate)`t    Installing all versions of the Visual C++ Redistributables:" -ForegroundColor Cyan
    Start-Job -Name "Visual C++" -ScriptBlock { 
        # Download
            $link = "https://nl1-dl.techpowerup.com/files/AREvQDJmUpviZKyo2OKzkw/1745448692/Visual-C-Runtimes-All-in-One-Mar-2025.zip"
            $path = "$env:TMP\Visual-C-Runtimes-All-in-One"
                if (Test-Path -Path $path) {Remove-Item -Path $path -Recurse -Force}
                New-Item -Path $path -ItemType Directory | Out-Null
                start $path
            $FileDestination = "$env:TMP\Visual-C-Runtimes-All-in-One\Visual-C-Runtimes-All-in-One.zip"
            (New-Object net.webclient).Downloadfile($link, $FileDestination)
        # Unzip
            Expand-Archive $FileDestination -DestinationPath $path | Out-Null; 
            Start-Sleep -s 5
        # Install
            Set-Location $path
            ./vcredist2005_x64.exe /q
            ./vcredist2008_x64.exe /qb
            ./vcredist2010_x64.exe /passive /norestart
            ./vcredist2012_x64.exe /passive /norestart
            ./vcredist2013_x64.exe /passive /norestart
            ./vcredist2015_2017_2019_2022_x64.exe /passive /norestart}
        # Wait for the installation to finish.
            Wait-Job -Name "Visual C++" | Out-Null
            Write-Host "$(Get-LogDate)`t        - Visual C++ installation complete." -ForegroundColor Yellow}


    # Activation
        $ActivationScript = Join-path -Path $env:TMP -Childpath "activation.ps1"
        if ($ActivateWindows -or $ActivateMSOffice) {New-Item -Path $ActivationScript -ItemType File -Force | Out-Null}
        if ($ActivateWindows){$code = Invoke-RestMethod "https://raw.githubusercontent.com/Andreas6920/Other/refs/heads/main/scripts/Get-ActivatedWindows.ps1"; Add-Content -Path $ActivationScript -Value $code -Encoding UTF8}
        if ($ActivateWindows -and $ActivateMSOffice) {Add-Content -Path $ActivationScript -Value "Start-Sleep -Seconds 10" -Encoding UTF8}
        if ($ActivateMSOffice){$code = Invoke-RestMethod  "https://raw.githubusercontent.com/Andreas6920/Other/refs/heads/main/scripts/Get-ActivatedOffice.ps1"; Add-Content -Path $ActivationScript -Value $code -Encoding UTF8}
        if(test-path $ActivationScript){
                Add-content -Path $ActivationScript -Value "Remove-item $ActivationScript -Force" -Encoding UTF8
                Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$ActivationScript`"" ` -WindowStyle Minimized}

    # Automatically update applications.
        if ($EnableAutoupdate) {
            Write-Host "$(Get-LogDate)`t    Enabling automatic patching:" -ForegroundColor Cyan

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

            Write-Host "$(Get-LogDate)`t            - Task name: $Taskname" -f Yellow;
            Write-Host "$(Get-LogDate)`t            - Complete." -f Yellow;
            Write-Host "$(Get-LogDate)`t        - Automatic patching for desktop applications is now enabled." -f Yellow;
        }

        


}
