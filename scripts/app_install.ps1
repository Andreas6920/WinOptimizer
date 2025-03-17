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

    # Standardliste, hvis -Default vælges
    if ($Default) {$Name = "chrome,7zip,vlc,adobereader"}

    # Liste over tilgængelige applikationer
    $apps = @{
        "firefox" = "Mozilla Firefox|firefox"
        "chrome" = "Google Chrome|googlechrome"
        "brave" = "Brave Browser|brave"
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
        "vscode" = "Visual Studio Code|vscode"
        "vim" = "Vim|vim"
        "putty" = "PuTTY|putty"
        "superputty" = "SuperPutty|superputty"
        "teraterm" = "Tera Term|teraterm"
        "filezilla" = "FileZilla|filezilla"
        "winscp" = "WinSCP|winscp"
        "mremoteng" = "MremoteNG|mremoteng"
        "wireshark" = "Wireshark|wireshark"
        "git" = "Git|git"
        "powershell" = "PowerShell Core|powershell-core"
        "windowsterminal" = "Windows Terminal|microsoft-windows-terminal"
        "teams" = "Microsoft Teams|microsoft-teams"
        "zoom" = "Zoom|zoom"
        "webex" = "Webex|webex"
        "twitch" = "Twitch|twitch"
        "ubisoft" = "Ubisoft Connect|ubisoft-connect"}

    
    # Hvis INTET er sat
    if (-not $Name -and -not $Default -and -not $EnableAutoupdate -and -not $IncludeVisualPlusplus) {
        Write-Host "[$(Get-LogDate)]`t- Enter applications (comma-separated): " -NoNewline -ForegroundColor Yellow
        $Name = Read-Host}

    # Opdel input fra pipeline
        $requested_apps = $Name -split "[,;\s]+" | Where-Object {$_ -ne ""}

    # Installér Chocolatey, hvis det ikke er installeret
    if (!($requested_app -eq "cancel")){
    if (!(Test-Path "$env:ProgramData\Chocolatey")) {
        Write-Host "[$(Get-LogDate)]`t- Installing Chocolatey..." -ForegroundColor Yellow
        Start-Job -Name "Install_Choco" -ScriptBlock {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))} | Wait-Job | Out-Null
        Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1"; Update-SessionEnvironment}}

    # Installér Visual C++ Redistributable, hvis valgt
    if ($IncludeVisualPlusplus) { Write-Host "[$(Get-LogDate)]`t- Installere versionerne Visual C++ Redistributable..." -ForegroundColor Yellow
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
                Write-Host "[$(Get-LogDate)]`t- Visual C++ installation completed." -ForegroundColor Yellow

    # Tjek og korriger inputs
        foreach ($requested_app in $requested_apps) {
            
            # Office installation
            if ($requested_app -match "office") {
                $header = "Microsoft Office"
                $package = "microsoft-office-deployment"
                $params = "'/Product:ProfessionalRetail /64bit /ProofingToolLanguage:da-dk,en-us'" }
            
            # korriger inputs
            elseif ($apps.ContainsKey($requested_app)) {
                $app_info = $apps[$requested_app] -split "\|"
                $header = $app_info[0]
                $package = $app_info[1]
                $params = ""}
            
            # Invalid input
            else {Write-Host "[$(Get-LogDate)]`t- Applikationen '$requested_app' invalid. Springer over..." -ForegroundColor Yellow
            continue}
            
    # Installation start
    Write-Host "[$(Get-LogDate)]`t- Installing $header..." -ForegroundColor Yellow

        # Installation som job
        $job = Start-Job -Name $header -ScriptBlock {
            param($packageName, $installParams)
            
            # Refresh
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)
            if (!(Get-Command choco -ErrorAction SilentlyContinue)) {Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1"; Update-SessionEnvironment}
            
            if ($installParams -ne "") {choco install $packageName --params=$installParams -y | Out-Null} 
            else {choco install $packageName -y | Out-Null}
        
        } -ArgumentList $package, $params

        # Vent indtil installation er færdig
        $job | Wait-Job | Out-Null
        Write-Host "[$(Get-LogDate)]`t- $header installation completed." -ForegroundColor Yellow
        }

    # Installer auto-opdateringsværktøj, hvis flagget er angivet
    if ($EnableAutoupdate) {
        Write-Host "[$(Get-LogDate)]`t- Enabling auto-update..." -ForegroundColor Yellow

        # Download Script
        $appupdaterlink = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1"
        $appupdaterpath = Join-Path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -ChildPath "WinOptimizer\win_appinstaller\app-updater.ps1"
        New-Item -Path $appupdaterpath -Force | Out-Null
        Invoke-WebRequest -Uri $appupdaterlink -OutFile $appupdaterpath -UseBasicParsing

        # Setting Scheduled Task
        $Taskname = "WinOptimizer - Patching Desktop Applications"
        $Taskaction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ep bypass -w hidden -file $appupdaterpath"
        $Tasksettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit '03:00:00' -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
        $Tasktrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek 'Monday','Tuesday','Wednesday','Thursday','Friday' -At 11:50
        $User = [Environment]::UserName
        Register-ScheduledTask -TaskName $Taskname -Action $Taskaction -Settings $Tasksettings -Trigger $Tasktrigger -User $User -RunLevel Highest -Force | Out-Null

        Write-Host "[$(Get-LogDate)]`t- Auto-update enabled." -ForegroundColor Yellow
    }
}}

# Eksempel på hvordan du kan kalde funktionen:
# Install-App -Name "firefox,chrome,teams" -EnableAutoupdate -IncludeVisualPlusplus
