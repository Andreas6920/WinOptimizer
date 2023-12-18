#Install
    # TLS upgrade
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Disable Explorer first run
        $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
            If (!(Test-Path $RegistryKey)) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            if(!(Get-Item "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\" | ? Property -EQ "DisableFirstRunCustomize")){Write-host "`t- Disable First Run Internet Explorer.."; Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1}
    
    # Nuget Installation
        if(!(test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208")){
            $ProgressPreference = "SilentlyContinue"; Start-Sleep -S 1; Write-host "`t- Install Nuget";  
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null}
    
    # Create Base Folder
        $BaseFolder = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
        if(!(test-path $BaseFolder)){mkdir $BaseFolder -ErrorAction SilentlyContinue | Out-Null }

    # Preparing Scripts
        $scripts = @(
        "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_antibloat.ps1"
        "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_security.ps1"
        "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/win_settings.ps1")
        Foreach ($script in $scripts) {

        # Download Scripts
            $filename = split-path $script -Leaf
            $filedestination = join-path $BaseFolder -Childpath $filename
            (New-Object net.webclient).Downloadfile("$script", "$filedestination")
            
        # Creating Missing Regpath
            $reg_install = "HKLM:\Software\WinOptimizer"
            If(!(Test-Path $reg_install)) {New-Item -Path $reg_install -Force | Out-Null;}

        # Creating Missing Regkeys
            if (!((Get-Item -Path $reg_install).Property -match $filename)){Set-ItemProperty -Path $reg_install -Name $filename -Type String -Value 0}}

Function Restart-Explorer{
            <# When explorer restarts with the regular stop-process function, the active PowerShell loses focus,
            which means you'll have to click on the window in order to enter your input. here's the hotfix. #>
            taskkill /IM explorer.exe /F | Out-Null -ErrorAction SilentlyContinue
            start explorer | Out-Null
            $windowname = $Host.UI.RawUI.WindowTitle
            Add-Type -AssemblyName Microsoft.VisualBasic
            [Microsoft.VisualBasic.Interaction]::AppActivate($windowname)}

Function Start-Menu {
            <# When you're choosing the UI version of this script, the menu options will grey out if the exact script
            has aldready been ran on the system.. Yep, spent way to much time on this feature.#>
            param (
                [Parameter(Mandatory=$true)]
                [string]$Name,
                [Parameter(Mandatory=$true)]
                [string]$Number,
                [Parameter(Mandatory=$false)]
                [string]$Rename)

            $Base = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer"
            $path = Join-Path -Path $Base -Childpath "$Name.ps1"
            $file = "$Name.ps1"
            $filehash = (Get-FileHash $path).Hash
            $reg_install = "HKLM:\Software\WinOptimizer"
            $reghash = (get-ItemProperty -Path $reg_install -Name $file).$file

            if($filehash -eq $reghash){$color = "Gray"}
            elseif($filehash -ne $reghash){$color = "White"}
            if($reghash -eq "0"){$color = "White"}
            
            if($rename) {   Write-Host "`t[$number] - $rename" -ForegroundColor $color  }
            else {          Write-Host "`t[$number] - $name" -ForegroundColor $color    }}
            

Function Start-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }

Function Stop-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }

function Add-Reg {
        
        param (
            [Parameter(Mandatory=$true)]
            [string]$Path,
            [Parameter(Mandatory=$true)]
            [string]$Name,
            [Parameter(Mandatory=$true)]
            [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword',' Unknown')]
            [String]$Type,
            [Parameter(Mandatory=$true)]
            [string]$Value
        )

    If (!(Test-Path $path)) {New-Item -Path $path -Force | Out-Null}; 
    Set-ItemProperty -Path $path -Name $name -Type $type -Value $value -Force | Out-Null

}

function Install-App {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [switch]$EnableAutoupdate,
        [Parameter(Mandatory=$false)]
        [switch]$Default)

# Disable Explorer first run
    $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main"
    If (!(Test-Path $RegistryKey)) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
    if(!(Get-Item "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\" | ? Property -EQ "DisableFirstRunCustomize")){Write-Host "Preparing" -f Yellow; Write-host "`t- Disabling First Run Internet Explorer.."; Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1}

#Create folders and files
    $folder = [Environment]::GetFolderPath("CommonApplicationData")
    $folder = Join-path -Path $folder -Childpath "WinOptimizer\win_appinstaller"
    $applist = "$folder\app_list.txt"
    New-Item -Path $applist -Force | Out-Null
    $appinstallerscript = "$folder\app_installerscript.ps1" 
    New-Item -Path $appinstallerscript -Force | Out-Null

# Add Chocolatey installation script to file
    #If (!(Test-Path "$env:ProgramData\Chocolatey")) {
    if(!(get-command choco -ErrorAction SilentlyContinue)){        
    $WebResponse = Invoke-WebRequest -Uri "https://chocolatey.org/install"
    $chococode = ($WebResponse.AllElements | ? {$_.Class -eq "form-control text-bg-theme-elevation-1 user-select-all border-start-0 ps-1"}).Value
    if(!($chococode)){$chococode = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"}
    $refresh = 'if(!(get-command choco -ErrorAction SilentlyContinue)){Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1"; Update-SessionEnvironment}'
    Add-Content -Encoding UTF8 -Value $chococode -Path $appinstallerscript
    Add-Content -Encoding UTF8 -Value $refresh -Path $appinstallerscript}

# If 'Default' parameter is used, install default applications  
    if($Default){ write-host "Default package chosen:`n`t- Chrome`n`t- VLC`n`t- 7-zip`n`t- Adobe"; $name = "Chrome, vlc, 7-zip, Adobe"}

# If 'Name' parameter is NOT used, a user interface will be shown
        if(!$Name){
        Clear-Host
        Write-Host "`n`tAPP INSTALLER" -f Yellow
        Write-Host "`tList the desired applications, seperate them with comma.`n`tSyntax: Chrome, Adobe Reader, 7-zip, Notepad++" -f Gray
        Write-Host "`n"
        Write-Host "`t" -NoNewline
        Write-Host "BROWSERS                                            " -f DarkBlue -BackgroundColor Yellow
        Write-Host "`tGoogle Chrome`t`tMozilla Firefox`t`tBrave"
        Write-Host "`tOpera`t`t`t`tLibre Wolf`t`t`tVivaldi"
        Write-Host "`n"
        Write-Host "`t" -NoNewline
        Write-Host "TOOLS                                               " -f DarkBlue -BackgroundColor Yellow
        Write-Host "`tDrop Box`t`t`tGoogle Drive`t`tTeam Viewer"
        Write-Host "`t7zip`t`t`t`tGreenshot`t`t`tShareX"
        Write-Host "`tGimp`t`t`t`tAdobe Reader"
        Write-Host "`n"
        Write-Host "`t" -NoNewline
        Write-Host "MEDIA                                               " -f DarkBlue -BackgroundColor Yellow
        Write-Host "`tSpotify`t`t`t`tVLC`t`t`t`t`tiTunes"
        Write-Host "`tWinamp`t`t`t`tFoobar2000`t`t`tK-lite"
        Write-Host "`tMPC-HC"
        Write-Host "`n"
        Write-Host "`t" -NoNewline
        Write-Host "DEVELOPMENT                                         " -f DarkBlue -BackgroundColor Yellow
        Write-Host "`tNotepad++`t`t`tVisual Studio Code`tvscode"
        Write-Host "`tPuTTY`t`t`t`tSuperPutty`t`t`tTeraterm"
        Write-Host "`tVim`t`t`t`t`tFileZilla`t`t`tWinSCP"
        Write-Host "`tmRemoteNG`t`t`tWireshark`t`t`tgit"
        Write-Host "`tPowerShell Core"
        Write-Host "`n"
        Write-Host "`t" -NoNewline
        Write-Host "SOCIAL                                              " -f DarkBlue -BackgroundColor Yellow
        Write-Host "`tMicrosoft Teams`t`tZoom`t`t`t`tWebex"
        Write-Host "`tTwich`t`t`t`tUbisoft Connect"
        Write-Host "`n"
        Write-Host "`tOPTION: " -f Yellow -nonewline; ;
        $name = Read-Host
        Clear-Host}

# Converting 'Name' user input to app list        
    $name.Split(",").Replace("+","").Replace("-","").Replace(";",",").Replace(" ","") | ForEach-Object { add-content -value $_ -path $applist}
    $requested_apps = get-content $applist
    Write-host "Adding to queue:" -f Yellow

# Converting app list to install script
    foreach ($requested_app in $requested_apps) {
        
        # Cancel
            if("cancel" -eq "$requested_app"){Write-Output "Skipping this section.."}
        # Browsers
            elseif("firefox" -match "$requested_app"){$header = "Mozilla Firefox"; $package = "firefox"; Write-host "`t- $Header";} 
            elseif("chrome" -match "$requested_app"){$header = "Google Chrome"; $package = "googlechrome"; Write-host "`t- $Header";} 
            elseif("brave" -match "$requested_app"){$header = "Brave Browser"; $package = "brave"; Write-host "`t- $Header";} 
            elseif("opera" -match "$requested_app"){$header = "Opera"; $package = "opera"; Write-host "`t- $Header";} 
            elseif("vivaldi" -match "$requested_app"){$header = "Vivaldi"; $package = "vivaldi"; Write-host "`t- $Header";}
        # Tools
            elseif("dropbox" -match "$requested_app"){$header = "Dropbox"; $package = "dropbox"; Write-host "`t- $Header";} 
            elseif("drive" -match "$requested_app"){$header = "Google Drive"; $package = "googledrive"; Write-host "`t- $Header";} 
            elseif("teamviewer" -match "$requested_app"){$header = "TeamViewer"; $package = "teamviewer"; Write-host "`t- $Header";} 
            elseif("7zip" -match "$requested_app"){$header = "7-Zip"; $package = "7Zip"; Write-host "`t- $Header";} 
            elseif("winrar" -match "$requested_app"){$header = "Winrar"; $package = "winrar"; Write-host "`t- $Header";}
            elseif("Greenshot" -match "$requested_app"){$header = "Greenshot"; $package = "greenshot"; Write-host "`t- $Header";}
            elseif("sharex" -match "$requested_app"){$header = "ShareX"; $package = "sharex"; Write-host "`t- $Header";}
            elseif("gimp" -match "$requested_app"){$header = "Gimp"; $package = "gimp"; Write-host "`t- $Header";}
            elseif("adobe" -match "$requested_app"){$header = "Adobe Acrobat Reader"; $package = "adobereader"; Write-host "`t- $Header";}
        # Media Player
            elseif("spotify" -match "$requested_app"){$header = "Spotify"; $package = "Spotify"; Write-host "`t- $Header";}
            elseif("vlc" -match "$requested_app"){$header = "VLC"; $package = "VLC"; Write-host "`t- $Header";}
            elseif("itunes" -match "$requested_app"){$header = "iTunes"; $package = "itunes"; Write-host "`t- $Header";}
            elseif("Winamp" -match "$requested_app"){$header = "Winamp"; $package = "Winamp"; Write-host "`t- $Header";}
            elseif("foobar2000" -match "$requested_app"){$header = "foobar2000"; $package = "foobar2000"; Write-host "`t- $Header";}
            elseif("klite" -match "$requested_app"){$header = "K-lite"; $package = "k-litecodecpackfull"; Write-host "`t- $Header";}
            elseif("mpchc" -match "$requested_app"){$header = "MPC-HC"; $package = "MPC-HC"; Write-host "`t- $Header";}
        # Development
            elseif("notepad" -match "$requested_app"){$header = "Notepad++"; $package = "notepadplusplus"; Write-host "`t- $Header";}
            elseif("vscode" -match "$requested_app"){$header = "Visual Studio Code"; $package = "vscode"; Write-host "`t- $Header";}
            elseif("vim" -match "$requested_app"){$header = "vim"; $package = "vim"; Write-host "`t- $Header";}
            elseif("putty" -match "$requested_app"){$header = "PuTTY"; $package = "putty"; Write-host "`t- $Header";}
            elseif("superputty" -match "$requested_app"){$header = "SuperPutty"; $package = "superputty"; Write-host "`t- $Header";}
            elseif("teraterm" -match "$requested_app"){$header = "Tera Term"; $package = "teraterm"; Write-host "`t- $Header";}
            elseif("filezilla" -match "$requested_app"){$header = "Filezilla"; $package = "filezilla"; Write-host "`t- $Header";}
            elseif("winscp" -match "$requested_app"){$header = "WinSCP"; $package = "WinSCP"; Write-host "`t- $Header";}
            elseif("mremoteng" -match "$requested_app"){$header = "MremoteNG"; $package = "mremoteng"; Write-host "`t- $Header";}
            elseif("wireshark" -match "$requested_app"){$header = "Wireshark"; $package = "wireshark"; Write-host "`t- $Header";}
            elseif("git" -match "$requested_app"){$header = "git"; $package = "git"; Write-host "`t- $Header";}
            elseif("powershell" -match "$requested_app"){$header = "PowerShell Core"; $package = "powershell-core"; Write-host "`t- $Header";}
            elseif("Windowsterminal" -match "$requested_app"){$header = "Windows terminal"; $package = "microsoft-windows-terminal"; Write-host "`t- $Header";}
        # Social
            elseif("teams" -match "$requested_app"){$header = "Microsoft Teams"; $package = "microsoft-teams"; Write-host "`t- $Header";} 
            elseif("zoom" -match "$requested_app"){$header = "Zoom"; $package = "zoom"; Write-host "`t- $Header";}
            elseif("webex" -match "$requested_app"){$header = "Webex"; $package = "webex"; Write-host "`t- $Header";}
            elseif("twitch" -match "$requested_app"){$header = "Twitch"; $package = "twitch"; Write-host "`t- $Header";}
            elseif("ubisoft" -match "$requested_app"){$header = "Ubisoft Connect"; $package = "ubisoft-connect";  Write-host "`t- $Header";}

    # Add entries to template, insert template in installer script
        Add-content -Value (invoke-webrequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/app-template.txt").Content.replace('REPLACE-ME-NAME', $header).replace('REPLACE-ME-APP', $package) -Path $appinstallerscript}

   # Execute installer script
        Write-Host "Starting installation script" -f Yellow
        Start-Job -Name "Installation" -ScriptBlock  { Start-Process Powershell -argument "-Ep bypass -Windowstyle Hidden -file `"""C:\ProgramData\WinOptimizer\win_appinstaller\app_installerscript.ps1""`"" } | Out-Null
        Write-Host "Installing applications. (This may take a while)" -f Yellow
        Wait-Job -Name "Installation"  | Out-Null
    
    #Scheduling application updater service
        if(!$Name){
            Do {
                Write-Host "Would you like to configure applications to Auto Update? (y/n)" -nonewline;
                $appinstall = Read-Host " " 
                Switch ($appinstall) { 
                    Y {Write-Host "- Yes"; Install-AppUpdater;} 
                    N {Write-Host "- NO";} } 
                } 
            While($Readhost -notin "y", "n")}
        else{Install-AppUpdater;}
        
    # Operation complete 
    Write-Host "Installation complete" -f Yellow

            <#
            $regpath = "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist"
            $regData = 'cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx'
            New-Item -Path $regpath -Force
            New-ItemProperty -Path $regpath -Name 1 -Value $regData -PropertyType STRING -Force
            #>

}

Function Install-AppUpdater {
# Download Script
    $appupdaterlink = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1"
    $appupdaterpath = Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer\win_appinstaller\app-updater.ps1"
    New-Item -Path $appupdaterpath -Force | Out-Null
    Invoke-WebRequest -uri $appupdaterlink -OutFile $appupdaterpath -UseBasicParsing

# Setting Scheduled Task
    $Taskname = "WinOptimizer - Patching Desktop Applications"
    $Taskaction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ep bypass -w hidden -file $appupdaterpath"
    $Tasksettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit '03:00:00' -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
    $Tasktrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek 'Monday','Tuesday','Wednesday','Thursday','Friday' -At 11:50
    $User = If ($Args[0]) {$Args[0]} Else {[Environment]::UserName}
    Register-ScheduledTask -TaskName $Taskname -Action $Taskaction -Settings $Tasksettings -Trigger $Tasktrigger -User $User -RunLevel Highest -Force | Out-Null
}


Function Start-WinOptimizerUI {
Clear-Host
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 3.0
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "


# Start Menu

    Set-Location (Join-path -Path ([Environment]::GetFolderPath("CommonApplicationData")) -Childpath "WinOptimizer")
    #Clear-Host
    Write-Host $intro -f Yellow 
    Write-Host "`t[1] - All"
    Start-Menu -Name "win_antibloat" -Number "2" -Rename "Clean Windows"
    Start-Menu -Name "win_security" -Number "3" -Rename "Secure Windows"
    Start-Menu -Name "win_settings" -Number "4" -Rename "Configure Windows"
    Write-Host ""
    Write-Host "`t[0] - Quit"
    Write-Host ""
    Write-Host "`nOption: " -f Yellow -nonewline; ;

        $option = Read-Host
        Switch ($option) { 
            0 { exit }
            1 { }
            2 { .\win_antibloat.ps1; Add-Hash -Name "win_antibloat.ps1"; .\menu.ps1; }
            3 { .\win_security.ps1; Add-Hash -Name "win_security.ps1"; .\menu.ps1; }
            4 { .\win_settings.ps1; Add-Hash -Name "win_settings.ps1"; .\menu.ps1; }
            5 {  }
            Default { } 
        }




}