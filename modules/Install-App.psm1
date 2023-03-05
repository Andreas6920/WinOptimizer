function Install-App {
    param ( [Parameter(Mandatory=$true)]
        [string]$Name)

# Disable Explorer first run
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1

#Create folders and files
    $folder = Join-Path $env:temp -ChildPath "app-installer"
    $applist = "$folder\app-list.txt"
    New-Item -Path $applist -Force | Out-Null
    $name.split(",").Trim() | ForEach-Object { add-content -value $_ -path $applist}
    $powershellfile = "$folder\app-installer.ps1" 
    New-Item -Path $powershellfile -Force | Out-Null
    
# Add Chocolatey installation script to file
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
If (!(Test-Path "$env:ProgramData\Chocolatey")) {
$WebResponse = Invoke-WebRequest -Uri "https://chocolatey.org/install"
$chococode = ($WebResponse.AllElements | ? {$_.Class -eq "form-control text-bg-theme-elevation-1 user-select-all border-start-0 ps-1"}).Value
if(!($chococode)){$chococode = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"}
Add-Content -Encoding UTF8 -Value $chococode -Path $powershellfile}

$requested_apps = get-content $applist
foreach ($requested_app in $requested_apps) {
    if("cancel" -eq "$requested_app"){Write-Output "Skipping this section.."}
    # Browsers
        elseif("Firefox" -match "$requested_app"){$header = "Mozilla Firefox"; $package = "firefox";} 
        elseif("Chrome" -match "$requested_app"){$header = "Google Chrome"; $package = "googlechrome";} 
        elseif("Brave" -match "$requested_app"){$header = "Brave Browser"; $package = "brave";} 
        elseif("Opera" -match "$requested_app"){$header = "Opera"; $package = "opera";} 
        elseif("Vivaldi" -match "$requested_app"){$header = "Libre wolf"; $package = "librewolf";}

    # Tools
        elseif("Dropbox" -match "$requested_app"){$header = "Dropbox"; $package = "dropbox";} 
        elseif("Google Drive" -match "$requested_app"){$header = "Google Drive"; $package = "googledrive";} 
        elseif("TeamViewer" -match "$requested_app"){$header = "TeamViewer"; $package = "teamviewer";} 
        elseif("7-zip" -match "$requested_app"){$header = "7-Zip"; $package = "7Zip";} 
        elseif("winrar" -match "$requested_app"){$header = "Winrar"; $package = "winrar";} 
        elseif("Greenshot" -match "$requested_app"){$header = "Greenshot"; $package = "greenshot";} 
        elseif("ShareX" -match "$requested_app"){$header = "ShareX"; $package = "sharex";} 
        elseif("Gimp" -match "$requested_app"){$header = "Gimp"; $package = "gimp";} 
        elseif("Adobe" -match "$requested_app"){$header = "Adobe Acrobat Reader"; $package = "adobereader";} 
    # Media Player
        elseif("spotify" -match "$requested_app"){$header = "Spotify"; $package = "Spotify";}  
        elseif("VLC" -match "$requested_app"){$header = "VLC"; $package = "VLC";}  
        elseif("itunes" -match "$requested_app"){$header = "iTunes"; $package = "itunes";}  
        elseif("Winamp" -match "$requested_app"){$header = "Winamp"; $package = "Winamp";}  
        elseif("foobar2000" -match "$requested_app"){$header = "foobar2000"; $package = "foobar2000";}  
        elseif("K-lite" -match "$requested_app"){$header = "K-lite"; $package = "k-litecodecpackfull";}  
        elseif("MPC-HC" -match "$requested_app"){$header = "MPC-HC"; $package = "MPC-HC";}  
        elseif("popcorn" -match "$requested_app"){$header = "Popcorntime"; $package = "popcorntime";}  
    # Development
        elseif("notepad" -match "$requested_app"){$header = "Notepad++"; $package = "notepadplusplus";}  
        elseif("vscode" -match "$requested_app"){$header = "Visual Studio Code"; $package = "vscode";}  
        elseif("atom" -match "$requested_app"){$header = "atom"; $package = "atom";}  
        elseif("vim" -match "$requested_app"){$header = "vim"; $package = "vim";} 
        elseif("Eclipse" -match "$requested_app"){$header = "Eclipse"; $package = "Eclipse";} 
        elseif("putty" -match "$requested_app"){$header = "PuTTY"; $package = "putty";} 
        elseif("superputty" -match "$requested_app"){$header = "SuperPutty"; $package = "superputty";} 
        elseif("teraterm" -match "$requested_app"){$header = "Tera Term"; $package = "teraterm";} 
        elseif("Filezilla" -match "$requested_app"){$header = "Filezilla"; $package = "filezilla";} 
        elseif("WinSCP" -match "$requested_app"){$header = "WinSCP"; $package = "WinSCP";} 
        elseif("mremoteng" -match "$requested_app"){$header = "MremoteNG"; $package = "mremoteng";} 
        elseif("wireshark" -match "$requested_app"){$header = "Wireshark"; $package = "wireshark";} 
        elseif("git" -match "$requested_app"){$header = "git"; $package = "git";}
        elseif("PowershellCore" -match "$requested_app"){$header = "PowerShell Core"; $package = "powershell-core";}
        elseif("Windows terminal" -match "$requested_app"){$header = "Windows terminal"; $package = "microsoft-windows-terminal";}
    # Social
        elseif("Microsoft Teams" -match "$requested_app"){$header = "Microsoft Teams"; $package = "microsoft-teams";} 
        elseif("Zoom" -match "$requested_app"){$header = "Zoom"; $package = "zoom";} 
        elseif("Webex" -match "$requested_app"){$header = "Webex"; $package = "webex";}
        elseif("Twitch" -match "$requested_app"){$header = "Twitch"; $package = "twitch";}
        elseif("Ubisoft Connect" -match "$requested_app"){$header = "Ubisoft Connect"; $package = "ubisoft-connect";}
    
    # Add entries to installer file
    Add-content -Value (invoke-webrequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/app-template.txt").Content.replace('REPLACE-ME-NAME', $header).replace('REPLACE-ME-APP', $package) -Path $powershellfile}
    
    # Execute installer file
    Start-Process Powershell -argument "-Ep bypass -Windowstyle hidden -file `"""$($env:TMP)\app-installer\app-installer.ps1""`""


    }