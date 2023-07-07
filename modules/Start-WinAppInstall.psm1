
    function Install-App {
        param  ([Parameter(Mandatory=$false)]
                [string]$Name,
                [Parameter(Mandatory=$false)]
                [switch]$IncludeOffice,
                [Parameter(Mandatory=$false)]
                [switch]$IncludeVisualPlusplus,
                [Parameter(Mandatory=$false)]
                [switch]$IncludeDotNet)
    
        # Prepare system
            # Disable Explorer first run
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
                Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
    
            # Create folders and files
                $folder = Join-Path $env:temp -ChildPath "app-installer"; New-item -Path $folder -ItemType Directory -Force | Out-Null
                $appinstaller = join-path $folder -Childpath "app-installer.ps1"; New-item -Path $appinstaller -Force | Out-Null
                $applist = join-path $folder -Childpath "app-list.txt"; New-item -Path $applist -Force | Out-Null
            
        if($Name){
            
            $name.split(",").Trim() | ForEach-Object { add-content -value $_ -path $applist}
            (Get-Content $applist) | ? {$_.trim() -ne "" } | Set-Content -Path $applist # Remove empty lines
            
            if(!(test-path "$env:ProgramData\Chocolatey")){
            $chocoinstall = Invoke-WebRequest -Uri "https://chocolatey.org/install"
            $chocoinstall = ($chocoinstall.AllElements | ? {$_.Class -eq "form-control text-bg-theme-elevation-1 user-select-all border-start-0 ps-1"}).Value
            if(!($chocoinstall)){$chocoinstall = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"}
            Add-Content -Encoding UTF8 -Value $chocoinstall -Path $appinstaller}
            $refresh = 'if(!(get-command choco -ErrorAction SilentlyContinue)){Import-Module "$env:ProgramData\chocolatey\helpers\chocolateyInstaller.psm1"; Update-SessionEnvironment}'
            Add-Content -Encoding UTF8 -Value $refresh -Path $appinstaller
    
        # Choco application entries
            # Add Entries to a list where chocolatey will read afterwards,
                
                $apps = get-content $applist
                foreach ($app in $apps) {
                    if("cancel" -eq "$app"){Write-Output "Skipping this section.."}
                # Browsers
                    elseif("Firefox" -match "$app"){$header = "Mozilla Firefox"; $package = "firefox";} 
                    elseif("Chrome" -match "$app"){$header = "Google Chrome"; $package = "googlechrome";} 
                    elseif("Brave" -match "$app"){$header = "Brave Browser"; $package = "brave";} 
                    elseif("Opera" -match "$app"){$header = "Opera"; $package = "opera";} 
                    elseif("vivaldi" -match "$app"){$header = "Vivaldi"; $package = "Vivaldi";}
                    elseif("Libre Wolf" -match "$app"){$header = "Libre Wolf"; $package = "librewolf";}
                # Tools
                    elseif("Dropbox" -match "$app"){$header = "Dropbox"; $package = "dropbox";} 
                    elseif("Google Drive" -match "$app"){$header = "Google Drive"; $package = "googledrive";} 
                    elseif("TeamViewer" -match "$app"){$header = "TeamViewer"; $package = "teamviewer";} 
                    elseif("7zip|7-zip" -match "$app"){$header = "7-Zip"; $package = "7Zip";} 
                    elseif("winrar" -match "$app"){$header = "Winrar"; $package = "winrar";} 
                    elseif("Greenshot" -match "$app"){$header = "Greenshot"; $package = "greenshot";} 
                    elseif("ShareX" -match "$app"){$header = "ShareX"; $package = "sharex";} 
                    elseif("Gimp" -match "$app"){$header = "Gimp"; $package = "gimp";} 
                    elseif("Adobe Acrobat Reader" -match "$app"){$header = "Adobe Acrobat Reader"; $package = "adobereader";}
                    elseif("Process Hacker" -match "$app"){$header = "Process Hacker"; $package = "processhacker";}
                    elseif("process explorer" -match "$app"){$header = "Process Explorer"; $package = "procexp";}
                    elseif("Autoruns" -match "$app"){$header = "Autoruns"; $package = "autoruns";}
    
                # Media Player
                    elseif("spotify" -match "$app"){$header = "Spotify"; $package = "Spotify";}  
                    elseif("VLC" -match "$app"){$header = "VLC"; $package = "VLC";}  
                    elseif("itunes" -match "$app"){$header = "iTunes"; $package = "itunes";}  
                    elseif("Winamp" -match "$app"){$header = "Winamp"; $package = "Winamp";}  
                    elseif("foobar2000" -match "$app"){$header = "foobar2000"; $package = "foobar2000";}  
                    elseif("K-lite" -match "$app"){$header = "K-lite"; $package = "k-litecodecpackfull";}  
                    elseif("MPC-HC" -match "$app"){$header = "MPC-HC"; $package = "MPC-HC";}  
                    elseif("popcorn" -match "$app"){$header = "Popcorntime"; $package = "popcorntime";}  
                # Development
                    elseif("notepad" -match "$app"){$header = "Notepad++"; $package = "notepadplusplus";}  
                    elseif("vscode" -match "$app"){$header = "Visual Studio Code"; $package = "vscode";}  
                    elseif("atom" -match "$app"){$header = "atom"; $package = "atom";}  
                    elseif("vim" -match "$app"){$header = "vim"; $package = "vim";}
                    elseif("python" -match "$app"){$header = "Python"; $package = "python3";}
                    elseif("Eclipse" -match "$app"){$header = "Eclipse"; $package = "Eclipse";} 
                    elseif("putty" -match "$app"){$header = "PuTTY"; $package = "putty";} 
                    elseif("superputty" -match "$app"){$header = "SuperPutty"; $package = "superputty";} 
                    elseif("teraterm" -match "$app"){$header = "Tera Term"; $package = "teraterm";} 
                    elseif("Filezilla" -match "$app"){$header = "Filezilla"; $package = "filezilla";} 
                    elseif("WinSCP" -match "$app"){$header = "WinSCP"; $package = "WinSCP";} 
                    elseif("mremoteng" -match "$app"){$header = "MremoteNG"; $package = "mremoteng";} 
                    elseif("wireshark" -match "$app"){$header = "Wireshark"; $package = "wireshark";} 
                    elseif("git" -match "$app"){$header = "git"; $package = "git";}
                    elseif("PowershellCore" -match "$app"){$header = "PowerShell Core"; $package = "powershell-core";}
                    elseif("Windows terminal" -match "$app"){$header = "Windows terminal"; $package = "microsoft-windows-terminal";}
                # Social
                    elseif("Microsoft Teams" -match "$app"){$header = "Microsoft Teams"; $package = "microsoft-teams";} 
                    elseif("Zoom" -match "$app"){$header = "Zoom"; $package = "zoom";} 
                    elseif("Webex" -match "$app"){$header = "Webex"; $package = "webex";}
                    elseif("Twitch" -match "$app"){$header = "Twitch"; $package = "twitch";}
                    elseif("Ubisoft Connect" -match "$app"){$header = "Ubisoft Connect"; $package = "ubisoft-connect";}
    
            # Add to script
                $apptemplate = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/app-template.txt"
                Add-content -Value (invoke-webrequest -uri $apptemplate).Content.replace('REPLACE-ME-NAME', $header).replace('REPLACE-ME-APP', $package) -Path $appinstaller}
            }
        
        
            # Microsoft Office
            if ($IncludeOffice){
            DO { 
                Write-Host "`tWould you like to Install Microsoft Office? (y/n)" -f Yellow -nonewline;
                $answer1 = Read-host " " 
                Switch ($answer1) { 
                y {          
                    # Microsoft Office Type
                        "";
                        Write-Host "`t`tVersion Menu:" -f Green
                        "";
                        Write-Host "`t`t`t - Microsoft 365" -f Yellow
                        Write-Host "`t`t`t - Microsoft Office 2019 Business Retail" -f Yellow
                        Write-Host "`t`t`t - Microsoft Office 2016 Business Retail" -f Yellow
                        "";
                    # Microsoft Office Version
                        DO {                     
                        Write-Host "`t`tWhich version would you prefer?" -f Green -nonewline;
                        $answer2 = Read-host " "
                        if("$answer2" -eq "Cancel"){Write-Host "`tSkipping this section.."}                         
                        elseif("$answer2" -match "365")       {$ver = "O365BusinessRetail"; $name = "Microsoft 365";}
                        elseif("$answer2" -match "2019")      {$ver = "HomeBusiness2019Retail"; $name = "Microsoft Office 2019";}
                        elseif("$answer2" -match "2016")      {$ver = "HomeBusinessRetail"; $name = "Microsoft Office 2016"}}
                        While($ver -notin "O365BusinessRetail", "HomeBusiness2019Retail","HomeBusinessRetail")     
                  
                    # Microsoft Office Language
                        "";Write-Host "`t`tLanguage Menu:" -f Green;""
                        Write-Host "`t`t`t- English (United States)" -f Yellow
                        Write-Host "`t`t`t- German" -f Yellow
                        Write-Host "`t`t`t- Spanish" -f Yellow
                        Write-Host "`t`t`t- Danish" -f Yellow
                        Write-Host "`t`t`t- France" -f Yellow
                        Write-Host "`t`t`t- Japanese" -f Yellow
                        Write-Host "`t`t`t- Norwegian" -f Yellow
                        Write-Host "`t`t`t- Russia" -f Yellow
                        Write-Host "`t`t`t- Sweden" -f Yellow
                        "";
                        DO {       
                        Write-Host "`t`tEnter your language from above" -f Green -nonewline;
                        $answer3 = Read-host " "              
                        if("$answer3" -eq "Cancel"){Write-Host "`tSkipping this section.."}                         
                        elseif("$answer3" -match "^Eng")   {$lang = "en-us"}
                        elseif("$answer3" -match "^Ger")   {$lang = "de-de"}
                        elseif("$answer3" -match "^Spa")   {$lang = "es-es"}
                        elseif("$answer3" -match "^Dan")   {$lang = "da-dk"}
                        elseif("$answer3" -match "^Fra")   {$lang = "fr-fr"}
                        elseif("$answer3" -match "^Jap")   {$lang = "ja-jp"}
                        elseif("$answer3" -match "^Nor")   {$lang = "nb-no"}
                        elseif("$answer3" -match "^Rus")   {$lang = "ru-ru"}
                        elseif("$answer3" -match "^Swe")   {$lang = "sv-se"}}
                        While($lang -notin "en-us", "de-de","es-es","da-dk","fr-fr","ja-jp","nb-no","ru-ru","sv-se") 
                    
            # Add to script
                $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/office-template.txt"
                Add-content -Encoding UTF8 -Value (invoke-webrequest -uri $link).Content.replace('REPLACE-ME-FULLNAME', $Name).replace('REPLACE-ME-VERSION', $ver).replace('REPLACE-ME-LANGUAGE', $lang) -Path $appinstaller}
                n {Write-Host "`t`t- NO. Skipping this step." -f Red}}}
                While ($answer1 -notin "y", "n")}
    
        # Execute installer file
            if(test-path $appinstaller){
                # Run script 
                    Write-Host "`t`t- Running installation of apps in the background" -f Yellow
                    Start-Process Powershell -argument "-Ep bypass -w hidden -file `"""$($env:TMP)\app-installer\app-installer.ps1""`""
                    do{Start-Sleep -S 1}until(test-path (join-path -path $env:ProgramData -childpath "chocolatey")) # wait for choco installation before continue
                
                # Setup autoupdate    
                    Write-Host "`t`t- Scheduling update routine" -f Yellow
    
                    # Download script
                        $appupdatelink = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1"
                        $appupdatepath = join-path -Path "$env:ProgramData" -childpath "chocolatey\app-updater.ps1"
                        (New-Object net.webclient).Downloadfile($appupdatelink, $appupdatepath)
    
                    # schedule job for script
                        
                        $jobname = "Winoptimizer: Patching - Desktop Applications"
                        $jobprincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType ServiceAccount -RunLevel Highest
                        $jobtrigger= New-ScheduledTaskTrigger -Weekly -DaysOfWeek 'Monday','Tuesday','Wednesday','Thursday','Friday' -At 11:50
                        $jobaction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ep bypass -w hidden -file $appupdatepath"
                        $jobsettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit '03:00:00' -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
                        Register-ScheduledTask -TaskName $jobname -Settings $jobsettings -Principal $jobprincipal -Action $jobaction -Trigger $jobtrigger -Force | Out-Null}
    
        # Microsoft Visual C++
            if ($IncludeVisualPlusplus){
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
                    ./vcredist2015_2017_2019_2022_x64.exe /passive /norestart | Out-Null
                    restart-explorer
                    Write-Host "`t`t- Installation complete." -f Green;}
    
        # .Net Framework
            if($IncludeDotNet){
                    $link = 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/install-dotnet.ps1'
                    $filepath = join-path -Path $env:TMP -ChildPath ($link | Split-Path -Leaf)
                    (New-Object net.webclient).Downloadfile("$link", "$filepath")
                    Start-Process Powershell -argument "-ep bypass -windowstyle Hidden -file `"$filepath`""
                    }
       
   

    
}
#End of function
Write-Host "`tApp installer completed. Enjoy your freshly installed applications." -f Green
Start-Sleep 10