function Start-WinAppInstall {
    Function app_installer {
      
            Write-Host "`tApp installer:" -f Green
            function appinstall {
                param ( [Parameter(Mandatory=$true)]
                        [string]$Name,
                        [Parameter(Mandatory=$true)]
                        [string]$App,
                        [Parameter(Mandatory=$false)]
                        [switch]$IncludeOffice,
                        [Parameter(Mandatory=$false)]
                        [switch]$IncludeVisualPlusplus,
                        [Parameter(Mandatory=$false)]
                        [switch]$IncludeDotNet
                        )
            
                If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
                Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
                
                $code = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
                $appinstall = "$($env:ProgramData)\Winoptimizer\appinstall.ps1"
            
                if(!(test-path $appinstall)){new-item -ItemType Directory ($appinstall | Split-Path) -ea ignore | out-null; New-item $appinstall -ea ignore | out-null;}
                if(!((get-content $appinstall) -notmatch "https://community.chocolatey.org/install.ps1")){Set-content -Encoding UTF8 -Value $code -Path $appinstall}
            
                Add-content -Encoding UTF8 -Value (invoke-webrequest "https://paste.ee/r/XnPJT").Content.replace('REPLACE-ME-NAME', $Name).replace('REPLACE-ME-APP', $App) -Path $appinstall}
    
                Write-host "`tDesktop Applications:" -f Green;""; 
    
                write-host "`t`tBROWSER:" -f Yellow
                write-host "`t`t`tChrome        Firefox      Opera" -f Green
                write-host "`t`t`tBrave         Opera        Vevaldi" -f Green
                "";
                write-host "`t`tTOOLS:" -f Yellow
                write-host "`t`t`tDropbox       Google Drive    Teamviewer" -f Green
                write-host "`t`t`t7-zip         Winrar          Greenshot" -f Green
                write-host "`t`t`tShareX        Gimp            Adobe Acrobat Reader" -f Green
                "";
                write-host "`t`tMEDIA PLAYER:" -f Yellow
                write-host "`t`t`tSpotify       VLC           Itunes" -f Green
                write-host "`t`t`tWinamp        Foobar2000    K-Lite" -f Green
                write-host "`t`t`tMPC-HC        Popcorntime" -f Green
                "";
                write-host "`t`tDevelopment:" -f Yellow
                write-host "`t`t`tNotepad++       vscode           atom" -f Green
                write-host "`t`t`tVim             Eclipse          git " -f Green
                write-host "`t`t`tPuTTY           Superputty       TeraTerm" -f Green
                write-host "`t`t`tFilezilla       WinSCP           mRemoteNG" -f Green
                write-host "`t`t`tWireshark" -f Green
                "";
                write-host "`t`tSocial:" -f Yellow
                write-host "`t`t`tWebex           Zoom           Microsoft Teams" -f Green
                write-host "`t`t`tDiscord         Twitch         Ubisoft-Connect" -f Green
                "";
                Write-host "    ** List multiple programs seperated by , (comma) - spaces are allowed." -f Yellow;
                "";
                Write-host "Type the programs you would like to be installed on this system" -nonewline; 
                
    
                $requested_apps = (Read-Host " ").Split(",") | Foreach-object { $_ -replace ' ',''}
                foreach ($requested_app in $requested_apps) {
                    if("cancel" -eq "$requested_app"){Write-Output "Skipping this section.."}
                    # Browsers
                        elseif("Firefox" -match "$requested_app"){Appinstall -Name "Mozilla Firefox" -App "firefox"} 
                        elseif("Chrome" -match "$requested_app"){Appinstall -Name "Google Chrome" -App "googlechrome"} 
                        elseif("Brave" -match "$requested_app"){Appinstall -Name "Brave Browser" -App "brave"} 
                        elseif("Opera" -match "$requested_app"){Appinstall -Name "Opera" -App "opera"} 
                        elseif("Vivaldi" -match "$requested_app"){Appinstall -Name "Vivaldi" -App "vivaldi"} 
                    # Tools
                        elseif("Dropbox" -match "$requested_app"){Appinstall -Name "Dropbox" -App "dropbox"} 
                        elseif("Google Drive" -match "$requested_app"){Appinstall -Name "Google Drive" -App "googledrive"} 
                        elseif("TeamViewer" -match "$requested_app"){Appinstall -Name "TeamViewer" -App "teamviewer"} 
                        elseif("7-zip" -match "$requested_app"){Appinstall -Name "7-Zip" -App "7Zip"} 
                        elseif("winrar" -match "$requested_app"){Appinstall -Name "Winrar" -App "winrar"} 
                        elseif("Greenshot" -match "$requested_app"){Appinstall -Name "Greenshot" -App "greenshot"} 
                        elseif("ShareX" -match "$requested_app"){Appinstall -Name "ShareX" -App "sharex"} 
                        elseif("Gimp" -match "$requested_app"){Appinstall -Name "Gimp" -App "gimp"} 
                        elseif("Adobe" -match "$requested_app"){Appinstall -Name "Adobe Acrobat Reader" -App "adobereader"} 
                    # Media Player
                        elseif("spotify" -match "$requested_app"){Appinstall -Name "Spotify" -App "Spotify"}  
                        elseif("VLC" -match "$requested_app"){Appinstall -Name "VLC" -App "VLC"}  
                        elseif("itunes" -match "$requested_app"){Appinstall -Name "iTunes" -App "itunes"}  
                        elseif("Winamp" -match "$requested_app"){Appinstall -Name "Winamp" -App "Winamp"}  
                        elseif("foobar2000" -match "$requested_app"){Appinstall -Name "foobar2000" -App "foobar2000"}  
                        elseif("K-lite" -match "$requested_app"){Appinstall -Name "K-lite" -App "k-litecodecpackfull"}  
                        elseif("MPC-HC" -match "$requested_app"){Appinstall -Name "MPC-HC" -App "MPC-HC"}  
                        elseif("popcorn" -match "$requested_app"){Appinstall -Name "Popcorntime" -App "popcorntime"}  
                    # Development
                        elseif("notepad++" -match "$requested_app"){Appinstall -Name "Notepad++" -App "notepadplusplus"}  
                        elseif("vscode" -match "$requested_app"){Appinstall -Name "Visual Studio Code" -App "vscode"}  
                        elseif("atom" -match "$requested_app"){Appinstall -Name "atom" -App "atom"}  
                        elseif("vim" -match "$requested_app"){Appinstall -Name "vim" -App "vim"} 
                        elseif("Eclipse" -match "$requested_app"){Appinstall -Name "Eclipse" -App "Eclipse"} 
                        elseif("putty" -match "$requested_app"){Appinstall -Name "PuTTY" -App "putty"} 
                        elseif("superputty" -match "$requested_app"){Appinstall -Name "SuperPutty" -App "superputty"} 
                        elseif("teraterm" -match "$requested_app"){Appinstall -Name "Tera Term" -App "teraterm"} 
                        elseif("Filezilla" -match "$requested_app"){Appinstall -Name "Filezilla" -App "filezilla"} 
                        elseif("WinSCP" -match "$requested_app"){Appinstall -Name "WinSCP" -App "WinSCP"} 
                        elseif("mremoteng" -match "$requested_app"){Appinstall -Name "MremoteNG" -App "mremoteng"} 
                        elseif("wireshark" -match "$requested_app"){Appinstall -Name "Wireshark" -App "wireshark"} 
                        elseif("git" -match "$requested_app"){Appinstall -Name "git" -App "git"}
                    # Social
                        elseif("Microsoft Teams" -match "$requested_app"){Appinstall -Name "Microsoft Teams" -App "microsoft-teams"} 
                        elseif("Zoom" -match "$requested_app"){Appinstall -Name "Zoom" -App "zoom"} 
                        elseif("Webex" -match "$requested_app"){Appinstall -Name "Webex" -App "webex"}
                        elseif("Twitch" -match "$requested_app"){Appinstall -Name "Twitch" -App "twitch"}
                        elseif("Ubisoft Connect" -match "$requested_app"){Appinstall -Name "Ubisoft Connect" -App "ubisoft-connect"}
                }

    DO {
        Write-Host "`tWould you like to Install Microsoft Office? (y/n)" -f Yellow -nonewline;
        $answer1 = Read-host " " 
            Switch ($answer1) { 
      
            y {        
                
                #build your own: https://www.powershellgallery.com/packages/Install-Office365Suite/1.5/Content/Install-Office365Suite.ps1, https://github.com/mallockey/Install-Office365Suite
                
                
                # Choose version
                    "";
                    Write-Host "`t`tVersion Menu:" -f Green
                    "";
                    Write-Host "`t`t`t - Microsoft 365" -f Yellow
                    Write-Host "`t`t`t - Microsoft Office 2019 Business Retail" -f Yellow
                    Write-Host "`t`t`t - Microsoft Office 2016 Business Retail" -f Yellow
                    "";
                    DO {                     
                        Write-Host "`t`tWhich version would you prefer?" -f Green -nonewline;
                        $answer2 = Read-host " "
                        if("$answer2" -eq "Cancel"){Write-Host "`tSkipping this section.."}                         
                        elseif("$answer2" -match "365")       {$ver = "O365BusinessRetail"; $name = "Microsoft 365";}
                        elseif("$answer2" -match "2019")      {$ver = "HomeBusiness2019Retail"; $name = "Microsoft Office 2019";}
                        elseif("$answer2" -match "2016")      {$ver = "HomeBusinessRetail"; $name = "Microsoft Office 2016"}}
                    While($ver -notin "O365BusinessRetail", "HomeBusiness2019Retail","HomeBusinessRetail")     
              
                # Choose Language
                      "";
                      Write-Host "`t`tLanguage Menu:" -f Green
                      "";
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
                  
                #Installation
                    # Modify install script
                        # Download
                            $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/office-template.txt"
                            $installationfile = "$($env:TMP)\Start-WinAppInstall.ps1"
                            if(!(test-path $installationfile)){new-item -ItemType Directory ($installationfile | Split-Path) -ea ignore | out-null; New-item $installationfile -ea ignore | out-null;}
                            Add-content -Encoding UTF8 -Value (invoke-webrequest $link).Content.replace('REPLACE-ME-FULLNAME', $Name).replace('REPLACE-ME-VERSION', $ver).replace('REPLACE-ME-LANGUAGE', $lang) -Path $installationfile
                  
                        }
               
            n {Write-Host "`t`t- NO. Skipping this step."}}}
    
        While ($answer1 -notin "y", "n")
    
# Start installtion file in the background
    Start-Process Powershell -argument "-Ep bypass -Windowstyle hidden -file `"""$($env:TMP)\Start-WinAppInstall.ps1""`""

<#
# Microsoft Visual C++
    Do {
        Write-Host "`t- Install all Microsoft Visual C++ Redistributable versions? (y/n)" -f Yellow -nonewline; 
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing all the Visual C++ versions.." -f Green

                # Download file
                $link = "https://drive.google.com/uc?export=download&confirm=uc-download-link&id=1mHvNVA_pI0XnWyjRDNee0vhQxLp6agp_"
                $FileDestination = "$($env:TMP)\drivers.zip"
                (New-Object net.webclient).Downloadfile($link, $FileDestination)
                
                # Unzip file
                Expand-Archive $FileDestination -DestinationPath $path | Out-Null; 
                Start-Sleep -s 5
                
                # Install files
                Set-Location ($FileDestination | Split-Path -Parent)
                ./vcredist2005_x64.exe /q | Out-Null
                ./vcredist2008_x64.exe /qb | Out-Null
                ./vcredist2010_x64.exe /passive /norestart | Out-Null
                ./vcredist2012_x64.exe /passive /norestart | Out-Null
                ./vcredist2013_x64.exe /passive /norestart | Out-Null
                ./vcredist2015_2017_2019_2022_x64.exe /passive /norestart | Out-Null
                restart-explorer

                Write-Host "`t`t- Installation complete." -f Green;
                
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } }} 
    While ($answer -notin "y", "n")

    
    # .Net Framework
    Do {
        Write-Host "`t- Install all Microsoft .NET Framework? (y/n)" -f Yellow -nonewline; 
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing all the .Net Frameworks.." -f Green
                
                #Download file
                $link = 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/install-dotnet.ps1'
                $file = "$dir\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); 
                Start-Sleep -S 3

                # Run file
                Start-Process Powershell -argument "-ep bypass -windowstyle Hidden -file `"$file`""
                Start-Sleep -S 3
                restart-explorer

                Write-Host "`t`t- Installation complete." -f Green;
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }}
    While ($answer -notin "y", "n")
    #>


    Do {
        Write-Host "`tWould you like to install auto-updater? (y/n)" -f Green -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {   
                    #create update file
                    Write-Host "`t`t- Downloading updating script." -f Yellow
                    $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                    Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/app-updater.ps1" -OutFile $filepath -UseBasicParsing
                    
                    # Create scheduled job
                    Write-Host "`t`t- scheduling update routine." -f Yellow
                    $name = 'winoptimizer-app-Updater'
                    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-W hidden -ep bypass -file $filepath"
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                    $trigger= New-ScheduledTaskTrigger -At 12:00 -Daily
                    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -RunOnlyIfIdle -DontStopOnIdleEnd -IdleDuration 00:05:00 -IdleWaitTimeout 03:00:00

                    Register-ScheduledTask -TaskName $Name -Taskpath "\Microsoft\Windows\Winoptimizer\" -Settings $settings -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null
                                                                        
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red }}} 
    While ($answer -notin "y", "n")

    

#End of function
Write-Host "`tApp installer completed. Enjoy your freshly installed applications." -f Green
Start-Sleep 10