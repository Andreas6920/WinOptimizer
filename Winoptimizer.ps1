#clean terminal before run
Clear-Host
    
#Functions
Function remove_bloatware {
    Write-host "`n`n INITIALIZING BLOAT REMOVER" -f green;
    Write-host "    - Removing bloat apps and games:" -f green;
    $ProgressPreference = "SilentlyContinue" #hide progressbar

    $Bloatware = @(		
        # Microsoft Bloat ##
        "Microsoft.ZuneMusic"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.Getstarted"
        "Microsoft.Office.OneNote"
        "Microsoft.People"
        "Microsoft.3DBuilder"
        "*officehub*"
        "*feedback*"
        "Microsoft.Music.Preview"
        "Microsoft.WindowsMaps"
        "*windowscommunicationsapps*"
        "*autodesksketch*"
        "*plex*"
        "*print3d*"
        "*Paint3D*"
        "*Mixed*"
        "*oneconnect*"
                                            
        ## Xbox Bloat ##
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.XboxGameOverlay"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxApp"
                                            
        ## Bing Bloat ##
        "Microsoft.BingTravel"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingWeather"
        "Microsoft.BingNews"
        "Microsoft.BingFinance"
        "Microsoft.BingSports"
        "Microsoft.Bing*"
        "*Bing*"

        ## Games ##
        "*disney*"
        "*candycrush*"
        "*minecraft*"
        "*bubblewitch*"
        "*empires*"
        "*Royal Revolt*"
                            
        ## Other crap ##
        "*Skype*"
        "*Facebook*"
        "*Twitter*"
        "*Spotify*"
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*Wunderlist*"
        "*Flipboard*"
    )
    foreach ($Bloat in $Bloatware) {
        $bloat_output = Get-AppxPackage | Where-Object Name -Like $Bloat | Select -Property Name; #Write-Host "        - Removing: $bloat_output"
        if ($bloat_output -ne $null) { Write-host "        - Removing: " -f yellow -nonewline; write-host "$bloat_output".Split(".")[1].Split("}")[0] -f yellow }
        Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
    }
    Write-host "        - Bloat app removal complete. " -f yellow;
    $ProgressPreference = "Continue" #unhide progressbar
    
    Write-Output "    - Disabling scheduled tasks" -f green
        Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask | Out-Null
        Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask | Out-Null
        Get-ScheduledTask  Consolidator | Disable-ScheduledTask | Out-Null
        Get-ScheduledTask  UsbCeip | Disable-ScheduledTask | Out-Null
        Get-ScheduledTask  DmClient | Disable-ScheduledTask | Out-Null
        Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask | Out-Null

    
    
    #Unpin start menu

    $START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
    

    $layoutFile = "C:\Windows\StartMenuLayout.xml"
            
    Write-host "    - Cleaning Start Menu from pinned bloat:" -f Green;
    #Delete layout file if it already exists
    Write-Host "        - Removing current Start Menu..." -f Green
    If (Test-Path $layoutFile) {
        Remove-Item $layoutFile
    }

    #Creates the blank layout file
    Write-host "        - Creates and applying a new blank start menu..." -f Green
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII
    $regAliases = @("HKLM", "HKCU")

    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        IF (!(Test-Path -Path $keyPath)) { 
            New-Item -Path $basePath -Name "Explorer" | Out-Null
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Write-host "        - Restarting explorer..." -f Green
    Stop-Process -name explorer -Force
    Start-Sleep -s 5

    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
    }
    Stop-Process -name explorer
    write-host "        - Save changes to all users.." -f Green
    Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
    Remove-Item $layoutFile
    write-host "        - Start menu bloat removal complete." -f Green
        
    #Clean Taskbar
    Write-host "    - Cleaning Taskbar:" -f Green;
    write-host "        - Changing keys.." -f Green
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesChanges -Value 3 -Type Dword -Force | Out-Null
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesRemovedChanges -Value 32 -Type Dword -Force | Out-Null
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesVersion -Value 3 -Type Dword -Force | Out-Null
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
    write-host "        - Removing shortcuts.." -f Green
    Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse -Force | Out-Null
    Stop-Process -name explorer
    start-sleep 5
    write-host "        - Taskbar is now clean." -f Green
            
}
Function settings_privacy {
      
    Write-host "    Changing settings to protect your privacy:" -f Green
          
    # Disable Advertising ID
    Write-host "    - Disabling advertising ID." -f Green
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    Start-Sleep -s 2
      
    # Disable let websites provide locally relevant content by accessing language list
    Write-host "    - Disabling location tracking." -f Green
    If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
        New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
    }
    Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
    Start-Sleep -s 2
      
    # Disable Show me suggested content in the Settings app
    Write-host "    - Disabling personalized content suggestions." -f Green
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
    Start-Sleep -s 2
      
    # Remove Cortana
    Write-host "    - Disabling Cortana." -f Green
    Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
    If (!(Test-Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
    Stop-Process -name explorer
    Start-Sleep -s 2

    # Disable Online Speech Recognition
    Write-host "    - Disabling Online Speech Recognition." -f Green
    If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
        New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
    Start-Sleep -s 2
    
    # Hiding personal information from lock screen
    Write-host "    - Hiding email and domain information from sign-in screen." -f Green
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
    Start-Sleep -s 2
       
    # Disable diagnostic data collection
    Write-host "    - Disabling diagnostic data collection" -f Green
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    }
    Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
    Start-Sleep -s 2
    
    # Disable App Launch Tracking
    Write-host "    - Disabling App Launch Tracking." -f Green
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "Start_TrackProgs" -Type DWord -Value 0
    Start-Sleep -s 2

    # Disable "tailored expirence"
    Write-host "    - Disable tailored expirience." -f Green        
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null
    }
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
    Start-Sleep -s 2

    # Disabling services
    Write-host "    - Disabling tracking services to startup with windows." -f Green
        $trackingservices = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "DiagTrack"                                # Diagnostics Tracking Service
            "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
            "lfsvc"                                    # Geolocation Service
            "TrkWks"                                   # Distributed Link Tracking Client
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
                            )

        foreach ($trackingservice in $trackingservices) {
            Get-Service -Name $trackingservice | Stop-Service | Set-Service -StartupType Disabled
        }   


    # Adding entries to hosts file
    Write-host "    - Blocking Microsoft tracking domains. " -f Green
        #Taking backup of current hosts file first
        $hostsfile = "C:\Windows\System32\drivers\etc\hosts"
        $Takebackup = "C:\Windows\System32\drivers\etc\hosts_backup"
        Copy-Item $hostsfile $Takebackup
    
    Write-Host "        - Getting an updated list of microsoft tracking domains..(This step may take a while).." -f Green
    $domain = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt  -UseBasicParsing
    $domain = $domain.Content | Foreach-object { $_ -replace "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "" } | Foreach-object { $_ -replace " ", "" }
    $domain = $domain.Split("`n"); 
    Write-Host "        - Taking backup of original hostsfile before adding entries." -f Green

    #Adding entries to hostsfile C:\Windows\System32\drivers\etc\hosts
    #spynet2.microsoft can't by added this way without Microsoft Defender kills the script. will be added later.
    Write-Host "        - Adding shady domains to your blocking list..." -f Green
    Add-Content -Encoding UTF8  $hostsfile ("`n" + "`n" + "# Blocking Microsoft tracking" + "`n")           
    $counter = 0
    foreach ($domain_entry in $domain) {
        if ($domain_entry -notlike "#*" -and $domain_entry -match "\w" -and $domain_entry -notmatch "spynet2.microsoft.com" ) {
            $counter++

            Write-Progress -Activity 'Adding entries to host file..' -CurrentOperation $domain_entry -PercentComplete (($counter / $domain.count) * 100)
            Add-Content -Encoding UTF8  $hostsfile ("`t" + "0.0.0.0" + "`t`t" + "$domain_entry") -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 200
        }
    }
    $ProgressPreference = "SilentlyContinue"
    #adding the missing piece manually in hostsfile
    Start-Process Notepad -Verb RunAs "C:\Windows\System32\drivers\etc\hosts"
    $app = New-Object -ComObject Shell.Application
    $key = New-Object -com Wscript.Shell
    $key.AppActivate("hosts - notepad")
    Start-Sleep -s 1
    $key.SendKeys("^{END}")
    $key.SendKeys("{TAB}")
    Start-Sleep -s 1
    $key.SendKeys("0.0.0.0")
    Start-Sleep -s 1
    $key.SendKeys("{TAB}")
    $key.SendKeys("{TAB}")
    Start-Sleep -s 1
    $key.SendKeys("spynet2.microsoft.com")
    Start-Sleep -s 1
    $key.SendKeys("^s")
    Stop-Process -Name Notepad

    # Blocking Microsoft Tracking IP's in the firewall
    Write-host "    - Blocking Microsoft tracking IP's." -f Green 
    Write-Host "        - Getting updated lists of Microsoft's trackin IP's" -f Green
    $blockip = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt  -UseBasicParsing
    $blockip = $blockip.Content | Foreach-object { $_ -replace "0.0.0.0 ", "" } | Out-String
    $blockip = $blockip.Split("`n");
    Write-Host "        - Configuring blocking rules in your firewall.." -f Green
    foreach ($ip_entry in $blockip) {   
        if ($ip_entry -notlike "#*" -and $ip_entry -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
            netsh advfirewall firewall add rule name="Block Microsoft Tracking IP: $ip_entry" dir=out action=block remoteip=$ip_entry enable=yes | Out-Null
        }
    }
    Start-Sleep -s 2

    # Send Microsoft a request to delete collected data about you.
    Write-host "    - Submitting a request to Microsoft to delete data about you." -f Green
    Start-Sleep -s 2
    $app = New-Object -ComObject Shell.Application
    $key = New-Object -com Wscript.Shell

    $app.open("ms-settings:privacy-feedback")
    $key.AppActivate("Settings")
    Start-Sleep -s 2
    $key.SendKeys("{TAB}")
    $key.SendKeys("{TAB}")
    $key.SendKeys("{TAB}")
    $key.SendKeys("{TAB}")
    $key.SendKeys("{TAB}")
    Start-Sleep -s 2
    $key.SendKeys("{ENTER}")
    Start-Sleep -s 3
    $key.SendKeys("%{F4}")
    
    #Add-Content -Encoding UTF8  $hostsfile "`t0.0.0.0`t`tspynet2.microsoft.com"

    
}
     
Function settings_customize {
    
    # Remove 
    Do {
        Write-Host "        - Would you like to remove Cortana? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing Cortana" -f Green
                Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
                If (!(Test-Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
                Stop-Process -name explorer
                Start-Sleep -s 2
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     
    
    
    # Remove login screensaver
    Do {
        Write-Host "        - Disable LockScreen ScreenSaver? To prevent missing first character(y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Screen saver is disabled." -f Green
                If (!(Test-Path HKLM:\Software\Policies\Microsoft\Windows\Personalization)) {
                    New-Item -Path HKLM:\Software\Policies\Microsoft\Windows -Name Personalization | Out-Null
                }
                Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")        

    # Taskbar: Hide Searchbox
    Do {
        Write-Host "        - Hide Searchbox in the taskbar? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Getting rid of the search box." -f Green
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0 -Type Dword -Force | Out-Null
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")
        
    # Taskbar: Hide task view button
    Do {
        Write-Host "        - Hide task view button? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. task view button will be hidden." -f Green
                If ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\")) {
                    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")

    # Show file extensions
    Do {
        Write-Host "        - Show known filetype extensions? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. file extensions will be shown" -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")            
            
    # Show hidden files
    Do {
        Write-Host "        - Show hidden files? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. file extensions will be shown" -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     

    # Enable Windows Dark Mode
    Do {
        Write-Host "        - Enable Dark Mode (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Enabling Dark Mode for Windows" -f Green
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0 -Type Dword -Force | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Value 0 -Type Dword -Force | Out-Null 
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")               
          
    # Change Explorer to "This PC"
    Do {
        Write-Host "        - Change Explorer to 'This PC'? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Explorer is changed." -f Green
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Type DWord -Value 1
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  
        
    # Start Menu: Disable Bing Search Results
    Do {
        Write-Host "        - Disable Bing Search Results in StartMenu? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Bing is removed." -f Green
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWord -Value 0
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Remove 3D objects
    Do {
        Write-Host "        - Remove '3D Objects' shortcuts? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing '3D Objects' shortcuts" -f Green
                $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
                If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
                If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}
            }
            N { Write-Host "            NO. 3D Objects will remain listed in your explorer" -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Hyper-V
    Do {
        Write-Host "        - Install Hyper-V? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. This may take a while.." -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                If ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
                    Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
                }
                Else { Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null }
                $ProgressPreference = "Continue" #unhide progressbar 
                Write-Host "            Installation complete. Restart PC to take effect." -f Green
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Linux Sub-system
    Do {
        Write-Host "        - Install Linux Sub-system? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Linux-subsystem is installing.." -f Green
                If ([System.Environment]::OSVersion.Version.Build -ge 14393) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
                }
                Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null 
                Write-Host "            Installation complete. Restart PC to take effect." -f Green 
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")         

    Do {
        Write-Host "        - Removing extra fax and printer? (XPS, Fax, PDF, OneNote)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing printers.." -f Green
                Get-Printer | Where-Object Name -match "xps|fax|pdf|onenote" | Remove-Printer -ErrorAction SilentlyContinue            
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")    


    # This module is complete, refreshing explorer.    
    Stop-Process -ProcessName explorer
                       
       
}


#Front end begins here
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__ \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 1.01
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "
 
#Check if admin
$admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin_permissions_check) {


    do {
        Write-host $intro -f Yellow 
        Write-host "Please select one of the following options:" -f yellow
        Write-host ""; Write-host "";
        Write-host "        [1] - All"
        Write-host "        [2] - Bloatware removal"
        Write-host "        [3] - Privacy optimizer"
        Write-host "        [4] - Customize Windows settings"
        Write-host "        [5] - Exit"
        Write-host ""; Write-host "";
        Write-Host "Option: " -f yellow -nonewline; ;
        $option = Read-Host
        Switch ($option) { 
            1 { remove_bloatware; settings_privacy; settings_customize }
            2 { remove_bloatware }
            3 { settings_privacy }
            4 { settings_customize }
            5 { exit }
            Default { cls; Write-host""; Write-host""; Write-host "INVALID OPTION. TRY AGAIN.." -f red; Write-host""; Write-host""; Sleep 1; cls; Write-host ""; Write-host "" } 
        }
         
    }while ($option -ne 5 )
     
    if ($option -le 5) { Write-host "         **Placeholder for exit menu**" -f Yellow }

} 
else {
    1..99 | % {
        $Warning_message = "POWERSHELL IS NOT RUNNING AS ADMINISTRATOR. Please close this and run this script as administrator."
        cls; ""; ""; ""; ""; ""; write-host $Warning_message -ForegroundColor White -BackgroundColor Red; ""; ""; ""; ""; ""; sleep 1; cls
        cls; ""; ""; ""; ""; ""; write-host $Warning_message -ForegroundColor White; ""; ""; ""; ""; ""; sleep 1; cls
    }    
}
