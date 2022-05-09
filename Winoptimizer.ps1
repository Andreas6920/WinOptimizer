#clean terminal before run
Clear-Host


#Functions
Function remove_bloatware {
    Write-host "  REMOVING MICROSOFT BLOAT" -f green
    #Cleaning Apps and Features
        Write-host "      CLEANING - Apps and Features" -f green
        start-sleep 5 
        $ProgressPreference = "SilentlyContinue" #hide progressbar

        Write-host "        - Removing bloated Microsoft apps, games, tools etc.." -f yellow
        start-sleep 3
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
            "*maps*"
            "*print3d*"
            "*Paint3D*"
            "*Mixed*"
            "*oneconnect*"
                                                
            ## Xbox Bloat ##
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxSpeechToTextOverlay"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxIdentityProvider"
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxApp"
            "Microsoft.Xbox.TCUI"
                                                
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
            if ($bloat_output -ne $null) { Write-host "        - Bloat app found! Removing: " -f yellow -nonewline; ; write-host "$bloat_output".Split(".")[1].Split("}")[0] -f yellow }
            Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
        }
        Write-host "        - CLEANED - Apps and Features" -f yellow; $ProgressPreference = "Continue" #unhide progressbar
        start-sleep 5    
        Write-host "      CLEANING - Task Scheduler" -f green
        $Bloatschedules = @(
                "XblGameSaveTaskLogon"
                "XblGameSaveTask"
                "Consolidator"
                "UsbCeip"
                "DmClient"
                "DmClientOnScenarioDownload"
                )
            foreach ($BloatSchedule in $BloatSchedules) {
            if ((Get-ScheduledTask | where state -ne Disabled | where TaskName -like $BloatSchedule)){
            Write-host "        - Bloat found in Task Scheduler! Disabling: $BloatSchedule" -f yellow
            Get-ScheduledTask | where Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null}}
            Write-host "        - CLEANED - Task Scheduler" -f yellow;
            
        
        
    #Unpin start menu
        Write-host "      CLEANING - Start Menu" -f Green

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
    

        $layoutFile = "$env:SystemRoot\StartMenuLayout.xml"
                
        start-sleep 5
        #Delete layout file if it already exists
        Write-Host "        - Removing current Start Menu..." -f Yellow
        If (Test-Path $layoutFile) {
            Remove-Item $layoutFile
        }

        #Creates the blank layout file
        Write-host "        - Creates and applying a new blank start menu..." -f Yellow
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
        Write-host "        - Restarting explorer..." -f yellow
        Stop-Process -name explorer -Force
        Start-Sleep -s 5

        #Enable the ability to pin items again by disabling "LockedStartLayout"
        foreach ($regAlias in $regAliases) {
            $basePath = $regAlias + ":\Software\Policies\Microsoft\Windows"
            $keyPath = $basePath + "\Explorer" 
            Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
        }
        Stop-Process -name explorer
        write-host "        - Save changes to all users.." -f yellow
        Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
        Remove-Item $layoutFile
        write-host "        - CLEANED - Start Menu" -f yellow
        
    #Clean Taskbar
        Write-host "      CLEANING - Taskbar" -f Green
        start-sleep -s 5
        write-host "        - Changing keys.." -f yellow
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesChanges -Value 3 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesRemovedChanges -Value 32 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesVersion -Value 3 -Type Dword -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Type DWord -Value 0 | Out-Null
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value 0 -Type Dword | Out-Null
        set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0 | Out-Null

        write-host "        - Removing shortcuts.." -f yellow
        Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse -Force | Out-Null
        Stop-Process -name explorer
        start-sleep -s 5
        #Start-Process explorer
        write-host "        - CLEANED - Taskbar" -f yellow

    # Remove Windows pre-installed bloat printers (Fax, PDF, OneNote) These are almost never used.
            If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
            Get-Printer | ? Name -cMatch "OneNote for Windows 10|Microsoft XPS Document Writer|Microsoft Print to PDF|Fax" | Remove-Printer 
            
    #END
        write-host "      COMPLETE - BLOAT REMOVAL" -f Green
        start-sleep 10
                
}
Function settings_privacy {
      
    Write-host "`tENHANCE WINDOWS PRIVACY" -f green
    #Cleaning Apps and Features
    Write-host "`t`tBLOCKING - Microsoft Data Collection" -f green
          

    
    # Disable Advertising ID
        Write-host "`t`t`t- Disabling advertising ID." -f yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
        Start-Sleep -s 2
      
    # Disable let websites provide locally relevant content by accessing language list
        Write-host "`t`t`t- Disabling location tracking." -f yellow
        If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
            New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
        }
        Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
        Start-Sleep -s 2
      
    # Disable Show me suggested content in the Settings app
        Write-host "`t`t`t- Disabling personalized content suggestions." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        Start-Sleep -s 2
      
    # Remove Cortana
        Write-host "`t`t`t- Disabling Cortana." -f yellow
        $ProgressPreference = "SilentlyContinue"
        Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
        $ProgressPreference = "Continue"
        Stop-Process -name explorer
        Start-Sleep -s 5

    # Disable Online Speech Recognition
        Write-host "`t`t`t- Disabling Online Speech Recognition." -f yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
        Start-Sleep -s 2
    
    # Hiding personal information from lock screen
        Write-host "`t`t`t- Disabling sign-in screen notifications." -f yellow
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
        Start-Sleep -s 2
       
    # Disable diagnostic data collection
        Write-host "`t`t`t- Disabling diagnostic data collection" -f Yellow
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        }
        Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
        Start-Sleep -s 2
    
    # Disable App Launch Tracking
        Write-host "`t`t`t- Disabling App Launch Tracking." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "Start_TrackProgs" -Type DWord -Value 0
        Start-Sleep -s 2

    # Disable "tailored expirence"
        Write-host "`t`t`t- Disable tailored expirience." -f Yellow        
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null
        }
        Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
        Start-Sleep -s 2

    # Disabling services
        Write-host "`t`tBLOCKING - Tracking startup services" -f green
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
         if((Get-Service -Name $trackingservice | Where-Object Starttype -ne Disabled)){
         write-host "`t`t`t- Blocking tracking service: $trackingservice" -f yellow
         Get-Service | Where-Object name -eq $trackingservice | Set-Service -StartupType Disabled}}
         write-host "`t`t`t- Service scan complete" -f yellow

    #Disabling Scheduled tasks that logs your activity
        Write-host "`t`tBLOCKING - scheduled taks" -f green
        write-host "`t`t`t- Disabling all the jobs in the background" -f yellow
        Start-Job -Name "Disabling scheduled tasks" -ScriptBlock {
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppID\" -TaskName "SmartScreenSpecific" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "AitAgent" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "Microsoft Compatibility Appraiser" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "ProgramDataUpdater" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "StartupAppTask" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\" -Taskname "Proxy" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\CloudExperienceHost\" -TaskName "CreateObjectTask" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "BthSQM" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Consolidator" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "KernelCeipTask" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Uploader" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "UsbCeip" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\DiskDiagnostic\" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\DiskFootprint\" -TaskName "Diagnostics" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\FileHistory\" -Taskname "File History (maintenance mode)" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Maintenance\" -TaskName "WinSAT" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Sqm-Tasks" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Power Efficiency Diagnostics\" -TaskName "AnalyzeSystem" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyMonitor" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyRefresh" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyUpload" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\" -TaskName "QueueReporting" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -TaskName "Automatic App Update" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\License Manager\" -TaskName "TempSignedLicenseExchange" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Clip\" -TaskName "License Validation" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\ApplicationData\" -TaskName "DsSvcCleanup" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Power Efficiency Diagnostics\" -TaskName "AnalyzeSystem" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PushToInstall\" -TaskName "LoginCheck" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PushToInstall\" -TaskName "Registration" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyMonitor" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyMonitorToastTask" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Shell\" -TaskName "FamilySafetyRefreshTask" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Subscription\" -TaskName "EnableLicenseAcquisition" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Subscription\" -TaskName "LicenseAcquisition" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Diagnosis\" -TaskName "RecommendedTroubleshootingScanner" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Diagnosis\" -TaskName "Scheduled" | Out-Null
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\NetTrace\" -TaskName "GatherNetworkInfo" | Out-Null
        } | Out-Null | Wait-Job

    # Adding entries to hosts file
        Write-host "`t`tBLOCKING - Tracking domains (This may take a while).." -f green
        start-sleep -s 3
         Write-Host "`t`t`t- Backing up your hostsfile.." -f Yellow
        #Taking backup of current hosts file first
        $hostsfile = "$env:SystemRoot\System32\drivers\etc\hosts"
        $Takebackup = "$env:SystemRoot\System32\drivers\etc\hosts_backup"
        Copy-Item $hostsfile $Takebackup
        
        Write-Host "`t`t`t- Getting an updated list of microsoft tracking domains" -f Yellow
        $domain = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt'  -UseBasicParsing
        $domain = $domain.Content | Foreach-object { $_ -replace "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "" } | Foreach-object { $_ -replace " ", "" }
        $domain = $domain.Split("`n") -notlike "#*" -notmatch "spynet2.microsoft.com" -match "\w"
        
        Write-Host "`t`t`t- Blocking domains from tracking-list" -f Yellow
        foreach ($domain_entry in $domain) {
        $counter++
                Write-Progress -Activity 'Adding entries to host file..' -CurrentOperation $domain_entry -PercentComplete (($counter /$domain.count) * 100)
                Add-Content -Encoding UTF8  $hostsfile ("`t" + "0.0.0.0" + "`t`t" + "$domain_entry") -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 200
        }
        Write-Progress -Completed -Activity "make progress bar dissapear"
        #flush DNS cache
        Write-host "`t`t`t- Flushing local DNS cache" -f Yellow
        ipconfig /flushdns | Out-Null; start-Sleep 2; nbtstat -R | Out-Null; start-Sleep -s 2;
        Stop-Process -name explorer; Start-Sleep -s 5

    # Blocking Microsoft Tracking IP's in the firewall
        Write-host "`t`tBLOCKING - Tracking IP's" -f green
        Write-Host "`t`t`t- Getting updated lists of Microsoft's trackin IP's" -f Yellow
        $blockip = Invoke-WebRequest -Uri https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt  -UseBasicParsing
        $blockip = $blockip.Content | Foreach-object { $_ -replace "0.0.0.0 ", "" } | Out-String
        $blockip = $blockip.Split("`n") -notlike "#*" -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        Clear-Variable -Name counter
        Write-Host "`t`t`t- Configuring blocking rules in your firewall.." -f Yellow
        foreach ($ip_entry in $blockip) {
        $counter++
        Write-Progress -Activity 'Configuring firewall rules..' -CurrentOperation $ip_entry -PercentComplete (($counter /$blockip.count) * 100)
        netsh advfirewall firewall add rule name="Block Microsoft Tracking IP: $ip_entry" dir=out action=block remoteip=$ip_entry enable=yes | Out-Null}
        Write-Progress -Completed -Activity "make progress bar dissapear"
        Write-Host "`t`t`t- Firewall configuration complete." -f Yellow
        start-sleep 5

    # Send Microsoft a request to delete collected data about you.
        
        #lock keyboard and mouse to avoid disruption while navigating in GUI.
        function block_input{
            $code = @"
        [DllImport("user32.dll")]
        public static extern bool BlockInput(bool fBlockIt);
"@
            $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
            $userInput::BlockInput($true)
            }
    
        function allow_input{
            $code = @"
        [DllImport("user32.dll")]
        public static extern bool BlockInput(bool fBlockIt);
"@
            $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
            $userInput::BlockInput($false)
            }
    
        
        block_input | Out-Null
        Write-host "`t`tSUBMIT - request to Microsoft to delete data about you." -f green
        Start-Sleep -s 2
        #start navigating
        $app = New-Object -ComObject Shell.Application
        $key = New-Object -com Wscript.Shell

        $app.open("ms-settings:privacy-feedback")
        $key.AppActivate("Settings") | out-null
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
        Start-Sleep -s 2
        
        #unlocking keyboard and mouse
        allow_input | Out-Null
        
        # Windows hardening
        Write-host "`t`tBLOCKING - Security holes" -f green
        
        # Disable automatic setup of network connected devices.
            Write-host "`t`t`t- Disabling auto setup network devices." -f yellow
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
            }
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 -Force 
            Start-Sleep -s 2
            
        # Disable sharing of PC and printers
            Write-host "`t`t`t- Disabling sharing of PC and Printers." -f yellow
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

        # Disable LLMNR    
            #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-host "`t`t`t- Disabling LLMNR." -f yellow
            New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force -ea SilentlyContinue | Out-Null
            
        # Disabe SMB Compression - CVE-2020-0796    
            #https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Write-host "`t`t`t- Disabling SMB Compression." -f yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force -ea SilentlyContinue | Out-Null

        # Disable SMB v1    
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-host "`t`t`t- Disabling SMB version 1 support." -f yellow
            Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue  | Out-Null
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force

        # Disable SMB v2    
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-host "`t`t`t- Disabling SMB version 2 support." -f yellow
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 –Force

        # Enable SMB Encryption    
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Write-host "`t`t- Activating SMB Encryption." -f yellow
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null

        # Bad Neighbor - CVE-2020-16898    
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            Write-host "`t`t- Patching Bad Neighbor (CVE-2020-16898)." -f yellow
            netsh int ipv6 set int *INTERFACENUMBER* rabaseddnsconfig=disable | Out-Null
            
        # Spectre Meldown - CVE-2017-5754    
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Write-host "`t`t- Patching Bad Metldown (CVE-2017-5754)." -f yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force -ea SilentlyContinue | Out-Null
                        
            
        write-host "      COMPLETE - PRIVACY OPTIMIZATION" -f yellow
        start-sleep 10
    
}
     
Function settings_customize {
    
    # Remove 
    Do {
        Write-Host "        - Would you like to remove Cortana? (y/n)" -f yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing Cortana" -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
                If (!(Test-Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
                $ProgressPreference = "Continue" #unhide progressbar 
                Stop-Process -name explorer
                Start-Sleep -s 2
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     
    
    
    # Remove login screensaver
    Do {
        Write-Host "        - Disable LockScreen ScreenSaver? To prevent missing first character(y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Hide Searchbox in the taskbar? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Hide task view button? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Show known filetype extensions? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Show hidden files? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Enable Dark Mode (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Change Explorer to 'This PC'? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Disable Bing Search Results in StartMenu? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Remove '3D Objects' shortcuts? (y/n)" -f yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing '3D Objects' shortcuts" -f Green
                $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
                If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
                If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}
            }
            N { Write-Host "            NO. 3D Objects will remain listed in your explorer" -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Hyper-V
    Do {
        Write-Host "        - Install Hyper-V? (y/n)" -f yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. This may take a while.." -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                if (((Get-WmiObject -class Win32_OperatingSystem).Caption) -match "Home"){$dst = "$env:TMP\install-hyper-v"
                    write-host "                Windows Home detected, additional script is needed!" -f green
                    $file = "install.bat"
                    md "$env:TMP\install-hyper-v" -Force | out-null
                    New-Item "$dst\$file" -Force | out-null
                    $domain = Invoke-WebRequest -Uri 'https://gist.githubusercontent.com/samuel-fonseca/662a620ae32aca254ea7730be5ff7145/raw/a1de2537d5b0613e29c9ca3b9bc0ec67ff1e29a2/Hyper-V-Enabler.bat'  -UseBasicParsing
                    $domain = $domain.content; Start-sleep 1
                    write-host "                Downloading script..." -f green
                    Set-content "$dst\$file" $domain; sleep 1
                    write-host "                Opening CMD..." -f green
                    start cmd -Verb RunAs -ArgumentList "/c","$dst/$file" -wait}
                elseIf ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
                    Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null}
                Else { Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null }
                $ProgressPreference = "Continue" #unhide progressbar 
                Write-Host "            Installation complete. Restart PC to take effect." -f Green
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Linux Sub-system
    Do {
        Write-Host "        - Install Linux Sub-system? (y/n)" -f yellow -nonewline; ;
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
        Write-Host "        - Removing extra fax and printer? (XPS, Fax, PDF, OneNote)" -f yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "            YES. Removing printers.." -f Green
                If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
                Get-Printer | ? Name -cMatch "OneNote for Windows 10|Microsoft XPS Document Writer|Microsoft Print to PDF|Fax" | Remove-Printer
            }
            N { Write-Host "            NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")    


    # This module is complete, refreshing explorer.    
    Stop-Process -ProcessName explorer
                       
       
}

Function app_installer {
    <#
    .SYNOPSIS
    Appinstaller with user interface

    .DESCRIPTION
    This will install silently an trusted appinstaller called Chocolatey, for info check https://chocolatey.org
    This will install requested app from a userinterface
    This will automaticly update the installed apps to gaining maximum security.

    .EXAMPLE
    firefox, notepad++, vscode, vlc

    .NOTES
    General notes
    #> 
    
    # STEP 1 - app-installer
        #check if chocolatey is installed
        Write-host "  Checking the system if the appinstaller is installed." -f green
        if (!(Test-Path "$($env:ProgramData)\chocolatey\choco.exe")) { 
                # installing chocolatey
                Write-host "      application not found. Installing:" -f green
                Write-host "        - Preparing system.." -f yellow
                Set-ExecutionPolicy Bypass -Scope Process -Force;
                # Downloading installtion file from original source
                Write-host "        - Downloading script.." -f yellow
                (New-Object System.Net.WebClient).DownloadFile("https://chocolatey.org/install.ps1","$env:TMP/choco-install.ps1")
                # Adding a few lines to make installtion more silent.
                Write-host "        - Preparing script.." -f yellow
                $add_line1 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace '\| write-Output', ' | out-null' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1; "
                $add_line2 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace 'write-', '#write-' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1; "
                $add_line3 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace 'function.* #write-', 'function Write-' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1;"
                ((Get-Content -path $env:TMP/choco-install.ps1 -Raw) -replace 'write-host', "#write-host" ) | Set-Content -Path $env:TMP/choco-install.ps1
                ((Get-Content -path $env:TMP/choco-install.ps1 -Raw) -replace '#endregion Download & Extract Chocolatey', "$add_line1`n$add_line2`n$add_line3" ) | Set-Content -Path $env:TMP/choco-install.ps1
                # Executing installation file.
                cd $env:TMP
                Write-host "        - Installing.." -f yellow
                .\choco-install.ps1
                Write-host "        - Installation complete.." -f yellow
        }
        else { write-host "appinstaller already installed on this system. skipping installation." }
        
    
    #STEP 2 - app-installation
        
$appheader = 
"
                   _           _        _ _                 
  __ _ _ __  _ __ (_)_ __  ___| |_ __ _| | | ___ _ __ 
 / _`  | '_ \| '_ \| | '_ \/ __| __/ _`  | | |/ _ \ '__|
| (_| | |_) | |_) | | | | \__ \ |  (_| | | |  __/ |   
 \__,_| .__/| .__/|_|_| |_|___/\__\__,_|_|_|\___|_|   
      |_|   |_|                                               
" 
        
            Write-host $appheader -f Yellow 
            write-host "    BROWSER:" -f yellow
            write-host "        Chrome        Firefox      Opera" -f green
            write-host "        Brave         Opera        Vevaldi" -f green
            "";
            write-host "    TOOLS:" -f yellow
            write-host "        Dropbox       Google Drive    Teamviewer" -f green
            write-host "        7-zip         Winrar          Greenshot" -f green
            write-host "        ShareX        Gimp            Visual studio++" -f green
            "";
            write-host "    MEDIA PLAYER:" -f yellow
            write-host "        Spotify       VLC           Itunes" -f green
            write-host "        Winamp        Foobar2000    K-Lite" -f green
            write-host "        MPC-HC        Popcorntime         " -f green
            "";
            write-host "    Development:" -f yellow
            write-host "        Notepad++       vscode           atom" -f green
            write-host "        Vim             Eclipse          PyCharm" -f green
            write-host "        PuTTY           Superputty       TeraTerm" -f green
            write-host "        Filezilla       WinSCP           mRemoteNG" -f green
            write-host "        Wireshark       git              Github Desktop" -f green
            "";
            write-host "    Social:" -f yellow
            write-host "        Webex           Zoom           Microsoft Teams" -f green
            write-host "        Discord         Twitch         Ubisoft-Connect" -f green
            write-host "        Steam" -f green
            "";
            Write-host "    ** List multiple programs seperated by , (comma) - spaces are allowed." -f yellow;
            "";
            Write-host "Type the programs you would like to be installed on this system" -nonewline; 
            

            $requested_apps = (Read-Host " ").Split(",") | Foreach-object { $_ -replace ' ',''}
            foreach ($requested_app in $requested_apps) {
                if("cancel" -eq "$requested_app"){Write-Output "Skipping this section.."}
                # Browsers
                elseif("Firefox" -match "$requested_app"){Write-host "        - installing firefox.." -f yellow -nonewline; choco install firefox -y | out-null;write-host "          [ COMPLETE ]" -f green;} 
                elseif("Chrome" -match "$requested_app"){Write-host "        - installing Chrome.." -f yellow -nonewline; choco install googlechrome -y | out-null;write-host "           [ COMPLETE ]" -f green;} 
                elseif("Brave" -match "$requested_app"){Write-host "        - installing Brave.." -f yellow -nonewline; choco install Brave -y | out-null;write-host "            [ COMPLETE ]" -f green;} 
                elseif("Opera" -match "$requested_app"){Write-host "        - installing Opera.." -f yellow -nonewline; choco install opera -y | out-null;write-host "            [ COMPLETE ]" -f green;} 
                elseif("Vivaldi" -match "$requested_app"){Write-host "        - installing Vivaldi.." -f yellow -nonewline; choco install Vivaldi -y | out-null;write-host "          [ COMPLETE ]" -f green;} 
                # Tools
                elseif("Dropbox" -match "$requested_app"){Write-host "        - installing Dropbox.." -f yellow -nonewline; choco install dropbox -y | out-null;write-host "          [ COMPLETE ]" -f green;} 
                elseif("Google Drive" -match "$requested_app"){Write-host "        - installing Google Drive.." -f yellow -nonewline; choco install googledrive -y | out-null;write-host "     [ COMPLETE ]" -f green;} 
                elseif("TeamViewer" -match "$requested_app"){Write-host "        - installing TeamViewer.." -f yellow -nonewline; choco install TeamViewer -y | out-null;write-host "       [ COMPLETE ]" -f green;} 
                elseif("7-zip" -match "$requested_app"){Write-host "        - installing 7-Zip.." -f yellow -nonewline; choco install 7Zip -y | out-null;write-host "            [ COMPLETE ]" -f green;} 
                elseif("winrar" -match "$requested_app"){Write-host "        - installing Winrar.." -f yellow -nonewline; choco install winrar -y | out-null;write-host "           [ COMPLETE ]" -f green;} 
                elseif("Greenshot" -match "$requested_app"){Write-host "        - installing Greenshot.." -f yellow -nonewline; choco install Greenshot -y | out-null;write-host "        [ COMPLETE ]" -f green;} 
                elseif("ShareX" -match "$requested_app"){Write-host "        - installing Sharex.." -f yellow -nonewline; choco install Sharex -y | out-null;write-host "           [ COMPLETE ]" -f green;} 
                elseif("Gimp" -match "$requested_app"){Write-host "        - installing Gimp.." -f yellow -nonewline; choco install Gimp -y | out-null;write-host "             [ COMPLETE ]" -f green;} 
                elseif("Visual studio++" -match "$requested_app"){Write-host "        - installing Visual studio++.." -f yellow -nonewline; choco install vcredist140 -y | out-null;write-host "  [ COMPLETE ]" -f green;} 
                # Media Player
                elseif("spotify" -match "$requested_app"){Write-host "        - installing spotify.." -f yellow -nonewline; choco install spotify -y | out-null;write-host "          [ COMPLETE ]" -f green;}  
                elseif("VLC" -match "$requested_app"){Write-host "        - installing VLC.." -f yellow -nonewline; choco install VLC -y | out-null;write-host "              [ COMPLETE ]" -f green;}  
                elseif("itunes" -match "$requested_app"){Write-host "        - installing itunes.." -f yellow -nonewline; choco install itunes -y | out-null;write-host "           [ COMPLETE ]" -f green;}  
                elseif("Winamp" -match "$requested_app"){Write-host "        - installing Winamp.." -f yellow -nonewline; choco install Winamp -y | out-null;write-host "           [ COMPLETE ]" -f green;}  
                elseif("foobar2000" -match "$requested_app"){Write-host "        - installing foobar2000.." -f yellow -nonewline; choco install foobar2000 -y | out-null;write-host "       [ COMPLETE ]" -f green;}  
                elseif("K-lite" -match "$requested_app"){Write-host "        - installing K-Lite.." -f yellow -nonewline; choco install k-litecodecpackfull -y | out-null;write-host "           [ COMPLETE ]" -f green;}  
                elseif("MPC-HC" -match "$requested_app"){Write-host "        - installing MPC-HC.." -f yellow -nonewline; choco install MPC-HC -y | out-null;write-host "           [ COMPLETE ]" -f green;}  
                elseif("popcorn" -match "$requested_app"){Write-host "        - installing Popcorntime.." -f yellow -nonewline; choco install popcorntime -y | out-null;write-host "      [ COMPLETE ]" -f green;}  
                # Development
                elseif("notepad++" -match "$requested_app"){Write-host "        - installing Notepad++.." -f yellow -nonewline; choco install notepadplusplus -y | out-null;write-host "        [ COMPLETE ]" -f green;}  
                elseif("vscode" -match "$requested_app"){Write-host "        - installing vscode.." -f yellow -nonewline; choco install vscode -y | out-null;write-host "           [ COMPLETE ]" -f green;}  
                elseif("atom" -match "$requested_app"){Write-host "        - installing atom.." -f yellow -nonewline; choco install atom -y | out-null;write-host "             [ COMPLETE ]" -f green;}  
                elseif("vim" -match "$requested_app"){Write-host "        - installing vim.." -f yellow -nonewline; choco install vim -y | out-null;write-host "              [ COMPLETE ]" -f green;} 
                elseif("Eclipse" -match "$requested_app"){Write-host "        - installing Eclipse.." -f yellow -nonewline; choco install Eclipse -y | out-null;write-host "          [ COMPLETE ]" -f green;} 
                elseif("PyCharm" -match "$requested_app"){Write-host "        - installing PyCharm.." -f yellow -nonewline; choco install PyCharm -y | out-null;write-host "          [ COMPLETE ]" -f green;} 
                elseif("putty" -match "$requested_app"){Write-host "        - installing putty.." -f yellow -nonewline; choco install PyCharm -y | out-null;write-host "            [ COMPLETE ]" -f green;} 
                elseif("superputty" -match "$requested_app"){Write-host "        - installing superputty.." -f yellow -nonewline; choco install superputty -y | out-null;write-host "       [ COMPLETE ]" -f green;} 
                elseif("teraterm" -match "$requested_app"){Write-host "        - installing teraterm.." -f yellow -nonewline; choco install teraterm -y | out-null;write-host "         [ COMPLETE ]" -f green;} 
                elseif("Filezilla" -match "$requested_app"){Write-host "        - installing Filezilla.." -f yellow -nonewline; choco install Filezilla -y | out-null;write-host "        [ COMPLETE ]" -f green;} 
                elseif("WinSCP" -match "$requested_app"){Write-host "        - installing WinSCP.." -f yellow -nonewline; choco install WinSCP -y | out-null;write-host "           [ COMPLETE ]" -f green;} 
                elseif("mremoteng" -match "$requested_app"){Write-host "        - installing MRemoteNG.." -f yellow -nonewline; choco install mremoteng -y | out-null;write-host "        [ COMPLETE ]" -f green;} 
                elseif("wireshark" -match "$requested_app"){Write-host "        - installing Wireshark.." -f yellow -nonewline; choco install wireshark -y | out-null;write-host "        [ COMPLETE ]" -f green;} 
                elseif("git" -match "$requested_app"){Write-host "        - installing git.." -f yellow -nonewline; choco install git.install -y | out-null;write-host "              [ COMPLETE ]" -f green;}
                elseif("GithubDesktop" -match "$requested_app"){Write-host "        - installing Github Desktop.." -f yellow -nonewline; choco install github-desktop -y | out-null;write-host "   [ COMPLETE ]" -f green;}
                # Social
                elseif("Microsoft Teams" -match "$requested_app"){Write-host "        - installing Microsoft Teams.." -f yellow -nonewline; choco install microsoft-teams -y | out-null;write-host "  [ COMPLETE ]" -f green;} 
                elseif("Zoom" -match "$requested_app"){Write-host "        - installing Zoom.." -f yellow -nonewline; choco install Zoom -y | out-null;write-host "             [ COMPLETE ]" -f green;} 
                elseif("Webex" -match "$requested_app"){Write-host "        - installing Webex.." -f yellow -nonewline; choco install webex-teams -y | out-null;choco install webex-meetings -y | out-null;  write-host "            [ COMPLETE ]" -f green;}
                elseif("Discord" -match "$requested_app"){Write-host "        - installing Discord.." -f yellow -nonewline; choco install Discord -y | out-null;Write-host "          [ COMPLETE ]" -f green;}
                elseif("Twitch" -match "$requested_app"){Write-host "        - installing Twitch.." -f yellow -nonewline; choco install Twitch -y | out-null;Write-host "           [ COMPLETE ]" -f green;}
                elseif("Steam" -match "$requested_app"){Write-host "        - installing Steam.." -f yellow -nonewline; choco install Steam -y | out-null;  write-host "            [ COMPLETE ]" -f green;}
                elseif("Ubisoft Connect" -match "$requested_app"){Write-host "        - installing Ubisoft Connect.." -f yellow -nonewline; choco install ubisoft-connect -y | out-null;write-host "  [ COMPLETE ]" -f green;}
            }
    # STEP 3 - app-updater
                Do {
                    Write-Host "        - Would you like to install auto-updater? (y/n)" -f yellow -nonewline; ;
                    $answer = Read-Host " " 
                    Switch ($answer) { 
                        Y {   
                                if ((Get-Childitem -Path $env:ProgramData).Name  -match "Chocolatey"){
                                #create update file
                                write-host "        - Downloading updating script." -f green
                                $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                                Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile $filepath -UseBasicParsing

                                
                                # Create scheduled job
                                write-host "        - scheduling update routine." -f green
                                $name = 'winoptimizer-app-Updater'
                                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nop -W hidden -noni -ep bypass -file $filepath"
                                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                                $trigger= New-ScheduledTaskTrigger -At 12:00 -Daily
                                $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -RunOnlyIfIdle -DontStopOnIdleEnd -IdleDuration 00:05:00 -IdleWaitTimeout 03:00:00

                                Register-ScheduledTask -TaskName $Name -Taskpath "\Microsoft\Windows\Winoptimizer\" -Settings $settings -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null
                                } else{Write-host "Chocolatey is not installed on this system." -f red}                                                    
                        }
                        N { Write-Host "        - NO. Skipping this step." -f Red }}
                    } While ($answer -notin "y", "n")



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
Version 2.1
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "
 
#Check if admin
$admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin_permissions_check) {


    do {
        Write-host $intro -f Yellow 
        Write-host "Please select one of the following options:" -f yellow
        Write-host ""; Write-host "";
        Write-host "        [1] - All"
        Write-host "        [2] - Bloatware removal"
        Write-host "        [3] - Privacy optimizer"
        Write-host "        [4] - Customize Windows settings"
        Write-host "        [5] - App installer"
        "";
        Write-host "        [0] - Exit"
        Write-host ""; Write-host "";
        Write-Host "Option: " -f yellow -nonewline; ; ;
        $option = Read-Host
        Switch ($option) { 
            0 { exit }
            1 { remove_bloatware; settings_privacy; settings_customize; app_installer; }
            2 { remove_bloatware }
            3 { settings_privacy }
            4 { settings_customize }
            5 { app_installer }
            Default { cls; Write-host""; Write-host""; Write-host "INVALID OPTION. TRY AGAIN.." -f red; Write-host""; Write-host""; Start-Sleep 1; cls; Write-host ""; Write-host "" } 
        }
         
    }while ($option -ne 5 )
     
    if ($option -le 5) { Write-host "         **Placeholder for exit menu**" -f Yellow }

} 
else {
    1..99 | % {
        $Warning_message = "POWERSHELL IS NOT RUNNING AS ADMINISTRATOR. Please close this and run this script as administrator."
        cls; ""; ""; ""; ""; ""; write-host $Warning_message -ForegroundColor White -BackgroundColor Red; ""; ""; ""; ""; ""; Start-Sleep 1; cls
        cls; ""; ""; ""; ""; ""; write-host $Warning_message -ForegroundColor White; ""; ""; ""; ""; ""; Start-Sleep 1; cls
    }    
}
#test: æøå