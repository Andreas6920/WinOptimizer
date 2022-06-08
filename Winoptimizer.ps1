#clean terminal before run
Clear-Host


#Functions
Function remove_bloatware {
    Write-host "REMOVING MICROSOFT BLOAT" -f Green;"";
    Start-Sleep -s 3
    
    # Clean Apps and features
        Write-host "`tCleaning Bloatware:" -f Green
        Start-Sleep -s 5
        $Bloatware = @(		
            ## Microsoft Bloat ##
            "*autodesksketch*"
            "*oneconnect*"
            "*plex*"
            "*print3d*"
            "Microsoft.3DBuilder"
            "Microsoft.Getstarted"
            "Microsoft.Microsoft3DViewer"
            "Microsoft.MicrosoftOfficeHub"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.MicrosoftStickyNotes"
            "Microsoft.MixedReality.Portal"
            "Microsoft.Music.Preview"
            "Microsoft.Office.OneNote"
            "Microsoft.People"
            "Microsoft.WindowsFeedbackHub"
            "Microsoft.WindowsMaps"
            "Microsoft.WindowsMaps"
            "Microsoft.ZuneMusic"
            "Microsoft.windowscommunicationsapps"
                                                
            ## Xbox Bloat ##
            "Microsoft.Xbox.TCUI"
            "Microsoft.XboxApp"
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxGameCallableUI"
            "Microsoft.XboxGameOverlay"
            "Microsoft.XboxGamingOverlay"
            "Microsoft.XboxIdentityProvider"
            "Microsoft.XboxSpeechToTextOverlay"
                                                
            ## Bing Bloat ##
            "*Bing*"
            "Microsoft.Bing*"
            "Microsoft.BingFinance"
            "Microsoft.BingFoodAndDrink"
            "Microsoft.BingHealthAndFitness"
            "Microsoft.BingNews"
            "Microsoft.BingSports"
            "Microsoft.BingTravel"
            "Microsoft.BingWeather"

            ## Games ##
            "*Bubblewitch*"
            "*Candycrush*"
            "*Disney*"
            "*Empires*"
            "*Minecraft*"
            "*Royal revolt*"
                                
            ## Other crap ##
            "*ActiproSoftwareLLC*"
            "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
            "*Duolingo-LearnLanguagesforFree*"
            "*EclipseManager*"
            "*Facebook*"
            "*Flipboard*"
            "*PandoraMediaInc*"
            "*Skype*"
            "*Spotify*"
            "*Twitter*"
            "*Wunderlist*")

            $ProgressPreference = "SilentlyContinue" # hide progressbar
            foreach ($Bloat in $Bloatware) {
                $bloat_name = (Get-AppxPackage | Where-Object Name -Like $Bloat).Name
                if (Get-AppxPackage | Where-Object Name -Like $Bloat){Write-host "`t`t- Removing: " -f Yellow -nonewline; ; write-host "$bloat_name".Split(".")[1].Split("}")[0] -f Yellow; Get-AppxPackage | Where-Object Name -Like $Bloat | Remove-AppxPackage | Out-Null}
                if (Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat){Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null}}
            $ProgressPreference = "Continue" #unhide progressbar
            write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;



    # Disabling services
        Write-host "`tCleaning Startup services:" -f Green
        Start-Sleep -s 5
        $services = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "DiagTrack"                                # Diagnostics Tracking Service
            "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
            "lfsvc"                                    # Geolocation Service
            "MapsBroker"                               # Downloaded Maps Manager
            "ndu"                                      # Windows Network Data Usage Monitor
            "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
            "RemoteAccess"                             # Routing and Remote Access
            "RemoteRegistry"                           # Remote Registry
            "SharedAccess"                             # Internet Connection Sharing (ICS)
            "TrkWks"                                   # Distributed Link Tracking Client
            "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
            "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
            )

         foreach ($service in $services) {
         if((Get-Service -Name $service | Where-Object Starttype -ne Disabled)){
         write-host "`t`t- Disabling: $service" -f Yellow
         Get-Service | Where-Object name -eq $service | Set-Service -StartupType Disabled}}
         write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;



    # Clean Task Scheduler
        Write-host "`tCleaning Scheduled tasks:" -f Green
        Start-Sleep -s 5
        $Bloatschedules = @(
            "AitAgent" 
            "AnalyzeSystem" 
            "Automatic App Update" 
            "BthSQM" 
            "Consolidator"
            "Consolidator" 
            "CreateObjectTask" 
            "Diagnostics" 
            "DmClient"
            "DmClientOnScenarioDownload"
            "DsSvcCleanup" 
            "EnableLicenseAcquisition" 
            "FamilySafetyMonitor" 
            "FamilySafetyMonitorToastTask" 
            "FamilySafetyRefresh" 
            "FamilySafetyRefreshTask" 
            "FamilySafetyUpload" 
            "File History (maintenance mode)" 
            "GatherNetworkInfo" 
            "KernelCeipTask" 
            "License Validation" 
            "LicenseAcquisition" 
            "LoginCheck" 
            "Microsoft Compatibility Appraiser" 
            "Microsoft-Windows-DiskDiagnosticDataCollector" 
            "ProgramDataUpdater" 
            "Proxy" 
            "QueueReporting" 
            "RecommendedTroubleshootingScanner" 
            "Registration" 
            "Scheduled" 
            "SmartScreenSpecific" 
            "Sqm-Tasks" 
            "StartupAppTask" 
            "TempSignedLicenseExchange" 
            "Uploader" 
            "UsbCeip"
            "UsbCeip" 
            "WinSAT" 
            "XblGameSaveTask")

            foreach ($BloatSchedule in $BloatSchedules) {
            if ((Get-ScheduledTask | Where-Object state -ne Disabled | Where-Object TaskName -like $BloatSchedule)){
            Write-host "`t`t- Disabling: $BloatSchedule" -f Yellow
            Get-ScheduledTask | Where-Object Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null}}
            write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;
        

            
    # Clean start menu
        Write-host "`tCleaning Start Menu:" -f Green
        Start-Sleep -s 5
    
            # Prepare
            $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/StartMenuLayout.xml"
            $layoutFile = "$($env:SystemRoot)\StartMenuLayout.xml"
            $keys = "HKLM:\Software\Policies\Microsoft\Windows\Explorer","HKCU:\Software\Policies\Microsoft\Windows\Explorer"; 
                
            # Download blank Start Menu file
            Write-Host "`t`t- Downloading Start Menu file..." -f Yellow;
            iwr -useb $link -OutFile $layoutFile; Start-Sleep -S 3
                            
            # Unlock start menu, disable pinning, replace with blank file
            Write-Host "`t`t- Unlocking and replacing current file..." -f Yellow;
            $keys | % { if(!(test-path $_)){ New-Item -Path $_ -Force | Out-Null; Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 1; Set-ItemProperty -Path $_ -Name "StartLayoutFile" -Value $layoutFile } }
            Write-host "`t`t- Restarting explorer..." -f Yellow
            Stop-Process -name explorer -Force; Start-Sleep -s 5

            # Enable pinning
            Write-host "`t`t- Fixing pinning..." -f Yellow
            $keys | % { Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 0 }
            Write-host "`t`t- Restarting explorer..." -f Yellow
            Stop-Process -name explorer -Force; Start-Sleep -s 5

            # Save menu to all users
            write-host "`t`t- Save changes to all users.." -f Yellow
            Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

            # Clean up after script
            Remove-Item $layoutFile
            write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    # Clean Taskbar
        Write-host "`tCleaning Taskbar:" -f Green
        Start-Sleep -s 5
        
            write-host "`t`t- Changing keys.." -f Yellow
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesChanges -Value 3 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesRemovedChanges -Value 32 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesVersion -Value 3 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Type DWord -Value 0 | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value 0 -Type Dword | Out-Null
            set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0 | Out-Null

            write-host "`t`t- Removing shortcuts.." -f Yellow
            Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse -Force | Out-Null
            Stop-Process -name explorer
            Start-Sleep -s 5
            write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    # Cleaning printers
        Write-host "`tCleaning Printers:" -f Green
        Start-Sleep -s 5    
        
            write-host "`t`t- Disabling auto-install printers from network.." -f Yellow
            If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
            
            write-host "`t`t- Cleaning spooler" -f Yellow
            Stop-Service "Spooler" | out-null; sleep -s 3
            Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*.*" -Force | Out-Null
            Start-Service "Spooler"

            write-host "`t`t- Removing bloat printers:" -f Yellow
            $Bloatprinters = "Fax","OneNote for Windows 10","Microsoft XPS Document Writer", "Microsoft Print to PDF" 
            $Bloatprinters | % {if(Get-Printer | Where-Object Name -cMatch $_){write-host "`t`t`t- Uninstalling: $_" -f Yellow; Remove-Printer $_; Start-Sleep -s 2}}
            write-host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    #End of function
        write-host "`tBloat Remover Complete. Your system is now clean." -f Green
        Start-Sleep 10
                
}
Function settings_privacy {
      
    Write-host "`tENHANCE WINDOWS PRIVACY" -f Green
    #Cleaning Apps and Features
    Write-host "`t`tBLOCKING - Microsoft Data Collection" -f Green
          

    
    # Disable Advertising ID
        Write-host "`t`t`t- Disabling advertising ID." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
        Start-Sleep -s 2
      
    # Disable let websites provide locally relevant content by accessing language list
        Write-host "`t`t`t- Disabling location tracking." -f Yellow
        If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
            New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null}
        Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
        Start-Sleep -s 2
      
    # Disable Show me suggested content in the Settings app
        Write-host "`t`t`t- Disabling personalized content suggestions." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
        Start-Sleep -s 2
      
    # Remove Cortana
        Write-host "`t`t`t- Disabling Cortana." -f Yellow
        $ProgressPreference = "SilentlyContinue"
        Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
        $ProgressPreference = "Continue"
        Stop-Process -name explorer
        Start-Sleep -s 5

    # Disable Online Speech Recognition
        Write-host "`t`t`t- Disabling Online Speech Recognition." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
        Start-Sleep -s 2
    
    # Hiding personal information from lock screen
        Write-host "`t`t`t- Disabling sign-in screen notifications." -f Yellow
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null}
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
        Start-Sleep -s 2
       
    # Disable diagnostic data collection
        Write-host "`t`t`t- Disabling diagnostic data collection" -f Yellow
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null}
        Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
        Start-Sleep -s 2
    
    # Disable App Launch Tracking
        Write-host "`t`t`t- Disabling App Launch Tracking." -f Yellow
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "Start_TrackProgs" -Type DWord -Value 0
        Start-Sleep -s 2

    # Disable "tailored expirence"
        Write-host "`t`t`t- Disable tailored expirience." -f Yellow        
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null}
        Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
        Start-Sleep -s 2

    # Adding entries to hosts file
        Write-host "`t`tBLOCKING - Tracking domains (This may take a while).." -f Green
        Start-Sleep -s 3
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
        Write-host "`t`tBLOCKING - Tracking IP's" -f Green
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
        Start-Sleep 5

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
        Write-host "`t`tSUBMIT - request to Microsoft to delete data about you." -f Green
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
        Write-host "`t`tBLOCKING - Security holes" -f Green
        
        # Disable automatic setup of network connected devices.
            Write-host "`t`t`t- Disabling auto setup network devices." -f Yellow
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
            }
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 -Force 
            Start-Sleep -s 2
            
        # Disable sharing of PC and printers
            Write-host "`t`t`t- Disabling sharing of PC and Printers." -f Yellow
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

        # Disable LLMNR    
            #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-host "`t`t`t- Disabling LLMNR." -f Yellow
            New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force -ea SilentlyContinue | Out-Null
            
        # Disabe SMB Compression - CVE-2020-0796    
            #https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Write-host "`t`t`t- Disabling SMB Compression." -f Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force -ea SilentlyContinue | Out-Null

        # Disable SMB v1    
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-host "`t`t`t- Disabling SMB version 1 support." -f Yellow
            Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue  | Out-Null
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force

        # Disable SMB v2    
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-host "`t`t`t- Disabling SMB version 2 support." -f Yellow
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 –Force

        # Enable SMB Encryption    
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Write-host "`t`t- Activating SMB Encryption." -f Yellow
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null

        # Bad Neighbor - CVE-2020-16898    
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            Write-host "`t`t- Patching Bad Neighbor (CVE-2020-16898)." -f Yellow
            netsh int ipv6 set int *INTERFACENUMBER* rabaseddnsconfig=disable | Out-Null
            
        # Spectre Meldown - CVE-2017-5754    
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Write-host "`t`t- Patching Bad Metldown (CVE-2017-5754)." -f Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force -ea SilentlyContinue | Out-Null
                        
            
        write-host "      COMPLETE - PRIVACY OPTIMIZATION" -f Yellow
        Start-Sleep 10
    
}
     
Function settings_customize {
    
    # Remove 
    Do {
        Write-Host "`t- Would you like to remove Cortana? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Remove Cortana" -f Green
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
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     
    
    
    # Remove login screensaver
    Do {
        Write-Host "`t- Disable LockScreen ScreenSaver? To prevent missing first character(y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Disable screen saver." -f Green
                If (!(Test-Path HKLM:\Software\Policies\Microsoft\Windows\Personalization)) {
                    New-Item -Path HKLM:\Software\Policies\Microsoft\Windows -Name Personalization | Out-Null
                }
                Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")        

    # Taskbar: Hide Searchbox
    Do {
        Write-Host "`t- Hide Searchbox in the taskbar? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Disable searchbox." -f Green
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0 -Type Dword -Force | Out-Null
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")
        
    # Taskbar: Hide task view button
    Do {
        Write-Host "`t- Hide task view button? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Disable task view button." -f Green
                If ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\")) {
                    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")

    # Show file extensions
    Do {
        Write-Host "`t- Show known filetype extensions? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Show file extensions." -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")            
            
    # Show hidden files
    Do {
        Write-Host "`t- Show hidden files? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Show hidden files." -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     

    # Enable Windows Dark Mode
    Do {
        Write-Host "`t- Enable Dark Mode (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Enabling Dark Mode" -f Green
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0 -Type Dword -Force | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Value 0 -Type Dword -Force | Out-Null 
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")               
          
    # Change Explorer to "This PC"
    Do {
        Write-Host "`t- Change Explorer to 'This PC'? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Explorer is changed." -f Green
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Type DWord -Value 1
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  
        
    # Start Menu: Disable Bing Search Results
    Do {
        Write-Host "`t- Disable Bing Search Results in StartMenu? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Bing is being removed." -f Green
                Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWord -Value 0
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Remove 3D objects
    Do {
        Write-Host "`t- Remove '3D Objects' shortcuts? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Removing '3D Objects'" -f Green
                $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
                $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
                If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
                If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}
            }
            N { Write-Host "`t`t- NO. 3D Objects will remain listed in your explorer" -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Hyper-V
    Do {
        Write-Host "`t- Install Hyper-V? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. This may take a while.." -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                if (((Get-WmiObject -class Win32_OperatingSystem).Caption) -match "Home"){$dst = "$env:TMP\install-hyper-v"
                    write-host "`t`t- Windows Home detected, additional script is needed!" -f Green
                    $file = "install.bat"
                    md "$env:TMP\install-hyper-v" -Force | out-null
                    New-Item "$dst\$file" -Force | out-null
                    $domain = Invoke-WebRequest -Uri 'https://gist.githubusercontent.com/samuel-fonseca/662a620ae32aca254ea7730be5ff7145/raw/a1de2537d5b0613e29c9ca3b9bc0ec67ff1e29a2/Hyper-V-Enabler.bat'  -UseBasicParsing
                    $domain = $domain.content; Start-sleep 1
                    write-host "`t`t- Downloading script..." -f Green
                    Set-content "$dst\$file" $domain; Start-Sleep -S 1
                    write-host "`t`t- Opening CMD..." -f Green
                    start cmd -Verb RunAs -ArgumentList "/c","$dst/$file" -wait}
                elseIf ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*") {
                    Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null}
                Else { Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null }
                $ProgressPreference = "Continue" #unhide progressbar 
                Write-Host "`t`t- Installation complete. Restart PC to take effect." -f Green;
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Linux Sub-system
    Do {
        Write-Host "`t- Install Linux Sub-system? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Linux-subsystem is installing.." -f Green
                If ([System.Environment]::OSVersion.Version.Build -ge 14393) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
                }
                Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null 
                Write-Host "`t`t- Installation complete. Restart PC to take effect." -f Green 
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")         

    # Windows Terminal
    Do {
        Write-Host "`t- Install Windows Terminal? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Install windows Terminal.." -f Green
                $link = "https://github.com"+((iwr -useb 'https://github.com/microsoft/terminal/releases/latest').Links | ? href -match 'Win10.*.msixbundle$').href
                $file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); Add-AppxPackage $file; Remove-Item $file
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")      

    # Windows Terminal
    Do {
        Write-Host "`t- Install Powershell Core? (y/n)" -f Yellow -nonewline; ;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                $link = "https://github.com"+((iwr -useb 'https://github.com/PowerShell/powershell/releases/latest/').Links | ? href -match 'win-x64.msi').href
                $file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); Start-Sleep -s 3; Start-Process $file -ArgumentList "/quiet /passive"
              }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
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
    

        
    $appheader = 
    "
                       _           _        _ _                 
      __ _ _ __  _ __ (_)_ __  ___| |_ __ _| | | ___ _ __ 
     / _`   ' _ \| '_ \| | '_ \/ __| __/ ` | | | |/ _ \ '__|
    | (_| | |_) | |_) | | | | \__ \ |  (_| | | |  __/ |   
     \__,_| .__/| .__/|_|_| |_|___/\__\__,_|_|_|\___|_|   
          |_|   |_|                                               
    " 
        
            Write-host $appheader -f Yellow 
            "";
            
            Do {
                Write-Host "`tWould you like to Install Microsoft .NET Framework? (y/n)" -f Green -nonewline; ;
                $answer = Read-Host " " 
                Switch ($answer) { 
                    Y {
                        Write-Host "`t`t- Download.." -f Yellow 
                        iwr -useb 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/other/install-dotnet.ps1' -OutFile "$($env:TMP)\visualplusplus.ps1"
                        Start-Sleep -S 3
                        Write-Host "`t`t- Installing.." -f Yellow 
                        start-process powershell -argument "-ep bypass -windowstyle Hidden -file `"$($env:TMP)\visualplusplus.ps1`""
                        Start-Sleep -S 3
                        Remove-item "$($env:TMP)\visualplusplus.ps1" | Out-Null
                    }
                    N { Write-Host "            NO. Skipping this step." -f Red } 
                }}
            While ($answer -notin "y", "n")
            
            Do {
                Write-Host "`tWould you like to install all Microsoft Visual C++ Redistributable versions? (y/n)" -f Green -nonewline; ;
                $answer = Read-Host " " 
                Switch ($answer) { 
                    Y {
                        
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
                        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
                        Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
                        
                        $path = "$($env:TMP)\Visual"
                            if(!(test-path $path)){New-Item $path -ItemType Directory -ea SilentlyContinue | Out-Null}
                        $FileDestination = "$($env:TMP)\Visual\drivers.zip"
                        
                        Write-Host "`t`t- Download.." -f Yellow
                        $link =  "https://drive.google.com/uc?export=download&confirm=uc-download-link&id=1mHvNVA_pI0XnWyjRDNee0vhQxLp6agp_"
                        (New-Object net.webclient).Downloadfile($link, $FileDestination)
                    
                        Write-Host "`t`t- Extracting.." -f Yellow
                        Expand-Archive $FileDestination -DestinationPath $path | Out-Null; 
                        Start-Sleep -s 5
                    
                        Write-Host "`t`t- Installing.." -f Yellow
                        Set-Location $path
                        ./vcredist2005_x64.exe /q | Out-Null
                        ./vcredist2008_x64.exe /qb | Out-Null
                        ./vcredist2010_x64.exe /passive /norestart | Out-Null
                        ./vcredist2012_x64.exe /passive /norestart | Out-Null
                        ./vcredist2013_x64.exe /passive /norestart | Out-Null
                        ./vcredist2015_2017_2019_2022_x64.exe /passive /norestart | Out-Null
                        
                      }
                    N { Write-Host "            NO. Skipping this step." -f Red } }} 
            While ($answer -notin "y", "n")  


        #check if chocolatey is installed
        Write-Host "`tApp installer:" -f Green
        if (!(Test-Path "$($env:ProgramData)\chocolatey\choco.exe")) { 
            # installing chocolatey
            Write-host "`t`t- Chocolatey not found on system:" -f Yellow
            Write-host "`t`t`t- Application not found. Installing:" -f Yellow
            Write-host "`t`t`t- Preparing system.." -f Yellow
            Set-ExecutionPolicy Bypass -Scope Process -Force;
            # Downloading installtion file from original source
            Write-host "`t`t`t- Downloading script.." -f Yellow
            (New-Object System.Net.WebClient).DownloadFile("https://chocolatey.org/install.ps1","$env:TMP/choco-install.ps1")
            # Adding a few lines to make installtion more silent.
            Write-host "`t`t`t- Preparing script.." -f Yellow
            $add_line1 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace '\| write-Output', ' | out-null' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1; "
            $add_line2 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace 'write-', '#write-' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1; "
            $add_line3 = "((Get-Content -path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1 -Raw) -replace 'function.* #write-', 'function Write-' ) | Set-Content -Path $env:TMP\chocolatey\chocoInstall\tools\chocolateysetup.psm1;"
            ((Get-Content -path $env:TMP/choco-install.ps1 -Raw) -replace 'write-host', "#write-host" ) | Set-Content -Path $env:TMP/choco-install.ps1
            ((Get-Content -path $env:TMP/choco-install.ps1 -Raw) -replace '#endregion Download & Extract Chocolatey', "$add_line1`n$add_line2`n$add_line3" ) | Set-Content -Path $env:TMP/choco-install.ps1
            # Executing installation file.
            cd $env:TMP
            Write-host "`t`t`t- Installing.." -f Yellow
            .\choco-install.ps1
            Write-host "`t`t`t- Installation complete.." -f Yellow}
        else { Write-host "`t`t- Installer found. Skipping installation." -f Yellow }

            Write-host "DESKTOP APPLICATIONS:" -f Green;""; 

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
            write-host "`t`t`tMPC-HC        Popcorntime         " -f Green
            "";
            write-host "`t`tDevelopment:" -f Yellow
            write-host "`t`t`tNotepad++       vscode           atom" -f Green
            write-host "`t`t`tVim             Eclipse          PyCharm" -f Green
            write-host "`t`t`tPuTTY           Superputty       TeraTerm" -f Green
            write-host "`t`t`tFilezilla       WinSCP           mRemoteNG" -f Green
            write-host "`t`t`tWireshark       git              Github Desktop" -f Green
            "";
            write-host "`t`tSocial:" -f Yellow
            write-host "`t`t`tWebex           Zoom           Microsoft Teams" -f Green
            write-host "`t`t`tDiscord         Twitch         Ubisoft-Connect" -f Green
            write-host "`t`t`tSteam" -f Green
            "";
            Write-host "    ** List multiple programs seperated by , (comma) - spaces are allowed." -f Yellow;
            "";
            Write-host "Type the programs you would like to be installed on this system" -nonewline; 
            

            $requested_apps = (Read-Host " ").Split(",") | Foreach-object { $_ -replace ' ',''}
            foreach ($requested_app in $requested_apps) {
                if("cancel" -eq "$requested_app"){Write-Output "Skipping this section.."}
                # Browsers
                elseif("Firefox" -match "$requested_app"){Write-host "        - installing firefox.." -f Yellow -nonewline; choco install firefox -y | out-null;write-host "          [ COMPLETE ]" -f Green;} 
                elseif("Chrome" -match "$requested_app"){Write-host "        - installing Chrome.." -f Yellow -nonewline; choco install googlechrome -y | out-null;write-host "           [ COMPLETE ]" -f Green;} 
                elseif("Brave" -match "$requested_app"){Write-host "        - installing Brave.." -f Yellow -nonewline; choco install Brave -y | out-null;write-host "            [ COMPLETE ]" -f Green;} 
                elseif("Opera" -match "$requested_app"){Write-host "        - installing Opera.." -f Yellow -nonewline; choco install opera -y | out-null;write-host "            [ COMPLETE ]" -f Green;} 
                elseif("Vivaldi" -match "$requested_app"){Write-host "        - installing Vivaldi.." -f Yellow -nonewline; choco install Vivaldi -y | out-null;write-host "          [ COMPLETE ]" -f Green;} 
                # Tools
                elseif("Dropbox" -match "$requested_app"){Write-host "        - installing Dropbox.." -f Yellow -nonewline; choco install dropbox -y | out-null;write-host "          [ COMPLETE ]" -f Green;} 
                elseif("Google Drive" -match "$requested_app"){Write-host "        - installing Google Drive.." -f Yellow -nonewline; choco install googledrive -y | out-null;write-host "     [ COMPLETE ]" -f Green;} 
                elseif("TeamViewer" -match "$requested_app"){Write-host "        - installing TeamViewer.." -f Yellow -nonewline; choco install TeamViewer -y | out-null;write-host "       [ COMPLETE ]" -f Green;} 
                elseif("7-zip" -match "$requested_app"){Write-host "        - installing 7-Zip.." -f Yellow -nonewline; choco install 7Zip -y | out-null;write-host "            [ COMPLETE ]" -f Green;} 
                elseif("winrar" -match "$requested_app"){Write-host "        - installing Winrar.." -f Yellow -nonewline; choco install winrar -y | out-null;write-host "           [ COMPLETE ]" -f Green;} 
                elseif("Greenshot" -match "$requested_app"){Write-host "        - installing Greenshot.." -f Yellow -nonewline; choco install Greenshot -y | out-null;write-host "        [ COMPLETE ]" -f Green;} 
                elseif("ShareX" -match "$requested_app"){Write-host "        - installing Sharex.." -f Yellow -nonewline; choco install Sharex -y | out-null;write-host "           [ COMPLETE ]" -f Green;} 
                elseif("Gimp" -match "$requested_app"){Write-host "        - installing Gimp.." -f Yellow -nonewline; choco install Gimp -y | out-null;write-host "             [ COMPLETE ]" -f Green;} 
                elseif("Adobe" -match "$requested_app"){Write-host "        - installing Adobe Acrobat Reader.." -f Yellow -nonewline; choco install adobereader -y | out-null;write-host "  [ COMPLETE ]" -f Green;} 
                # Media Player
                elseif("spotify" -match "$requested_app"){Write-host "        - installing spotify.." -f Yellow -nonewline; choco install spotify -y | out-null;write-host "          [ COMPLETE ]" -f Green;}  
                elseif("VLC" -match "$requested_app"){Write-host "        - installing VLC.." -f Yellow -nonewline; choco install VLC -y | out-null;write-host "              [ COMPLETE ]" -f Green;}  
                elseif("itunes" -match "$requested_app"){Write-host "        - installing itunes.." -f Yellow -nonewline; choco install itunes -y | out-null;write-host "           [ COMPLETE ]" -f Green;}  
                elseif("Winamp" -match "$requested_app"){Write-host "        - installing Winamp.." -f Yellow -nonewline; choco install Winamp -y | out-null;write-host "           [ COMPLETE ]" -f Green;}  
                elseif("foobar2000" -match "$requested_app"){Write-host "        - installing foobar2000.." -f Yellow -nonewline; choco install foobar2000 -y | out-null;write-host "       [ COMPLETE ]" -f Green;}  
                elseif("K-lite" -match "$requested_app"){Write-host "        - installing K-Lite.." -f Yellow -nonewline; choco install k-litecodecpackfull -y | out-null;write-host "           [ COMPLETE ]" -f Green;}  
                elseif("MPC-HC" -match "$requested_app"){Write-host "        - installing MPC-HC.." -f Yellow -nonewline; choco install MPC-HC -y | out-null;write-host "           [ COMPLETE ]" -f Green;}  
                elseif("popcorn" -match "$requested_app"){Write-host "        - installing Popcorntime.." -f Yellow -nonewline; choco install popcorntime -y | out-null;write-host "      [ COMPLETE ]" -f Green;}  
                # Development
                elseif("notepad++" -match "$requested_app"){Write-host "        - installing Notepad++.." -f Yellow -nonewline; choco install notepadplusplus -y | out-null;write-host "        [ COMPLETE ]" -f Green;}  
                elseif("vscode" -match "$requested_app"){Write-host "        - installing vscode.." -f Yellow -nonewline; choco install vscode -y | out-null;write-host "           [ COMPLETE ]" -f Green;}  
                elseif("atom" -match "$requested_app"){Write-host "        - installing atom.." -f Yellow -nonewline; choco install atom -y | out-null;write-host "             [ COMPLETE ]" -f Green;}  
                elseif("vim" -match "$requested_app"){Write-host "        - installing vim.." -f Yellow -nonewline; choco install vim -y | out-null;write-host "              [ COMPLETE ]" -f Green;} 
                elseif("Eclipse" -match "$requested_app"){Write-host "        - installing Eclipse.." -f Yellow -nonewline; choco install Eclipse -y | out-null;write-host "          [ COMPLETE ]" -f Green;} 
                elseif("PyCharm" -match "$requested_app"){Write-host "        - installing PyCharm.." -f Yellow -nonewline; choco install PyCharm -y | out-null;write-host "          [ COMPLETE ]" -f Green;} 
                elseif("putty" -match "$requested_app"){Write-host "        - installing putty.." -f Yellow -nonewline; choco install PyCharm -y | out-null;write-host "            [ COMPLETE ]" -f Green;} 
                elseif("superputty" -match "$requested_app"){Write-host "        - installing superputty.." -f Yellow -nonewline; choco install superputty -y | out-null;write-host "       [ COMPLETE ]" -f Green;} 
                elseif("teraterm" -match "$requested_app"){Write-host "        - installing teraterm.." -f Yellow -nonewline; choco install teraterm -y | out-null;write-host "         [ COMPLETE ]" -f Green;} 
                elseif("Filezilla" -match "$requested_app"){Write-host "        - installing Filezilla.." -f Yellow -nonewline; choco install Filezilla -y | out-null;write-host "        [ COMPLETE ]" -f Green;} 
                elseif("WinSCP" -match "$requested_app"){Write-host "        - installing WinSCP.." -f Yellow -nonewline; choco install WinSCP -y | out-null;write-host "           [ COMPLETE ]" -f Green;} 
                elseif("mremoteng" -match "$requested_app"){Write-host "        - installing MRemoteNG.." -f Yellow -nonewline; choco install mremoteng -y | out-null;write-host "        [ COMPLETE ]" -f Green;} 
                elseif("wireshark" -match "$requested_app"){Write-host "        - installing Wireshark.." -f Yellow -nonewline; choco install wireshark -y | out-null;write-host "        [ COMPLETE ]" -f Green;} 
                elseif("git" -match "$requested_app"){Write-host "        - installing git.." -f Yellow -nonewline; choco install git.install -y | out-null;write-host "              [ COMPLETE ]" -f Green;}
                elseif("GithubDesktop" -match "$requested_app"){Write-host "        - installing Github Desktop.." -f Yellow -nonewline; choco install github-desktop -y | out-null;write-host "   [ COMPLETE ]" -f Green;}
                # Social
                elseif("Microsoft Teams" -match "$requested_app"){Write-host "        - installing Microsoft Teams.." -f Yellow -nonewline; choco install microsoft-teams -y | out-null;write-host "  [ COMPLETE ]" -f Green;} 
                elseif("Zoom" -match "$requested_app"){Write-host "        - installing Zoom.." -f Yellow -nonewline; choco install Zoom -y | out-null;write-host "             [ COMPLETE ]" -f Green;} 
                elseif("Webex" -match "$requested_app"){Write-host "        - installing Webex.." -f Yellow -nonewline; choco install webex-teams -y | out-null;choco install webex-meetings -y | out-null;  write-host "            [ COMPLETE ]" -f Green;}
                elseif("Discord" -match "$requested_app"){Write-host "        - installing Discord.." -f Yellow -nonewline; choco install Discord -y | out-null;Write-host "          [ COMPLETE ]" -f Green;}
                elseif("Twitch" -match "$requested_app"){Write-host "        - installing Twitch.." -f Yellow -nonewline; choco install Twitch -y | out-null;Write-host "           [ COMPLETE ]" -f Green;}
                elseif("Steam" -match "$requested_app"){Write-host "        - installing Steam.." -f Yellow -nonewline; choco install Steam -y | out-null;  write-host "            [ COMPLETE ]" -f Green;}
                elseif("Ubisoft Connect" -match "$requested_app"){Write-host "        - installing Ubisoft Connect.." -f Yellow -nonewline; choco install ubisoft-connect -y | out-null;write-host "  [ COMPLETE ]" -f Green;}
            }
    
    
            Do {
                Write-Host "`tWould you like to install auto-updater? (y/n)" -f Green -nonewline;
                $answer = Read-Host " " 
                Switch ($answer) { 
                    Y {   
                            if ((Get-Childitem -Path $env:ProgramData).Name  -match "Chocolatey"){
                            #create update file
                            write-host "`t`t- Downloading updating script." -f Yellow
                            $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                            Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile $filepath -UseBasicParsing
                            
                            # Create scheduled job
                            write-host "`t`t- scheduling update routine." -f Yellow
                            $name = 'winoptimizer-app-Updater'
                            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nop -W hidden -noni -ep bypass -file $filepath"
                            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                            $trigger= New-ScheduledTaskTrigger -At 12:00 -Daily
                            $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -RunOnlyIfIdle -DontStopOnIdleEnd -IdleDuration 00:05:00 -IdleWaitTimeout 03:00:00

                            Register-ScheduledTask -TaskName $Name -Taskpath "\Microsoft\Windows\Winoptimizer\" -Settings $settings -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null
                            } else{Write-host "`t`t- Chocolatey is not installed on this system." -f red}                                                    
                    }
                    N { Write-Host "`t`t- NO. Skipping this step." -f Red }}} 
            While ($answer -notin "y", "n")

            
 

            DO {
                Write-Host "`tWould you like to Install Microsoft Office? (y/n)" -f Green -nonewline;
                $answer1 = Read-host -Prompt " " 
                    Switch ($answer1) { 
              
                    y {        
              
                        # Choose version
                              "";
                              Write-host "Version Menu:"
                              "";
                              Write-host "`t - Microsoft 365"
                              Write-host "`t - Microsoft Office 2019 Business Retail"
                              Write-host "`t - Microsoft Office 2016 Business Retail"
                              "";"";
                              DO {                     
                         
              
                                $answer2 = Read-host -Prompt "`tWhich version would you prefer?"
                                if("$answer2" -eq "Cancel"){}                         
                                elseif("$answer2" -match "365")       {$ver = "O365BusinessRetail"}
                                elseif("$answer2" -match "2019")      {$ver = "HomeBusiness2019Retail"}
                                elseif("$answer2" -match "2016")      {$ver = "HomeBusinessRetail"}}
                              While($ver -notin "O365BusinessRetail", "HomeBusiness2019Retail","HomeBusinessRetail")     
                      
                        # Choose Language
                              "";
                              Write-host "Language Menu:"
                              "";
                              Write-host "`t - English (United States)"
                              Write-host "`t - German"
                              Write-host "`t - Spanish"
                              Write-host "`t - Danish"
                              Write-host "`t - France"
                              Write-host "`t - Japanese"
                              Write-host "`t - Norwegian"
                              Write-host "`t - Russia"
                              Write-host "`t - Sweden"
                              "";"";
                              DO {                     
                                  $answer3 = Read-host -Prompt "`tEnter your language from above"
                                  if("$answer3" -eq "Cancel"){Write-Output "Skipping this section.."}                         
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
                          
                        # Download and customize script
                              # Download template
                              $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/install-office.ps1"
                              $officescript = "$($env:ProgramData)\office-script.ps1"
                              (New-Object net.webclient).Downloadfile($link, $officescript)               
                              # Add to script
                              

                              # Execute script
                              write-host "`tInstallation is running in the background."
                              Start-Process PowerShell -argument "-Ep bypass -Windowstyle hidden -file `"$officescript`""
                              
                          }
              
                                       
                       
                       
                    n {Write-host "Skipping Microsoft Office Installation."}}}
            
            While ($answer1 -notin "y", "n")

    Clear-Host



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
Version 2.6
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "
 
#Check if admin
$admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin_permissions_check) {


    do {
        Write-host $intro -f Yellow 
        Write-host "Please select one of the following options:" -f Yellow
        Write-host ""; Write-host "";
        Write-host "        [1] - All"
        Write-host "        [2] - Bloatware removal"
        Write-host "        [3] - Privacy optimizer"
        Write-host "        [4] - Customize Windows settings"
        Write-host "        [5] - App installer"
        "";
        Write-host "        [0] - Exit"
        Write-host ""; Write-host "";
        Write-Host "Option: " -f Yellow -nonewline; ; ;
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