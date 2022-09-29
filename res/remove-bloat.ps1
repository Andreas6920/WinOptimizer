    Write-Host "REMOVING MICROSOFT BLOAT" -f Green;"";
    Start-Sleep -s 3
    
    # Clean Apps and features
        # List
        Write-Host "`tCleaning Bloatware:" -f Green
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
            "Microsoft.Office.OneNote"
            "Microsoft.MicrosoftSolitaireCollection"
            "Microsoft.MicrosoftStickyNotes"
            "Microsoft.MixedReality.Portal"
            "Microsoft.Music.Preview"
            "Microsoft.People"
            "Microsoft.PeopleExperienceHost"
            "Microsoft.WindowsFeedbackHub"
            "Microsoft.WindowsMaps"
            "Microsoft.WindowsMaps"
            "Microsoft.ZuneMusic"
            "Microsoft.ZuneVideo"
            "Microsoft.windowscommunicationsapps"
            "Microsoft.Wallet"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "CBSPreview"
                                                
            ## Xbox Bloat ##
            "Microsoft.Xbox.TCUI"
            "Microsoft.XboxApp"
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

            # Remove listed
            $ProgressPreference = "SilentlyContinue" # hide progressbar
            foreach ($Bloat in $Bloatware) {
                $bloat_name = (Get-AppxPackage | Where-Object Name -Like $Bloat).Name
                if (Get-AppxPackage | Where-Object Name -Like $Bloat){Write-Host "`t`t- Removing: " -f Yellow -nonewline; Write-Host "$bloat_name".Split(".")[1].Split("}")[0].Replace('Microsoft','') -f Yellow; Get-AppxPackage | Where-Object Name -Like $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null}
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online | Out-Null} 
            $ProgressPreference = "Continue" #unhide progressbar
            Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;



    # Disabling services
        Write-Host "`tCleaning Startup services:" -f Green
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
         Write-Host "`t`t- Disabling: $service" -f Yellow
         Get-Service | Where-Object name -eq $service | Set-Service -StartupType Disabled}}
         Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;



    # Clean Task Scheduler
        Write-Host "`tCleaning Scheduled tasks:" -f Green
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
            Write-Host "`t`t- Disabling: $BloatSchedule" -f Yellow
            Get-ScheduledTask | Where-Object Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null}}
            Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;
        

            
    # Clean start menu
        Write-Host "`tCleaning Start Menu:" -f Green
        Start-Sleep -s 5
    
            # Prepare
            $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/StartMenuLayout.xml"
            $File = "$($env:SystemRoot)\StartMenuLayout.xml"
            $keys = "HKLM:\Software\Policies\Microsoft\Windows\Explorer","HKCU:\Software\Policies\Microsoft\Windows\Explorer"; 
                
            # Download blank Start Menu file
            Write-Host "`t`t- Downloading Start Menu file..." -f Yellow;
            (New-Object net.webclient).Downloadfile("$link", "$file"); 
                            
            # Unlock start menu, disable pinning, replace with blank file
            Write-Host "`t`t- Unlocking and replacing current file..." -f Yellow;
            $keys | % { if(!(test-path $_)){ New-Item -Path $_ -Force | Out-Null; Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 1; Set-ItemProperty -Path $_ -Name "StartLayoutFile" -Value $File } }
            
            # Restart explorer
            # restart-explorer

            # Enable pinning
            Write-Host "`t`t- Fixing pinning..." -f Yellow
            $keys | % { Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 0 }
            
            #Restart explorer
            # restart-explorer

            # Save menu to all users
            Write-Host "`t`t- Save changes to all users.." -f Yellow
            Import-StartLayout -LayoutPath $File -MountPath $env:SystemDrive\

            # Clean up after script
            Remove-Item $File
            Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    # Clean Taskbar
        Write-Host "`tCleaning Taskbar:" -f Green
        Start-Sleep -s 5
        
            Write-Host "`t`t- Changing keys.." -f Yellow
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesChanges -Value 3 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesRemovedChanges -Value 32 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name FavoritesVersion -Value 3 -Type Dword -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -Type DWord -Value 0 | Out-Null
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -Value 0 -Type Dword | Out-Null
            set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -Type DWord -Value 0 | Out-Null

            Write-Host "`t`t- Removing shortcuts.." -f Yellow
            Remove-Item -Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Recurse -Force | Out-Null
            Stop-Process -name explorer
            Start-Sleep -s 5
            Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    # Cleaning printers
        Write-Host "`tCleaning Printers:" -f Green
        Start-Sleep -s 5    
        
            Write-Host "`t`t- Disabling auto-install printers from network.." -f Yellow
            If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
            
            Write-Host "`t`t- Cleaning spooler" -f Yellow
            Stop-Service "Spooler" | out-null; sleep -s 3
            Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*.*" -Force | Out-Null
            Start-Service "Spooler"

            Write-Host "`t`t- Removing bloat printers:" -f Yellow
            $Bloatprinters = "Fax","OneNote for Windows 10","Microsoft XPS Document Writer", "Microsoft Print to PDF" 
            $Bloatprinters | % {if(Get-Printer | Where-Object Name -cMatch $_){Write-Host "`t`t`t- Uninstalling: $_" -f Yellow; Remove-Printer $_; Start-Sleep -s 2}}
            Write-Host "`t`t- Cleaning complete." -f Yellow; ""; Start-Sleep -S 3;

        
    #End of function
        Write-Host "`tBloat Remover Complete. Your system is now clean." -f Green
        Start-Sleep 10