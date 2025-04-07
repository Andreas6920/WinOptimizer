Function Start-WinAntiBloat {
    Write-Host "`n$(Get-LogDate)`tREMOVING WINDOWS BLOAT" -f Green
    Start-Sleep -s 3
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    #reinsure admin rights
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
        {# Relaunch as an elevated process
        $Script = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

    # Clean Taskbar
        Write-Host "$(Get-LogDate)`t    Cleaning Taskbar:" -f Green
        Start-Sleep -s 5
        
            Write-Host "$(Get-LogDate)`t        - Setting registrykeys:" -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesChanges" -Type "Dword" -Value "3"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesRemovedChanges" -Type "Dword" -Value "32"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesVersion" -Type "Dword"-Value "3" 
            Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband -Name Favorites -Value ([byte[]](0xFF)) -Force | Out-Null
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type "DWord" -Value "0"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0" 
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type "DWord" -Value "0" 
            Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type "DWord" -Value "2"
            $PinnedPath = Join-path -Path ([Environment]::GetFolderPath("ApplicationData")) -Childpath "\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*"
            If (test-path $PinnedPath){Remove-Item -Path $PinnedPath -Recurse -Force }
            Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;

    # Clean start menu
        Write-Host "$(Get-LogDate)`t    Cleaning Start Menu:" -f Green
        Start-Sleep -s 3
    
            # Prepare
            $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/StartMenuLayout.xml"
            $File = "$($env:SystemRoot)\StartMenuLayout.xml"
            $keys = "HKLM:\Software\Policies\Microsoft\Windows\Explorer","HKCU:\Software\Policies\Microsoft\Windows\Explorer"; 
                
            # Download blank Start Menu file
            Write-Host "$(Get-LogDate)`t        - Downloading Start Menu file." -f Yellow;
            (New-Object net.webclient).Downloadfile("$link", "$file"); 
                            
            # Unlock start menu, disable pinning, replace with blank file
            Write-Host "$(Get-LogDate)`t        - Unlocking and replacing current file." -f Yellow;
            $keys | % { if(!(test-path $_)){ New-Item -Path $_ -Force | Out-Null; Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 1; Set-ItemProperty -Path $_ -Name "StartLayoutFile" -Value $File } }
            
            # Restart explorer
            Restart-Explorer

            # Enable pinning
            Write-Host "$(Get-LogDate)`t        - Fixing pinning." -f Yellow
            $keys | % { Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 0 }
            
            #Restart explorer
            Restart-Explorer

            # Save menu to all users
            Write-Host "$(Get-LogDate)`t        - Save changes to all users." -f Yellow
            Import-StartLayout -LayoutPath $File -MountPath $env:SystemDrive\

            # Clean up after script
            Remove-Item $File
            Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;

    # Clean Apps and features
        # List
        Write-Host "$(Get-LogDate)`t    Cleaning Bloatware:" -f Green
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
                if (Get-AppxPackage | Where-Object Name -Like $Bloat){Write-Host "$(Get-LogDate)`t        - Removing: " -f Yellow -nonewline; Write-Host "$bloat_name".Split(".")[1].Split("}")[0].Replace('Microsoft','') -f Yellow; Get-AppxPackage | Where-Object Name -Like $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null}
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null} 
            $ProgressPreference = "Continue" #unhide progressbar
            Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;



    # Disabling services
    Write-Host "$(Get-LogDate)`t    Cleaning Startup services:" -f Green
    Start-Sleep -s 3

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
        try {$currentService = Get-Service -Name $service -ErrorAction Stop
            if ($currentService.StartType -ne 'Disabled') {
                Write-Host "$(Get-LogDate)`t        - Disabling: $service" -f Yellow
                Set-Service -Name $service -StartupType Disabled}}
        catch {Write-Host "$(Get-LogDate)`t        - Service not found: $service (Ignoring)" -f Red}
    }

    Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow
    Start-Sleep -S 3

    # Clean Task Scheduler
        Write-Host "$(Get-LogDate)`t    Cleaning Scheduled tasks:" -f Green
        Start-Sleep -s 3
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
            "XblGameSaveTask"
            "PcaPatchDbTask")

            foreach ($BloatSchedule in $BloatSchedules) {
            if ((Get-ScheduledTask | Where-Object state -ne Disabled | Where-Object TaskName -like $BloatSchedule)){
            Write-Host "$(Get-LogDate)`t        - Disabling: $BloatSchedule" -f Yellow
            Get-ScheduledTask | Where-Object Taskname -eq $BloatSchedule | Disable-ScheduledTask | Out-Null
            Start-Sleep -S 1}}
            Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;       

    # Cleaning printers
        Write-Host "$(Get-LogDate)`t    Cleaning Printers:" -f Green
        Start-Sleep -s 5    
        
            Write-Host "$(Get-LogDate)`t        - Disabling auto-install printers from network.." -f Yellow
            Add-Reg -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
            
            Write-Host "$(Get-LogDate)`t        - Cleaning spooler" -f Yellow
            Stop-Service "Spooler" | out-null; sleep -s 3
            Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*.*" -Force | Out-Null
            Start-Service "Spooler"

            Write-Host "$(Get-LogDate)`t        - Removing bloat printers:" -f Yellow
            $Bloatprinters = "Fax","OneNote for Windows 10","Microsoft XPS Document Writer", "Microsoft Print to PDF" 
            $Bloatprinters | % {if(Get-Printer | Where-Object Name -cMatch $_){Write-Host "$(Get-LogDate)`t            - Uninstalling: $_" -f Yellow; Remove-Printer $_; Start-Sleep -s 2}}
            Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;

        
    #End of function
        Write-Host "$(Get-LogDate)`t    BLOAT REMOVER COMPLETE." -f Green
        Start-Sleep 3
                
}