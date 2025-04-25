Function Start-WinAntiBloat {

    # Ensure admin rights
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
		# Relaunch as an elevated process
		$Script = $MyInvocation.MyCommand.Path
		Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned", "-File `"$Script`""}

    # Tjek om systemet er Windows 11 baseret eller 10
        $BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        if([int]$BuildNumber -ge 22000){$ThisIsWindows11 = $True; $ThisIsWindows10 = $False;}
        else{$ThisIsWindows11 = $False; $ThisIsWindows10 = $True;}
            if($ThisIsWindows10){$SystemVersion = "Windows 10"}
            if($ThisIsWindows11){$SystemVersion = "Windows 11"}

    # Start function
        Write-Host "`n$(Get-LogDate)`tREMOVING WINDOWS BLOAT, $($SystemVersion)" -f Green
        Start-Sleep -s 3
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    

    # Clean Taskbar
        Write-Host "$(Get-LogDate)`t    Cleaning Taskbar:" -f Green
        Start-Sleep -s 3
        Write-Host "$(Get-LogDate)`t        - Setting registrykeys:" -f Yellow
    
        # Taskbar features
            # Remove Searchbar    
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type "Dword" -Value "0"
            # Remove Taskview
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type "DWord" -Value "0"
            # Remove Cortana
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type "DWord" -Value "0" # Windows 10 specific
            # Remove Widgets
            Add-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type "DWord" -Value "0" # Windows 10 specific
            Add-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type "Dword" -Value "0"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type "DWord" -Value "0" 
        # Taskbar application shortcuts
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Value ([byte[]](0xFF)) -Force | Out-Null    
            $PinnedPath = Join-path -Path ([Environment]::GetFolderPath("ApplicationData")) -Childpath "\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*"
            If (test-path $PinnedPath){Remove-Item -Path $PinnedPath -Recurse -Force }
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesChanges" -Type "Dword" -Value "3"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesRemovedChanges" -Type "Dword" -Value "32"
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesVersion" -Type "Dword"-Value "3"

        Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;

    # Clean start menu
        Write-Host "$(Get-LogDate)`t    Cleaning Start Menu:" -f Green    
            if($ThisIsWindows10){
                # Prepare
                    $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/StartMenuLayout.xml"
                    $File = "$($env:SystemRoot)\StartMenuLayout.xml"
                    $keys = "HKLM:\Software\Policies\Microsoft\Windows\Explorer","HKCU:\Software\Policies\Microsoft\Windows\Explorer"; 
                        
                # Download blank Start Menu file
                    Write-Host "$(Get-LogDate)`t        - Downloading Start Menu file." -f Yellow;
                    (New-Object net.webclient).Downloadfile("$link", "$file"); 
                                    
                # Unlock start menu, disable pinning, replace with blank file
                    Write-Host "$(Get-LogDate)`t        - Unlocking and replacing current file." -f Yellow;
                    $keys | ForEach-Object { if(!(test-path $_)){ New-Item -Path $_ -Force | Out-Null; Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 1; Set-ItemProperty -Path $_ -Name "StartLayoutFile" -Value $File } }
                    
                # Restart explorer
                    Restart-Explorer

                # Enable pinning
                    Write-Host "$(Get-LogDate)`t        - Fixing pinning." -f Yellow
                    $keys | ForEach-Object { Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 0 }
                    
                #Restart explorer
                    Restart-Explorer

                # Save menu to all users
                    Write-Host "$(Get-LogDate)`t        - Save changes to all users." -f Yellow
                    Import-StartLayout -LayoutPath $File -MountPath $env:SystemDrive\

                # Clean up after script
                    Remove-Item $File
                    Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow;  Start-Sleep -S 3;}

        If($ThisIsWindows11){

            Start-Sleep -s 3
            $FileUrl = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/start2.bin"
            $DestinationPath = "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin"

            # Download og gem filen
                try {   Write-Host "$(Get-LogDate)`t        - Downloading new start menu template." -f Yellow
                        Invoke-RestMethod -Uri $FileUrl -OutFile $DestinationPath
                        Write-Host "$(Get-LogDate)`t        - Complete." -f Yellow
                        Write-Host "$(Get-LogDate)`t        - Restarting explorer." -f Yellow
                        Start-Sleep -S 2
                        Restart-Explorer} 
                catch { Write-Host "Failed to download file: $_" -ForegroundColor Red}}

   # Clean Apps and features
        Write-Host "$(Get-LogDate)`t    Cleaning Bloatware:" -ForegroundColor Green
        Start-Sleep -Seconds 3

        # Liste over kendte bloatware apps
        $Bloatware = @(
            # Microsoft bloat
            "*autodesksketch*", "*oneconnect*", "*plex*", "*print3d*",
            "Microsoft.3DBuilder", "Microsoft.Getstarted", "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftOfficeHub", "Microsoft.Office.OneNote", "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal", "Microsoft.Music.Preview",
            "Microsoft.People", "Microsoft.PeopleExperienceHost", "Microsoft.WindowsFeedbackHub",
            "Microsoft.WindowsMaps", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
            "Microsoft.windowscommunicationsapps", "Microsoft.Wallet", "Microsoft.GetHelp", "CBSPreview",

            # Xbox bloat
            "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameCallableUI",
            "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay", "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",

            # Bing bloat
            "*Bing*", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink",
            "Microsoft.BingHealthAndFitness", "Microsoft.BingNews", "Microsoft.BingSports",
            "Microsoft.BingTravel", "Microsoft.BingWeather",

            # Games
            "*Bubblewitch*", "*Candycrush*", "*Disney*", "*Empires*", "*Minecraft*", "*Royal revolt*",

            # Other
            "*ActiproSoftwareLLC*", "*AdobePhotoshopExpress*", "*Duolingo*", "*EclipseManager*",
            "*Facebook*", "*Flipboard*", "*PandoraMediaInc*", "*Skype*", "*Spotify*", "*Twitter*", "*Wunderlist*")

        $ProgressPreference = "SilentlyContinue"

        # Hent app-lister én gang
        $InstalledAppx      = Get-AppxPackage
        $ProvisionedAppx    = Get-AppxProvisionedPackage -Online

        foreach ($bloat in $Bloatware) {
            # Fjern brugerinstallerede apps
                $matches = $InstalledAppx | Where-Object Name -like $bloat
                foreach ($match in $matches) {
                    $AppName = $match.Name -replace '^.*?\.', '' -replace '^Microsoft', ''
                    Write-Host "$(Get-LogDate)`t        - Removing user app: $($AppName)" -ForegroundColor Yellow
                    Remove-AppxPackage -Package $match.PackageFullName -ErrorAction SilentlyContinue | Out-Null}
            
            # Fjern pre-provisioned apps (fremtidige brugere)
            $provMatches = $ProvisionedAppx | Where-Object DisplayName -like $bloat
            foreach ($prov in $provMatches) {
                $AppName = $prov.DisplayName -replace '^.*?\.', '' -replace '^Microsoft', ''
                if ($prov.PackageName -and $prov.PackageName -ne "") {
                    Write-Host "$(Get-LogDate)`t        - Removing provisioned app: $($AppName)" -ForegroundColor Yellow
                    try {Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null}
                    catch {Write-Host "$(Get-LogDate)`t        - Failed to remove provisioned: $($AppName)" -ForegroundColor Red}}}
        }

        $ProgressPreference = "Continue"

        Write-Host "$(Get-LogDate)`t        - Cleaning complete." -ForegroundColor Yellow
        Start-Sleep -Seconds 3

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

    foreach ($serviceName in $Services) {
        try {   $svc = Get-Service -Name $serviceName -ErrorAction Stop
            
                if ($svc.StartType -ne 'Disabled') {
                    Write-Host "$(Get-LogDate)`t        - Disabling: $serviceName" -ForegroundColor Yellow
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue}} 
                catch {Write-Host "$(Get-LogDate)`t        - Service not found: $serviceName (skipped)" -ForegroundColor DarkGray}}
    
    Write-Host "$(Get-LogDate)`t        - Cleaning complete." -ForegroundColor Yellow
    Start-Sleep -Seconds 2

    # Clean Task Scheduler
        Write-Host "$(Get-LogDate)`t    Cleaning Scheduled tasks:" -f Green
        Start-Sleep -s 3
        $Bloatschedules = @(
            "WebExperience"
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
            "WinSAT"
            "XblGameSaveTask"
            "PcaPatchDbTask"
            )

        foreach ($TaskName in $BloatSchedules) {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($task -and $task.State -ne "Disabled") {
                Write-Host "$(Get-LogDate)`t        - Disabling: $TaskName" -f Yellow
                try {Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null} catch {}
                Start-Sleep -Milliseconds 500}}
        
        Write-Host "$(Get-LogDate)`t        - Cleaning complete." -f Yellow
        Start-Sleep -Seconds 3   

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
        Start-Sleep 5
                
}