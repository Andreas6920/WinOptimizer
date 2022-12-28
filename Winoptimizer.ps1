#clean terminal before run
Clear-Host


#Functions

Function block_input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }

Function allow_input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }

Function restart-explorer{
taskkill /IM explorer.exe /F | Out-Null
start explorer | Out-Null
$windowname = $Host.UI.RawUI.WindowTitle
Add-Type -AssemblyName Microsoft.VisualBasic
[Microsoft.VisualBasic.Interaction]::AppActivate($windowname)}

Function remove_bloatware {
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
            restart-explorer

            # Enable pinning
            Write-Host "`t`t- Fixing pinning..." -f Yellow
            $keys | % { Set-ItemProperty -Path $_ -Name "LockedStartLayout" -Value 0 }
            
            #Restart explorer
            restart-explorer

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
                
}

Function settings_privacy {
      
    Write-Host "`tENHANCE WINDOWS PRIVACY" -f Green
    
    
     

    # Adding entries to hosts file
        Write-Host "`t`tBlocking Microsoft's Tracking domains:" -f Green
        Write-Host "`t`t`t- Will start in the background." -f Yellow
        $link = "https://github.com/Andreas6920/WinOptimizer/raw/main/res/block-domains.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;

    # Blocking Microsoft Tracking IP's in the firewall
        Write-Host "`t`tBlocking Microsoft's tracking IP's:" -f Green
        Write-Host "`t`t`t- Will start in the background." -f Yellow
        $link = "https://github.com/Andreas6920/WinOptimizer/raw/main/res/block-ips.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;
    
    #Configuring Windows privacy settings
        Write-Host "`t`tSetting Privacy Settings:" -f Green     
        
        # Disable Advertising ID
            Write-Host "`t`t`t- Disabling advertising ID." -f Yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
            Start-Sleep -s 2
        
        # Disable let websites provide locally relevant content by accessing language list
            Write-Host "`t`t`t- Disabling location tracking." -f Yellow
            If (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
                New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut"  -Value 1
            Start-Sleep -s 2
        
        # Disable Show me suggested content in the Settings app
            Write-Host "`t`t`t- Disabling personalized content suggestions." -f Yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
            Start-Sleep -s 2
        
        # Remove Cortana
            Write-Host "`t`t`t- Disabling Cortana." -f Yellow
            $ProgressPreference = "SilentlyContinue"
            Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
            $ProgressPreference = "Continue"
            Stop-Process -name explorer
            Start-Sleep -s 5

        # Disable Online Speech Recognition
            Write-Host "`t`t`t- Disabling Online Speech Recognition." -f Yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
                New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
            Start-Sleep -s 2
        
        # Hiding personal information from lock screen
            Write-Host "`t`t`t- Disabling sign-in screen notifications." -f Yellow
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\System")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLockedUserID" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUsername" -Type DWord -Value 0
            Start-Sleep -s 2
        
        # Disable diagnostic data collection
            Write-Host "`t`t`t- Disabling diagnostic data collection" -f Yellow
            If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection")) {
                New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"  -Value 0
            Start-Sleep -s 2
        
        # Disable App Launch Tracking
            Write-Host "`t`t`t- Disabling App Launch Tracking." -f Yellow
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "Start_TrackProgs" -Type DWord -Value 0
            Start-Sleep -s 2

        # Disable "tailored expirence"
            Write-Host "`t`t`t- Disable tailored expirience." -f Yellow        
            If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy")) {   
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null}
            Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled"  -Value 0
            Start-Sleep -s 2


    # Send Microsoft a request to delete collected data about you.
        
        #lock keyboard and mouse to avoid disruption while navigating in GUI.
        block_input | Out-Null
        Write-Host "`t`tSUBMIT - request to Microsoft to delete data about you." -f Green
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
        Write-Host "`tENHANCE WINDOWS SECURITY" -f Green
        
        # Disable automatic setup of network connected devices
            Write-Host "`t`t`t- Disabling auto setup network devices." -f Yellow
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null}
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 -Force 
            Start-Sleep -s 2
            
        # Disable sharing of PC and printers
            Write-Host "`t`t`t- Disabling sharing of PC and Printers." -f Yellow
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

        # Disable LLMNR
            #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-Host "`t`t`t- Disabling LLMNR." -f yellow
            New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force -ea SilentlyContinue | Out-Null
        
        # Bad Neighbor - CVE-2020-16898 (Disable IPv6 DNS)
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            Write-Host "`t`t`t- Patching Bad Neighbor (CVE-2020-16898)." -f Yellow
                # Disable DHCPv6  + routerDiscovery
                Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $(Get-NetIPInterface -AddressFamily IPv6 | Select-Object -ExpandProperty InterfaceIndex) -RouterDiscovery Disabled -Dhcp Disabled
                # Prefer IPv4 over IPv6 (IPv6 is prefered by default)
                If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Force | Out-Null}
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 0x20 -Force
        
        # Disabe SMB Compression - CVE-2020-0796
            #https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Write-Host "`t`t`t- Disabling SMB Compression." -f Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force -ea SilentlyContinue | Out-Null

        # Disable SMB v1
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "`t`t`t- Disabling SMB version 1 support." -f Yellow
            start-job -Name "Disable SMB1" -ScriptBlock {
                Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue | Out-Null
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force} | Out-Null
        # Disable SMB v2
            #https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "`t`t`t- Disabling SMB version 2 support." -f Yellow
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 0 –Force

        # Enable SMB Encryption
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Write-Host "`t`t`t- Activating SMB Encryption." -f Yellow
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null
            
        # Spectre Meldown - CVE-2017-5754
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Write-Host "`t`t`t- Patching Bad Metldown (CVE-2017-5754)." -f Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type DWORD -Value 3 -Force -ea SilentlyContinue | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type String -Value "1.0" -Force -ea SilentlyContinue | Out-Null
        
        # Enable LSA protection
            # https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
            Write-Host "`t`t`t- Enabling LSA protection." -f Yellow
            reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 1 /f
            
        #End of function
            Wait-job -Name "Disable SMB1" | Out-Null;
            Write-Host "`tPrivacy optimizer complete. Your system is now more private and secure." -f Green
            Start-Sleep 10
    
}
     
Function settings_customize {
    
    # Remove Cortana
    Do {
        Write-Host "`t- Would you like to remove Cortana? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                # Add/Edit regkey
                $ProgressPreference = "SilentlyContinue" # hide progressbar
                Write-Host "`t`t- YES. Remove Cortana" -f Green
                Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
                If (!(Test-Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
                $ProgressPreference = "Continue" # unhide progressbar
                
                #Restart explorer
                restart-explorer
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     


    $windowname = $Host.UI.RawUI.WindowTitle


    $excelpid = (Get-Process | Where-Object { $_.MainWindowHandle -eq $excel.Hwnd }).Id
    
    
    # Remove login screensaver
    Do {
        Write-Host "`t- Disable LockScreen ScreenSaver? To prevent missing first character (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Disable screen saver." -f Green
                If (!(Test-Path HKLM:\Software\Policies\Microsoft\Windows\Personalization)) {
                    New-Item -Path HKLM:\Software\Policies\Microsoft\Windows -Name Personalization | Out-Null}
                Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Type DWord -Value 1
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")        

    # Taskbar: Hide Searchbox
    Do {
        Write-Host "`t- Hide Searchbox in the taskbar? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                # Edit Regkey
                Write-Host "`t`t- YES. Disable searchbox." -f Green
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name SearchboxTaskbarMode -Value 0 -Type Dword -Force | Out-Null
                
                #Restart explorer
                restart-explorer
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")
        
    # Taskbar: Hide task view button
    Do {
        Write-Host "`t- Hide task view button? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Disable task view button." -f Green
                
                # Remove/Add regkey
                If ((Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\")) {
                    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\" -Force | Out-Null}
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

                #Restart explorer
                restart-explorer
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")

    # Show file extensions
    Do {
        Write-Host "`t- Show known filetype extensions? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Show file extensions." -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null }
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")            
            
    # Show hidden files
    Do {
        Write-Host "`t- Show hidden files? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Show hidden files." -f Green
                If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
                    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")     

    # Enable Windows Dark Mode
    Do {
        Write-Host "`t- Enable Dark Mode (y/n)" -f Yellow -nonewline;
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
        Write-Host "`t- Change Explorer to 'This PC'? (y/n)" -f Yellow -nonewline;
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
        Write-Host "`t- Disable Bing Search Results in StartMenu? (y/n)" -f Yellow -nonewline;
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
        Write-Host "`t- Remove '3D Objects' shortcuts? (y/n)" -f Yellow -nonewline;
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
        Write-Host "`t- Install Hyper-V? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing Hyper-V.. (this may take a while)" -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                if (((Get-WmiObject -class Win32_OperatingSystem).Caption) -match "Home"){$dst = "$env:TMP\install-hyper-v"
                    Write-Host "`t`t- Windows Home detected, additional script is needed!" -f Green
                    $link = "https://gist.githubusercontent.com/samuel-fonseca/662a620ae32aca254ea7730be5ff7145/raw/a1de2537d5b0613e29c9ca3b9bc0ec67ff1e29a2/Hyper-V-Enabler.bat"
                    $file = "$dir\"+(Split-Path $link -Leaf)
                    (New-Object net.webclient).Downloadfile("$link", "$file"); 
                    Start-Sleep -s 3; 
                    start cmd -Verb RunAs -ArgumentList "/c","$dst/$file" -wait}
                elseIf ((Get-WmiObject -Class "Win32_OperatingSystem").Caption -like "*Server*"){Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null}
                Else { Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null }
                $ProgressPreference = "Continue" #unhide progressbar
                Write-Host "`t`t- Installation complete. Restart PC to take effect." -f Green;
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")  

    # Install Linux Sub-system
    Do {
        Write-Host "`t- Install Linux Sub-system? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing Linux sub-system.. (this may take a while)" -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                
                # Enable Linux Sub-system Feature
                If ([System.Environment]::OSVersion.Version.Build -ge 14393) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1}
                Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null 
                
                # Download ubuntu
                $link = "https://wsldownload.azureedge.net/Ubuntu_2004.2020.424.0_x64.appx"
                $file = "$dir\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file")

                # Install Ubuntu
                Add-AppxPackage $file; Start-Sleep -S 3; Remove-item $file
                $ProgressPreference = "Continue" #unhide progressbar
                Start-Sleep -S 3;
                
                
                Write-Host "`t`t- Installation complete." -f Green;
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")         

    # Windows Terminal
    Do {
        Write-Host "`t- Install Windows Terminal? (y/n)" -f Yellow -nonewline; 
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                
                Write-Host "`t`t- YES. Installing Windows Terminal.." -f Green
                $ProgressPreference = "SilentlyContinue" #hide progressbar
                
                # Install VClibs
                $link = "https://github.com/Andreas6920/WinOptimizer/raw/main/res/Microsoft.VCLibs.140.00.UWPDesktop_14.0.30704.0_x64__8wekyb3d8bbwe.Appx"
                $file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); Add-AppxPackage $file; Remove-Item $file

                # Download terminal
                $link = "https://github.com"+((iwr -useb 'https://github.com/microsoft/terminal/releases/latest').Links | ? href -match 'Win10.*.msixbundle$').href
                $file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); 
                Start-Sleep -S 3; 
                
                # Install terminal
                Add-AppxPackage $file; Remove-Item $file
                restart-explorer

                Write-Host "`t`t- Installation complete." -f Green;

                
            }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")      

    # Powershell Core
    Do {
        Write-Host "`t- Install Powershell Core? (y/n)" -f Yellow -nonewline;
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing PowerShell Core.." -f Green
                
                # Download file
                $link = "https://github.com"+((iwr -useb 'https://github.com/PowerShell/powershell/releases/latest/').Links | ? href -match 'win-x64.msi').href
                $file = $($env:TMP)+"\"+(Split-Path $link -Leaf)
                (New-Object net.webclient).Downloadfile("$link", "$file"); Start-Sleep -s 3; 
                
                # Install file
                Start-Process $file -ArgumentList "/quiet /passive"

                Write-Host "`t`t- Installation complete." -f Green;
                
              }
            N { Write-Host "`t`t- NO. Skipping this step." -f Red } 
        }   
    } While ($answer -notin "y", "n")
    
    # .Net Framework
    Do {
        Write-Host "`t- Install all Microsoft .NET Framework? (y/n)" -f Yellow -nonewline; 
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing all the .Net Frameworks.." -f Green
                
                #Download file
                $link = 'https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/install-dotnet.ps1'
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
    
    # Microsoft Visual C++
    
    Do {
        Write-Host "`t- Install all Microsoft Visual C++ Redistributable versions? (y/n)" -f Yellow -nonewline; 
        $answer = Read-Host " " 
        Switch ($answer) { 
            Y {
                Write-Host "`t`t- YES. Installing all the Visual C++ versions.." -f Green

                # Download file
                $link = "https://drive.google.com/uc?export=download&confirm=uc-download-link&id=1mHvNVA_pI0XnWyjRDNee0vhQxLp6agp_"
                $file = "$dir\Visual\drivers.zip"
                (New-Object net.webclient).Downloadfile($link, $FileDestination)
                
                # Unzip file
                Expand-Archive $FileDestination -DestinationPath $path | Out-Null; 
                Start-Sleep -s 5
                
                # Install files
                Set-Location ($file | Split-Path -Parent)
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



    #End of function
    Write-Host "`tWindows customizer completed. Your system is now customized." -f Green
    Start-Sleep 10

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
        
            Write-Host $appheader -f Yellow 
            "";
            

        #check if chocolatey is installed
        Write-Host "`tApp installer:" -f Green
        function appinstall {
            param ( [Parameter(Mandatory=$true)]
                    [string]$Name,
                    [Parameter(Mandatory=$true)]
                    [string]$App)
        
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
            Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1
            
            $code = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
            $appinstall = "$($env:ProgramData)\Winoptimizer\appinstall.ps1"
        
            if(!(test-path $appinstall)){new-item -ItemType Directory ($appinstall | Split-Path) -ea ignore | out-null; New-item $appinstall -ea ignore | out-null;}
            if(!((get-content $appinstall) -notmatch "https://community.chocolatey.org/install.ps1")){Set-content -Encoding UTF8 -Value $code -Path $appinstall}
        
            Add-content -Encoding UTF8 -Value (invoke-webrequest "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/app-template.ps1").Content.replace('REPLACE-ME-NAME', $Name).replace('REPLACE-ME-APP', $App) -Path $appinstall}

            Write-Host "`tDesktop Applications:" -f Green;""; 

            Write-Host "`t`tBROWSER:" -f Yellow
            Write-Host "`t`t`tChrome        Firefox      Opera" -f Green
            Write-Host "`t`t`tBrave         Opera        Vevaldi" -f Green
            "";
            Write-Host "`t`tTOOLS:" -f Yellow
            Write-Host "`t`t`tDropbox       Google Drive    Teamviewer" -f Green
            Write-Host "`t`t`t7-zip         Winrar          Greenshot" -f Green
            Write-Host "`t`t`tShareX        Gimp            Adobe Acrobat Reader" -f Green
            "";
            Write-Host "`t`tMEDIA PLAYER:" -f Yellow
            Write-Host "`t`t`tSpotify       VLC           Itunes" -f Green
            Write-Host "`t`t`tWinamp        Foobar2000    K-Lite" -f Green
            Write-Host "`t`t`tMPC-HC        Popcorntime" -f Green
            "";
            Write-Host "`t`tDevelopment:" -f Yellow
            Write-Host "`t`t`tNotepad++       vscode           atom" -f Green
            Write-Host "`t`t`tVim             Eclipse          git " -f Green
            Write-Host "`t`t`tPuTTY           Superputty       TeraTerm" -f Green
            Write-Host "`t`t`tFilezilla       WinSCP           mRemoteNG" -f Green
            Write-Host "`t`t`tWireshark" -f Green
            "";
            Write-Host "`t`tSocial:" -f Yellow
            Write-Host "`t`t`tWebex           Zoom           Microsoft Teams" -f Green
            Write-Host "`t`t`tDiscord         Twitch         Ubisoft-Connect" -f Green
            "";
            Write-Host "    ** List multiple programs seperated by , (comma) - spaces are allowed." -f Yellow;
            "";
            Write-Host "Type the programs you would like to be installed on this system" -nonewline;
            

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
                Write-Host "`tWould you like to Install Microsoft Office? (y/n)" -f Green -nonewline;
                $answer1 = Read-host " " 
                    Switch ($answer1) { 
              
                    y {        
              
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
                                    $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/res/install-office.ps1"
                                    $appinstall = "$($env:ProgramData)\Winoptimizer\appinstall.ps1"
                                    if(!(test-path $appinstall)){new-item -ItemType Directory ($appinstall | Split-Path) -ea ignore | out-null; New-item $appinstall -ea ignore | out-null;}
                                    Add-content -Encoding UTF8 -Value (invoke-webrequest $link).Content.replace('REPLACE-ME-FULLNAME', $Name).replace('REPLACE-ME-VERSION', $ver).replace('REPLACE-ME-LANGUAGE', $lang) -Path $appinstall
                          }
                       
                    n {Write-Host "`t`t- NO. Skipping this step."}}}
            
                While ($answer1 -notin "y", "n")
            
        # Start app installation              
            Start-Process Powershell -argument "-Ep bypass -Windowstyle hidden -file `"""$($env:ProgramData)\Winoptimizer\appinstall.ps1""`""
    
    
            Do {
                Write-Host "`tWould you like to install auto-updater? (y/n)" -f Green -nonewline;
                $answer = Read-Host " " 
                Switch ($answer) { 
                    Y {   
                            #create update file
                            Write-Host "`t`t- Downloading updating script." -f Yellow
                            $filepath = "$env:ProgramData\chocolatey\app-updater.ps1"
                            Invoke-WebRequest -uri "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/app-updater/app-updater.ps1" -OutFile $filepath -UseBasicParsing
                            
                            # Create scheduled job
                            Write-Host "`t`t- scheduling update routine." -f Yellow
                            $name = 'winoptimizer-app-Updater'
                            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nop -W hidden -noni -ep bypass -file $filepath"
                            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM"-LogonType ServiceAccount -RunLevel Highest
                            $trigger= New-ScheduledTaskTrigger -At 12:05 -Daily
                            $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -RunOnlyIfIdle -DontStopOnIdleEnd -IdleDuration 00:05:00 -IdleWaitTimeout 03:00:00

                            Register-ScheduledTask -TaskName $Name -Taskpath "\Microsoft\Windows\Winoptimizer\" -Settings $settings -Principal $principal -Action $action -Trigger $trigger -Force | Out-Null
                                                                                
                    }
                    N { Write-Host "`t`t- NO. Skipping this step." -f Red }}} 
            While ($answer -notin "y", "n")

            
 
    #End of function
    Write-Host "`tApp installer completed. Enjoy your freshly installed applications." -f Green
    Start-Sleep 10




}

   
#Front end begins here
$intro = 
"
 _       ___       ____        __  _           _                
| |     / (_)___  / __ \____  / /_(_)___ ___  (_)___  ___  _____
| | /| / / / __ \/ / / / __ \/ __/ / __ `__  \/ /_  / / _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / /_/ / / / / / / / / /_/  __/ /    
|__/|__/_/_/ /_/\____/ .___/\__/_/_/ /_/ /_/_/ /___/\___/_/     
                    /_/                                         
Version 2.9
Creator: Andreas6920 | https://github.com/Andreas6920/
                                                                                                                                                    
 "
<#
    Next up:
        -  Menu change color if module runned.
            White if not used, orange if interupted, gray if used.
        - Module convert (Menu = script, functions = module)
            Import-Module C:\.. -Function remove_bloat

#>


#Check if admin
$admin_permissions_check = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$admin_permissions_check = $admin_permissions_check.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin_permissions_check) {

    # Prepare system
        
        # Allow powershell to download files with Internet Explorer
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Force | Out-Null}
        Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize"  -Value 1

        # Setting root directory
        $dir = "$env:ProgramData/Winoptimizer";if(!(Test-Path $dir)){mkdir $dir | Out-Null}
            # Download main script to folder
            $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/Winoptimizer.ps1"
            $file = "$dir\"+(Split-Path $link -Leaf)
            (New-Object net.webclient).Downloadfile("$link", "$file")
        
        




    do {
        Write-Host $intro -f Yellow 
        Write-Host "Please select one of the following options:" -f Yellow
        Write-Host ""; Write-Host "";
        Write-Host "        [1] - All"
        Write-Host "        [2] - Bloatware removal"
        Write-Host "        [3] - Privacy And security optimizer"
        Write-Host "        [4] - Customize Windows settings"
        Write-Host "        [5] - App installer"
        "";
        Write-Host "        [0] - Exit"
        Write-Host ""; Write-Host "";
        Write-Host "Option: " -f Yellow -nonewline; ;
        $option = Read-Host
        Switch ($option) { 
            0 { exit }
            1 { remove_bloatware; settings_privacy; settings_customize; app_installer; }
            2 { remove_bloatware }
            3 { settings_privacy }
            4 { settings_customize }
            5 { app_installer }
            Default { cls; Write-Host""; Write-Host""; Write-Host "INVALID OPTION. TRY AGAIN.." -f red; Write-Host""; Write-Host""; Start-Sleep 1; cls; Write-Host ""; Write-Host "" } 
        }
         
    }
    while ($option -ne 5 )

} 
else {
    1..99 | % {
        $Warning_message = "POWERSHELL IS NOT RUNNING AS ADMINISTRATOR. Please close this and run this script as administrator."
        cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White -BackgroundColor Red; ""; ""; ""; ""; ""; Start-Sleep 1; cls
        cls; ""; ""; ""; ""; ""; Write-Host $Warning_message -ForegroundColor White; ""; ""; ""; ""; ""; Start-Sleep 1; cls
    }    
}
