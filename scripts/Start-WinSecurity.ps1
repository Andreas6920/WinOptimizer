Function Start-WinSecurity {

    Write-Host "`n$(Get-LogDate)`tENHANCE WINDOWS PRIVACY" -f Green
     

    # Adding entries to hosts file
        Write-Host "$(Get-LogDate)`t    Blocking Microsoft's Tracking domains:" -f Green
        Write-Host "$(Get-LogDate)`t        - Will start in the background" -f Yellow
        $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/block-domains.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;

    # Blocking Microsoft Tracking IP's in the firewall
        Write-Host "$(Get-LogDate)`t    Blocking Microsoft's tracking IP's:" -f Green
        Write-Host "$(Get-LogDate)`t        - Will start in the background" -f Yellow
        $link = "https://github.com/Andreas6920/WinOptimizer/blob/main/scripts/block-ips.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;
    
    #Configuring Windows privacy settings
        Write-Host "$(Get-LogDate)`t    Setting Privacy Settings:" -f Green     
        
        # Disable Advertising ID
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWord" -Value "0"
            Start-Sleep -s 2
        
        # Disable let websites provide locally relevant content by accessing language list           
            Add-Reg -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWord" -Value "1"
            Start-Sleep -s 2
        
        # Disable Show me suggested content in the Settings app
            Write-Host "$(Get-LogDate)`t        - Disabling personalized content suggestions" -f Yellow
            $keys = "SubscribedContent-338393Enabled","SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled" 
            $keys | % {Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "$_" -Type "DWord" -Value "0"}
            Start-Sleep -s 2
        
        # Remove Cortana
            Write-Host "$(Get-LogDate)`t        - Disabling Cortana" -f Yellow
            $ProgressPreference = "SilentlyContinue"
            Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type "DWord" -Value "0"
            $ProgressPreference = "Continue"
            Restart-Explorer
            Start-Sleep -s 5

        # Disable Online Speech Recognition
            Write-Host "$(Get-LogDate)`t        - Disabling Online Speech Recognition" -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type "DWord" -Value "0"
            Start-Sleep -s 2
        
        # Hiding personal information from lock screen
            Write-Host "$(Get-LogDate)`t        - Disabling sign-in screen notifications" -f Yellow
            $keys = "DontDisplayLockedUserID","DontDisplayLastUsername";
            $keys | % {Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "$_" -Type "DWORD" -Value "0"}
            Start-Sleep -s 2
        
        # Disable diagnostic data collection
            Write-Host "$(Get-LogDate)`t        - Disabling diagnostic data collection" -f Yellow
            Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value "0"
            Start-Sleep -s 2
        
        # Disable App Launch Tracking
            Write-Host "$(Get-LogDate)`t        - Disabling App Launch Tracking" -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type "DWORD" -Value "0"
            Start-Sleep -s 2

        # Disable "tailored expirence"
            Write-Host "$(Get-LogDate)`t        - Disabling tailored expirience" -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value "0"
            Start-Sleep -s 2
        
        # Disable application telemetry
            Write-Host "$(Get-LogDate)`t        - Disabling application telemetry" -f Yellow
            Add-Reg -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value "0"
            Start-Sleep -s 2

        # Send Microsoft a request to delete collected data about you.
            
            # Kontrollér om Windows-versionen er 10
            $OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
            if ($OSVersion -like "10.*"){
                #lock keyboard and mouse to avoid disruption while navigating in GUI.
                Write-Host "$(Get-LogDate)`t    Submitting request to Microsoft to delete data about you." -f Green

                #start navigating
                Stop-Input | Out-Null
                Start-Sleep -s 2
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
                Start-Input | Out-Null}

    # Windows hardening
        Write-Host "`n$(Get-LogDate)`tENHANCE WINDOWS SECURITY" -f Green
        
        # Disable automatic setup of network connected devices
            Write-Host "$(Get-LogDate)`t        - Disabling auto setup network devices." -f Yellow
            Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type "DWORD" -Value "0"
            Start-Sleep -s 2
            
        # Disable sharing of PC and printers
            Write-Host "$(Get-LogDate)`t        - Disabling sharing of PC and Printers." -f Yellow
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

        # Disable LLMNR
            # https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-Host "$(Get-LogDate)`t        - Disabling LLMNR." -f yellow
            Add-Reg -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value "0"
            Start-Sleep -s 2


        # Disable Wi-Fi Sense
            # https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-Host "$(Get-LogDate)`t        - Disabling Wi-Fi Sense." -f yellow
            If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null}
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0
            Start-Sleep -s 2


        # Bad Neighbor - CVE-2020-16898 (Disable IPv6 DNS)
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            Write-Host "$(Get-LogDate)`t        - Patching Bad Neighbor (CVE-2020-16898)." -f Yellow
            # Disable DHCPv6  + routerDiscovery
            Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $(Get-NetIPInterface -AddressFamily IPv6 | Select-Object -ExpandProperty InterfaceIndex) -RouterDiscovery Disabled -Dhcp Disabled
            # Prefer IPv4 over IPv6 (IPv6 is prefered by default)
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type "DWORD" -Value "0x20"
            Start-Sleep -s 2
        

        # Disabe SMB Compression - CVE-2020-0796
            # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Write-Host "$(Get-LogDate)`t        - Disabling SMB Compression." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Type "DWORD" -Value "1"

        # Disable SMB v1
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "$(Get-LogDate)`t        - Disabling SMB version 1 support." -f Yellow
            $smb1state = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
            if ($smb1state -ne "Disabled"){
                $smb1beingdisabled = $true
                Write-Host "$(Get-LogDate)`t            - This may take a while.." -f Yellow
                Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue | Out-Null
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
                Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type "DWORD" -Value "0"}

        # Disable SMB v2
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "$(Get-LogDate)`t        - Disabling SMB version 2 support." -f Yellow
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Type "DWORD" -Value "0"

        # Enable SMB Encryption
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Write-Host "$(Get-LogDate)`t        - Activating SMB Encryption." -f Yellow
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null
            
        # Spectre Meldown - CVE-2017-5754
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Write-Host "$(Get-LogDate)`t        - Patching Bad Metldown (CVE-2017-5754)." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type "DWORD" -Value "3"
            Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "MinVmVersionForCpuBasedMitigations" -Type "String" -Value "1.0"
        
        # Enable LSA protection
            # https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
            Write-Host "$(Get-LogDate)`t        - Enabling LSA protection." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RunAsPPL" -Type "DWORD" -Value "1"

        # Change File association on typical malicious files to preventing accidental launching
            # https://www.reddit.com/r/sysadmin/comments/uvxzge/security_cadence_use_default_apps_to_help_prevent/
            Write-Host "$(Get-LogDate)`t        - Setting file association for prevent accidental launching:" -f Yellow
            $link = "https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/master/SFTA.ps1"
            $path = join-path -Path $env:TMP -ChildPath ($link | split-path -Leaf)
            (New-Object net.webclient).Downloadfile("$link", "$path");
            Import-Module $path            

        # Disable OneNote embedded file attacks
            # test om extensions definition virker
            # https://www.bleepingcomputer.com/news/security/how-to-prevent-microsoft-onenote-files-from-infecting-windows-with-malware/
            # Write-Host "$(Get-LogDate)`t        - Disabling embedded file OneNote phishing attacks." -f Yellow
            # Add-Reg -Path "HKCU:\software\policies\microsoft\office\16.0\onenote\options" -Name "disableembeddedfiles" -Type "DWORD" -Value "0"
            # Add-Reg -Path "HKCU:\software\policies\microsoft\office\16.0\onenote\options\embeddedfileopenoptions" -Name "blockedextensions" -Type "DWORD" -Value "".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps1""

        # End of function
            if($smb1beingdisabled){Wait-job -Name "Disable SMB1" | Out-Null;}
            
        Write-Host "$(Get-LogDate)`t    Privacy optimizer complete. Your system is now more private and secure." -f Green
        Start-Sleep 5
    
        }