    #Configuring Windows privacy settings
    Write-Host "`t`tSetting privacy Settings:" -f Green   
        
        # Blocking Microsoft Tracking domains in the hosts file
            Write-Host "`t`t`t- Blocking Microsoft's Tracking domains:" -f Green
            Write-Host "`t`t`t`t- Will start in the background." -f Yellow
            $link = "https://github.com/Andreas6920/WinOptimizer/raw/main/res/block-domains.ps1"
            $file = "$dir\"+(Split-Path $link -Leaf)
            (New-Object net.webclient).Downloadfile("$link", "$file"); 
            Start-Sleep -s 2;
            Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
            Start-Sleep -s 2;

        # Blocking Microsoft Tracking IP's in the firewall
            Write-Host "`t`t`t- Blocking Microsoft's tracking IP's:" -f Green
            Write-Host "`t`t`t`t- Will start in the background." -f Yellow
            $link = "https://github.com/Andreas6920/WinOptimizer/raw/main/res/block-ips.ps1"
            $file = "$dir\"+(Split-Path $link -Leaf)
            (New-Object net.webclient).Downloadfile("$link", "$file"); 
            Start-Sleep -s 2;
            Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
            Start-Sleep -s 2;
            
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
    
    #Configuring Windows security settings
    Write-Host "`t`tSetting security settings:" -f Green  

        # Disable automatic setup of network connected devices.
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
            
        #End of function
            Wait-job -Name "Disable SMB1" | Out-Null;
            Write-Host "`tPrivacy optimizer complete. Your system is now more private and secure." -f Green
            Start-Sleep 10