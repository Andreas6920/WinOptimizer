Function Add-Reg {

    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'Qword',' Unknown')]
        [String]$Type,
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

If (!(Test-Path $path)) {New-Item -Path $path -Force | Out-Null}; 
Set-ItemProperty -Path $path -Name $name -Type $type -Value $value -Force | Out-Null

}

Function Start-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($false)
    }

Function Stop-Input{
    $code = @"
[DllImport("user32.dll")]
public static extern bool BlockInput(bool fBlockIt);
"@
    $userInput = Add-Type -MemberDefinition $code -Name UserInput -Namespace UserInput -PassThru
    $userInput::BlockInput($true)
    }


    Write-Host "`n`tENHANCE WINDOWS PRIVACY" -f Green
     

    # Adding entries to hosts file
        Write-Host "`t    Blocking Microsoft's Tracking domains:" -f Green
        Write-Host "`t        - Will start in the background." -f Yellow
        $link = "https://raw.githubusercontent.com/Andreas6920/WinOptimizer/main/scripts/block-domains.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;

    # Blocking Microsoft Tracking IP's in the firewall
        Write-Host "`t    Blocking Microsoft's tracking IP's:" -f Green
        Write-Host "`t        - Will start in the background." -f Yellow
        $link = "https://github.com/Andreas6920/WinOptimizer/blob/main/scripts/block-ips.ps1"
        $file = "$dir\"+(Split-Path $link -Leaf)
        (New-Object net.webclient).Downloadfile("$link", "$file"); 
        Start-Sleep -s 2;
        Start-Process Powershell -argument "-ep bypass -windowstyle Minimized -file `"$file`""
        Start-Sleep -s 2;
    
    #Configuring Windows privacy settings
        Write-Host "`t    Setting Privacy Settings:" -f Green     
        
        # Disable Advertising ID
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWord" -Value "0"
            Start-Sleep -s 2
        
        # Disable let websites provide locally relevant content by accessing language list           
            Add-Reg -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWord" -Value "1"
            Start-Sleep -s 2
        
        # Disable Show me suggested content in the Settings app
            Write-Host "`t        - Disabling personalized content suggestions." -f Yellow
            $keys = "SubscribedContent-338393Enabled","SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled" 
            $keys | % {Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "$_" -Type "DWord" -Value "0"}
            Start-Sleep -s 2
        
        # Remove Cortana
            Write-Host "`t        - Disabling Cortana." -f Yellow
            $ProgressPreference = "SilentlyContinue"
            Get-AppxPackage -name *Microsoft.549981C3F5F10* | Remove-AppxPackage
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type "DWord" -Value "0"
            $ProgressPreference = "Continue"
            restart-explorer
            Start-Sleep -s 5

        # Disable Online Speech Recognition
            Write-Host "`t        - Disabling Online Speech Recognition." -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type "DWord" -Value "0"
            Start-Sleep -s 2
        
        # Hiding personal information from lock screen
            Write-Host "`t        - Disabling sign-in screen notifications." -f Yellow
            $keys = "DontDisplayLockedUserID","DontDisplayLastUsername";
            $keys | % {Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "$_" -Type "DWORD" -Value "0"}
            Start-Sleep -s 2
        
        # Disable diagnostic data collection
            Write-Host "`t        - Disabling diagnostic data collection" -f Yellow
            Add-Reg -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value "0"
            Start-Sleep -s 2
        
        # Disable App Launch Tracking
            Write-Host "`t        - Disabling App Launch Tracking." -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type "DWORD" -Value "0"
            Start-Sleep -s 2

        # Disable "tailored expirence"
            Write-Host "`t        - Disabling tailored expirience." -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value "0"
            Start-Sleep -s 2

    # Send Microsoft a request to delete collected data about you.
        
        #lock keyboard and mouse to avoid disruption while navigating in GUI.
        Write-Host "`t    Submitting request to Microsoft to delete data about you." -f Green
        
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
        Start-Input | Out-Null
        
        # Windows hardening
        Write-Host "`n`tENHANCE WINDOWS SECURITY" -f Green
        
        # Disable automatic setup of network connected devices
            Write-Host "`t        - Disabling auto setup network devices." -f Yellow
            Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type "DWORD" -Value "0"
            Start-Sleep -s 2
            
        # Disable sharing of PC and printers
            Write-Host "`t        - Disabling sharing of PC and Printers." -f Yellow
            Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
            get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
            netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

        # Disable LLMNR
            # https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
            Write-Host "`t        - Disabling LLMNR." -f yellow
            Add-Reg -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value "0"
        
        # Bad Neighbor - CVE-2020-16898 (Disable IPv6 DNS)
            # https://blog.rapid7.com/2020/10/14/there-goes-the-neighborhood-dealing-with-cve-2020-16898-a-k-a-bad-neighbor/
            Write-Host "`t        - Patching Bad Neighbor (CVE-2020-16898)." -f Yellow
                # Disable DHCPv6  + routerDiscovery
                Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex $(Get-NetIPInterface -AddressFamily IPv6 | Select-Object -ExpandProperty InterfaceIndex) -RouterDiscovery Disabled -Dhcp Disabled
                # Prefer IPv4 over IPv6 (IPv6 is prefered by default)
                Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type "DWORD" -Value "0x20"
        
        # Disabe SMB Compression - CVE-2020-0796
            # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0796
            Write-Host "`t        - Disabling SMB Compression." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Type "DWORD" -Value "1"

        # Disable SMB v1
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "`t        - Disabling SMB version 1 support." -f Yellow
            $smb1state = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
            if ($smb1state -ne "Disabled"){
                $smb1beingdisabled = $true
                Write-Host "`t            - This may take a while.." -f Yellow
                Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -WarningAction:SilentlyContinue | Out-Null
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ea SilentlyContinue | Out-Null
                Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type "DWORD" -Value "0"}

        # Disable SMB v2
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
            Write-Host "`t        - Disabling SMB version 2 support." -f Yellow
            Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ea SilentlyContinue | Out-Null
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Type "DWORD" -Value "0"

        # Enable SMB Encryption
            # https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
            Write-Host "`t        - Activating SMB Encryption." -f Yellow
            Set-SmbServerConfiguration –EncryptData $true -Force -ea SilentlyContinue | Out-Null
            Set-SmbServerConfiguration –RejectUnencryptedAccess $false -Force -ea SilentlyContinue | Out-Null
            
        # Spectre Meldown - CVE-2017-5754
            # https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            Write-Host "`t        - Patching Bad Metldown (CVE-2017-5754)." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type "DWORD" -Value "3"
            Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name "MinVmVersionForCpuBasedMitigations" -Type "String" -Value "1.0"
        
        # Enable LSA protection
            # https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
            Write-Host "`t        - Enabling LSA protection." -f Yellow
            Add-Reg -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RunAsPPL" -Type "DWORD" -Value "1"

        # Change File association on typical malicious files to preventing accidental launching
            # https://www.reddit.com/r/sysadmin/comments/uvxzge/security_cadence_use_default_apps_to_help_prevent/
            Write-host "`t        - Setting file association for prevent accidental launching:" -f Yellow
            $link = "https://raw.githubusercontent.com/DanysysTeam/PS-SFTA/master/SFTA.ps1"
            $path = join-path -Path $env:TMP -ChildPath ($link | split-path -Leaf)
            (New-Object net.webclient).Downloadfile("$link", "$path");
            Import-Module $path            

        # Disable OneNote embedded file attacks
            # test om extensions definition virker
            # https://www.bleepingcomputer.com/news/security/how-to-prevent-microsoft-onenote-files-from-infecting-windows-with-malware/
            # Write-Host "`t        - Disabling embedded file OneNote phishing attacks." -f Yellow
            # Add-Reg -Path "HKCU:\software\policies\microsoft\office\16.0\onenote\options" -Name "disableembeddedfiles" -Type "DWORD" -Value "0"
            # Add-Reg -Path "HKCU:\software\policies\microsoft\office\16.0\onenote\options\embeddedfileopenoptions" -Name "blockedextensions" -Type "DWORD" -Value "".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps1""

        # End of function
            if($smb1beingdisabled){Wait-job -Name "Disable SMB1" | Out-Null;}
            Write-Host "`tPrivacy optimizer complete. Your system is now more private and secure." -f Green
            Start-Sleep 10
    
        