Function Start-WinSettings {
    param (
        [switch]$EnableDarkMode
    )
    
# System Preparation

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

# Start
Write-Host "`n$(Get-LogDate)`tENHANCE WINDOWS SETTINGS, $($SystemVersion)" -f Green
Write-Host "$(Get-LogDate)`t    Configure Windows:" -f Green
        
    # Show file extensions
        Write-Host "$(Get-LogDate)`t        - Show file extensions." -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value "0"
        Start-Sleep -S 2
            
    # Show hidden files
        Write-Host "$(Get-LogDate)`t        - Show hidden files." -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type "DWORD" -Value "1"
        Start-Sleep -S 2
        
    # Change Explorer to "This PC"
        Write-Host "$(Get-LogDate)`t        - Change explorer to 'This PC' instead of 'Documents.'" -f Yellow
        Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type "DWORD" -Value "1"
        Start-Sleep -S 2

    # Seconds in System Tray Clock 
        Write-Host "$(Get-LogDate)`t        - Show Seconds in System Tray Clock." -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type "DWord" -Value "1"
        Start-Sleep -S 2
    
    # Disable automatic setup of network connected devices
        Write-Host "$(Get-LogDate)`t        - Turn off automatic setup of network connected devices." -f Yellow
        Add-Reg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type "DWORD" -Value "0"
        Start-Sleep -s 2

    # Duplicate drive entry from navigation panel
        Write-Host "$(Get-LogDate)`t        - Removing duplicate drive entry from navigation panel."
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        Remove-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable sharing of PC and printers    
        Write-Host "$(Get-LogDate)`t        - Turn off sharing of PC and Printers." -f Yellow
        Get-NetConnectionProfile | ForEach-Object {Set-NetConnectionProfile -Name $_.Name -NetworkCategory Public -ErrorAction SilentlyContinue | Out-Null}    
        get-printer | Where-Object shared -eq True | ForEach-Object {Set-Printer -Name $_.Name -Shared $False -ErrorAction SilentlyContinue | Out-Null}
        netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No -ErrorAction SilentlyContinue | Out-Null

    # Setting Power plan    
        Write-Host "$(Get-LogDate)`t        - Setting power plan." -f Yellow
        powercfg -change -monitor-timeout-ac 180
        powercfg -change -standby-timeout-ac 180
        powercfg -change -monitor-timeout-dc 45
        powercfg -change -standby-timeout-dc 60
    


    if($ThisIsWindows10){
        # Taskbar: Hide task view button
            Write-Host "$(Get-LogDate)`t        - Taskbar: Hide task view" -f Yellow
            Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView" -Name "ShowTaskViewButton" -Type "DWORD" -Value "0"
            Start-Sleep -S 2

        # Remove 3D objects
            Write-Host "$(Get-LogDate)`t        - Disabling 3D Objects app" -f Yellow
            $3Dlocation32bit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
            $3Dlocation64bit = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A"
            If((test-path $3Dlocation32bit )){remove-item $3Dlocation32bit}
            If((test-path $3Dlocation64bit )){remove-item $3Dlocation64bit}
            Start-Sleep -S 2}

    if($ThisIsWindows11){
        # Move Taskbar to the left side
        Write-Host "$(Get-LogDate)`t        - Move taskbar icons to left" -f Yellow
        Add-Reg -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type "DWord" -Value "0"
        Start-Sleep -S 2
    
        # Full context menu / old windows 11 menu
        Write-Host "$(Get-LogDate)`t        - Setting full context Left-Click menu." -f Yellow
        reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve | Out-Null
        Start-Sleep -S 2}

    if($EnableDarkMode){    
        Write-Host "$(Get-LogDate)`t        - Enabling Dark Mode" -f Yellow
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type "DWORD" -Value "0"
        Add-Reg -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type "DWORD" -Value "0"
        Start-Sleep -S 2
        Restart-Explorer}
    

    #End of function
    Write-Host "`n$(Get-LogDate)`tWINDOWS SETTINGS ENHANCEMENT COMPLETE" -f Green
    Start-Sleep -S 5}